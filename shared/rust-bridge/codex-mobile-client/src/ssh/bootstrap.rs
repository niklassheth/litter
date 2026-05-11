//! Bootstrap a remote `codex app-server` on its default app-server control
//! socket. Litter talks to that server by executing `codex app-server proxy`
//! over SSH stdio; no remote WebSocket listener or TCP tunnel is created.

use std::time::Duration;

use tracing::{info, warn};

use crate::shell_quoting::{posix_quote as shell_quote, powershell_quote as ps_quote};

use super::{
    PROFILE_INIT, RemoteCodexBinary, RemoteShell, SshBootstrapResult, SshClient, SshError,
    append_bridge_info_log, remote_shell_name, server_launch_command, windows_start_process_spec,
};

const APP_SERVER_SOCKET_LISTEN_URL: &str = "unix://";
const SOCKET_BOOTSTRAP_SETTLE_DELAY: Duration = Duration::from_millis(250);

impl SshClient {
    /// Ensure a remote Codex app-server has been asked to listen on the default
    /// app-server control socket. If another process already owns the socket,
    /// the spawned process may exit quickly; callers still connect through
    /// `codex app-server proxy`, which will attach to the owner.
    pub async fn bootstrap_codex_server(
        &self,
        working_dir: Option<&str>,
        prefer_ipv6: bool,
    ) -> Result<SshBootstrapResult, SshError> {
        append_bridge_info_log(&format!(
            "ssh_socket_bootstrap_start prefer_ipv6={} working_dir={}",
            prefer_ipv6,
            working_dir.unwrap_or("<none>")
        ));
        let codex_binary = self.resolve_codex_binary().await?;
        info!("remote codex binary: {}", codex_binary.path());
        append_bridge_info_log(&format!(
            "ssh_socket_bootstrap_binary path={}",
            codex_binary.path()
        ));
        self.bootstrap_codex_server_with_binary(&codex_binary, working_dir, prefer_ipv6)
            .await
    }

    pub(crate) async fn bootstrap_codex_server_with_binary(
        &self,
        codex_binary: &RemoteCodexBinary,
        working_dir: Option<&str>,
        prefer_ipv6: bool,
    ) -> Result<SshBootstrapResult, SshError> {
        let shell = self.detect_remote_shell().await;
        self.bootstrap_codex_server_with_binary_and_shell(
            codex_binary,
            working_dir,
            prefer_ipv6,
            shell,
        )
        .await
    }

    pub(crate) async fn bootstrap_codex_server_with_binary_and_shell(
        &self,
        codex_binary: &RemoteCodexBinary,
        working_dir: Option<&str>,
        _prefer_ipv6: bool,
        shell: RemoteShell,
    ) -> Result<SshBootstrapResult, SshError> {
        info!(
            "ssh socket bootstrap begin binary={} shell={} working_dir={}",
            codex_binary.path(),
            remote_shell_name(shell),
            working_dir.unwrap_or("<none>")
        );
        self.log_macos_keychain_unlock_for_bootstrap(shell).await?;
        let cd_prefix = match (shell, working_dir) {
            (RemoteShell::Posix, Some(dir)) => format!("cd {} && ", shell_quote(dir)),
            (RemoteShell::PowerShell, Some(dir)) => format!("Set-Location {}; ", ps_quote(dir)),
            _ => String::new(),
        };

        let (log_path, stderr_log_path) = match shell {
            RemoteShell::Posix => ("/tmp/codex-mobile-app-server.log".to_string(), None),
            RemoteShell::PowerShell => (
                "(Join-Path $env:TEMP 'codex-mobile-app-server.log')".to_string(),
                Some("(Join-Path $env:TEMP 'codex-mobile-app-server-err.log')".to_string()),
            ),
        };

        let launch_cmd = match shell {
            RemoteShell::Posix => format!(
                "{profile_init} {cd_prefix}nohup {launch} \
                 </dev/null >{log} 2>&1 & echo $!",
                profile_init = PROFILE_INIT,
                cd_prefix = cd_prefix,
                launch = server_launch_command(codex_binary, APP_SERVER_SOCKET_LISTEN_URL, shell),
                log = shell_quote(&log_path),
            ),
            RemoteShell::PowerShell => {
                let (file_path, argument_list) =
                    windows_start_process_spec(codex_binary, APP_SERVER_SOCKET_LISTEN_URL);
                format!(
                    r#"{cd_prefix}$logFile = {log}; $errFile = {log_err}; $proc = Start-Process -WindowStyle Hidden -PassThru -RedirectStandardOutput $logFile -RedirectStandardError $errFile -FilePath {file_path} -ArgumentList {argument_list}; Write-Host $proc.Id"#,
                    cd_prefix = cd_prefix,
                    log = log_path,
                    log_err = stderr_log_path.as_deref().expect("windows stderr log path"),
                    file_path = file_path,
                    argument_list = argument_list,
                )
            }
        };

        let launch_result = self.exec_shell(&launch_cmd, shell).await?;
        if launch_result.exit_code != 0 {
            return Err(SshError::ExecFailed {
                exit_code: launch_result.exit_code,
                stderr: if launch_result.stderr.trim().is_empty() {
                    launch_result.stdout
                } else {
                    launch_result.stderr
                },
            });
        }

        let pid: Option<u32> = launch_result.stdout.trim().parse().ok();
        append_bridge_info_log(&format!(
            "ssh_socket_bootstrap_launch_result pid={:?} stdout={} stderr={}",
            pid,
            launch_result.stdout.trim(),
            launch_result.stderr.trim()
        ));
        info!(
            "ssh socket bootstrap launched shell={} pid={:?}",
            remote_shell_name(shell),
            pid
        );

        tokio::time::sleep(SOCKET_BOOTSTRAP_SETTLE_DELAY).await;

        if let Some(p) = pid {
            if !self.is_process_alive_shell(p, shell).await {
                let tail = self
                    .fetch_process_log_tail_shell(&log_path, stderr_log_path.as_deref(), shell)
                    .await;
                if !tail.to_ascii_lowercase().contains("already in use") {
                    warn!(
                        "ssh socket bootstrap process exited before proxy attach shell={} pid={:?} tail={}",
                        remote_shell_name(shell),
                        pid,
                        tail
                    );
                }
            }
        }

        let version = self
            .read_server_version_shell(codex_binary.path(), shell)
            .await;
        append_bridge_info_log(&format!(
            "ssh_socket_bootstrap_success pid={:?} version={}",
            pid,
            version.clone().unwrap_or_else(|| "<unknown>".to_string())
        ));

        Ok(SshBootstrapResult {
            server_port: 0,
            tunnel_local_port: 0,
            server_version: version,
            pid,
            codex_path: codex_binary.path().to_string(),
            shell,
        })
    }

    pub(super) async fn read_server_version_shell(
        &self,
        codex_path: &str,
        shell: RemoteShell,
    ) -> Option<String> {
        let cmd = match shell {
            RemoteShell::Posix => format!(
                "{} {} --version 2>/dev/null",
                PROFILE_INIT,
                shell_quote(codex_path)
            ),
            RemoteShell::PowerShell => format!("& {} --version 2>$null", ps_quote(codex_path)),
        };
        match self.exec_shell(&cmd, shell).await {
            Ok(r) if r.exit_code == 0 => {
                let v = r.stdout.trim().to_string();
                if v.is_empty() { None } else { Some(v) }
            }
            _ => None,
        }
    }
}
