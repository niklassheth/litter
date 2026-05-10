//! Local↔remote TCP and Unix-socket plumbing on top of an open SSH session:
//!
//! - `forward_port` / `forward_port_to` / `ensure_forward_port_to` —
//!   bind a local TCP listener, accept connections, open a
//!   `direct-tcpip` channel to the remote, and proxy bytes via
//!   [`port_forward::proxy_connection`].
//! - `abort_forward_port` — abort a previously-started forward.
//! - `forward_streamlocal_to` / `ensure_forward_streamlocal_to` — bind a
//!   local TCP listener and forward each accepted connection to a remote Unix
//!   socket via SSH `direct-streamlocal`.
//! - `open_streamlocal` — open a `direct-streamlocal` channel to a
//!   remote Unix socket (used to talk to `codex-ipc` over SSH).
//! - `resolve_remote_ipc_socket_path` / `remote_ipc_socket_if_present` —
//!   compute / probe the Codex IPC socket path on the remote.

use std::sync::Arc;

use russh::ChannelStream;
use russh::client::Msg;
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

use crate::shell_quoting::posix_quote as shell_quote;

use super::{
    ForwardTask, SshClient, SshError, append_android_debug_log, port_forward::proxy_connection,
};

impl SshClient {
    /// Set up local-to-remote TCP port forwarding.
    ///
    /// Binds a local TCP listener on `local_port` (use 0 for a random port)
    /// and forwards each accepted connection through the SSH tunnel to
    /// `127.0.0.1:remote_port` on the remote host.
    ///
    /// Returns the actual local port that was bound. Forwarding runs in
    /// background tokio tasks until [`Self::disconnect`] is called.
    pub async fn forward_port(&self, local_port: u16, remote_port: u16) -> Result<u16, SshError> {
        self.forward_port_to(local_port, "127.0.0.1", remote_port)
            .await
    }

    /// Set up local-to-remote TCP port forwarding to an explicit remote host.
    pub async fn forward_port_to(
        &self,
        local_port: u16,
        remote_host: &str,
        remote_port: u16,
    ) -> Result<u16, SshError> {
        let (actual_port, task) = self
            .spawn_forward_port(local_port, remote_host, remote_port)
            .await?;
        self.forward_tasks.lock().await.insert(
            actual_port,
            ForwardTask {
                remote_host: remote_host.to_string(),
                remote_port,
                task,
            },
        );
        Ok(actual_port)
    }

    pub async fn ensure_forward_port_to(
        &self,
        local_port: u16,
        remote_host: &str,
        remote_port: u16,
    ) -> Result<u16, SshError> {
        {
            let tasks = self.forward_tasks.lock().await;
            if let Some(existing) = tasks.get(&local_port) {
                if existing.remote_host == remote_host && existing.remote_port == remote_port {
                    return Ok(local_port);
                }
                return Err(SshError::PortForwardFailed(format!(
                    "port {local_port} already forwarded to {}:{}",
                    existing.remote_host, existing.remote_port
                )));
            }
        }
        self.forward_port_to(local_port, remote_host, remote_port)
            .await
    }

    /// Set up local TCP forwarding to a remote Unix socket.
    ///
    /// This is useful for Codex's app-server control socket, which speaks the
    /// normal app-server WebSocket protocol over a Unix-domain socket.
    pub async fn forward_streamlocal_to(
        &self,
        local_port: u16,
        socket_path: &str,
    ) -> Result<u16, SshError> {
        let (actual_port, task) = self
            .spawn_forward_streamlocal(local_port, socket_path)
            .await?;
        self.forward_tasks.lock().await.insert(
            actual_port,
            ForwardTask {
                remote_host: ForwardTask::streamlocal_remote_host(socket_path),
                remote_port: 0,
                task,
            },
        );
        Ok(actual_port)
    }

    pub async fn ensure_forward_streamlocal_to(
        &self,
        local_port: u16,
        socket_path: &str,
    ) -> Result<u16, SshError> {
        let remote_host = ForwardTask::streamlocal_remote_host(socket_path);
        {
            let tasks = self.forward_tasks.lock().await;
            if let Some(existing) = tasks.get(&local_port) {
                if existing.remote_host == remote_host && existing.remote_port == 0 {
                    return Ok(local_port);
                }
                return Err(SshError::PortForwardFailed(format!(
                    "port {local_port} already forwarded to {}:{}",
                    existing.remote_host, existing.remote_port
                )));
            }
        }
        self.forward_streamlocal_to(local_port, socket_path).await
    }

    pub async fn abort_forward_port(&self, local_port: u16) -> bool {
        let mut tasks = self.forward_tasks.lock().await;
        if let Some(existing) = tasks.remove(&local_port) {
            existing.task.abort();
            true
        } else {
            false
        }
    }

    async fn spawn_forward_port(
        &self,
        local_port: u16,
        remote_host: &str,
        remote_port: u16,
    ) -> Result<(u16, tokio::task::JoinHandle<()>), SshError> {
        let listener = TcpListener::bind(format!("127.0.0.1:{local_port}"))
            .await
            .map_err(|e| SshError::PortForwardFailed(format!("bind: {e}")))?;

        let actual_port = listener
            .local_addr()
            .map_err(|e| SshError::PortForwardFailed(format!("local_addr: {e}")))?
            .port();

        info!("port forward: 127.0.0.1:{actual_port} -> remote {remote_host}:{remote_port}");

        let handle = Arc::clone(&self.handle);
        let remote_host = remote_host.to_string();

        let task = tokio::spawn(async move {
            loop {
                let (local_stream, peer_addr) = match listener.accept().await {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("port forward accept error: {e}");
                        append_android_debug_log(&format!(
                            "ssh_forward_accept_error listen=127.0.0.1:{} remote={}:{} error={}",
                            actual_port, remote_host, remote_port, e
                        ));
                        break;
                    }
                };

                debug!("port forward: accepted connection from {peer_addr}");
                append_android_debug_log(&format!(
                    "ssh_forward_accept listen=127.0.0.1:{} remote={}:{} peer={}",
                    actual_port, remote_host, remote_port, peer_addr
                ));

                let handle = Arc::clone(&handle);
                let remote_host = remote_host.clone();

                tokio::spawn(async move {
                    let ssh_channel = {
                        let h = handle.lock().await;
                        match h
                            .channel_open_direct_tcpip(
                                &remote_host,
                                remote_port as u32,
                                "127.0.0.1",
                                actual_port as u32,
                            )
                            .await
                        {
                            Ok(ch) => ch,
                            Err(e) => {
                                error!("port forward: open direct-tcpip failed: {e}");
                                append_android_debug_log(&format!(
                                    "ssh_forward_direct_tcpip_failed listen=127.0.0.1:{} remote={}:{} peer={} error={}",
                                    actual_port, remote_host, remote_port, peer_addr, e
                                ));
                                return;
                            }
                        }
                    };

                    append_android_debug_log(&format!(
                        "ssh_forward_direct_tcpip_opened listen=127.0.0.1:{} remote={}:{} peer={}",
                        actual_port, remote_host, remote_port, peer_addr
                    ));

                    if let Err(e) = proxy_connection(
                        local_stream,
                        ssh_channel,
                        actual_port,
                        &remote_host,
                        remote_port,
                        peer_addr,
                    )
                    .await
                    {
                        debug!("port forward proxy ended: {e}");
                        append_android_debug_log(&format!(
                            "ssh_forward_proxy_error listen=127.0.0.1:{} remote={}:{} peer={} error={}",
                            actual_port, remote_host, remote_port, peer_addr, e
                        ));
                    }
                });
            }
        });

        Ok((actual_port, task))
    }

    async fn spawn_forward_streamlocal(
        &self,
        local_port: u16,
        socket_path: &str,
    ) -> Result<(u16, tokio::task::JoinHandle<()>), SshError> {
        let listener = TcpListener::bind(format!("127.0.0.1:{local_port}"))
            .await
            .map_err(|e| SshError::PortForwardFailed(format!("bind: {e}")))?;

        let actual_port = listener
            .local_addr()
            .map_err(|e| SshError::PortForwardFailed(format!("local_addr: {e}")))?
            .port();

        info!("streamlocal forward: 127.0.0.1:{actual_port} -> remote unix:{socket_path}");

        let handle = Arc::clone(&self.handle);
        let socket_path = socket_path.to_string();
        let remote_label = ForwardTask::streamlocal_remote_host(&socket_path);

        let task = tokio::spawn(async move {
            loop {
                let (local_stream, peer_addr) = match listener.accept().await {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("streamlocal forward accept error: {e}");
                        append_android_debug_log(&format!(
                            "ssh_streamlocal_accept_error listen=127.0.0.1:{} remote={} error={}",
                            actual_port, remote_label, e
                        ));
                        break;
                    }
                };

                debug!("streamlocal forward: accepted connection from {peer_addr}");
                append_android_debug_log(&format!(
                    "ssh_streamlocal_accept listen=127.0.0.1:{} remote={} peer={}",
                    actual_port, remote_label, peer_addr
                ));

                let handle = Arc::clone(&handle);
                let socket_path = socket_path.clone();
                let remote_label = remote_label.clone();

                tokio::spawn(async move {
                    let ssh_channel = {
                        let h = handle.lock().await;
                        match h.channel_open_direct_streamlocal(&socket_path).await {
                            Ok(ch) => ch,
                            Err(e) => {
                                error!("streamlocal forward: open direct-streamlocal failed: {e}");
                                append_android_debug_log(&format!(
                                    "ssh_streamlocal_direct_open_failed listen=127.0.0.1:{} remote={} peer={} error={}",
                                    actual_port, remote_label, peer_addr, e
                                ));
                                return;
                            }
                        }
                    };

                    append_android_debug_log(&format!(
                        "ssh_streamlocal_direct_opened listen=127.0.0.1:{} remote={} peer={}",
                        actual_port, remote_label, peer_addr
                    ));

                    if let Err(e) = proxy_connection(
                        local_stream,
                        ssh_channel,
                        actual_port,
                        &remote_label,
                        0,
                        peer_addr,
                    )
                    .await
                    {
                        debug!("streamlocal forward proxy ended: {e}");
                        append_android_debug_log(&format!(
                            "ssh_streamlocal_proxy_error listen=127.0.0.1:{} remote={} peer={} error={}",
                            actual_port, remote_label, peer_addr, e
                        ));
                    }
                });
            }
        });

        Ok((actual_port, task))
    }

    /// Open a direct streamlocal channel to a remote Unix socket path.
    pub async fn open_streamlocal(
        &self,
        socket_path: &str,
    ) -> Result<ChannelStream<Msg>, SshError> {
        let handle = self.handle.lock().await;
        if handle.is_closed() {
            return Err(SshError::Disconnected);
        }
        let channel = handle
            .channel_open_direct_streamlocal(socket_path)
            .await
            .map_err(|e| {
                SshError::ConnectionFailed(format!("open direct-streamlocal {socket_path}: {e}"))
            })?;
        Ok(channel.into_stream())
    }

    /// Resolve the default remote Codex IPC socket path for the current SSH user.
    pub async fn resolve_remote_ipc_socket_path(&self) -> Result<String, SshError> {
        const SCRIPT: &str = r#"uid="$(id -u 2>/dev/null || printf '0')"
tmp="${TMPDIR:-${TMP:-/tmp}}"
tmp="${tmp%/}"
printf '%s/codex-ipc/ipc-%s.sock' "$tmp" "$uid""#;
        let result = self.exec_posix(SCRIPT).await?;
        let path = result.stdout.trim().to_string();
        if path.is_empty() {
            return Err(SshError::ExecFailed {
                exit_code: result.exit_code,
                stderr: "failed to resolve remote IPC socket path".to_string(),
            });
        }
        Ok(path)
    }

    /// Return the requested IPC socket path if it exists on the remote host.
    pub async fn remote_ipc_socket_if_present(
        &self,
        override_path: Option<&str>,
    ) -> Result<Option<String>, SshError> {
        let socket_path = match override_path {
            Some(path) if path.trim().is_empty() => return Ok(None),
            Some(path) => path.to_string(),
            None => self.resolve_remote_ipc_socket_path().await?,
        };
        let check = format!(
            "if [ -S {path} ]; then printf '%s' {path}; fi",
            path = shell_quote(&socket_path),
        );
        let result = self.exec_posix(&check).await?;
        if result.exit_code != 0 {
            return Err(SshError::ExecFailed {
                exit_code: result.exit_code,
                stderr: result.stderr,
            });
        }
        let resolved = result.stdout.trim();
        if resolved.is_empty() {
            Ok(None)
        } else {
            Ok(Some(resolved.to_string()))
        }
    }

    /// Resolve the default Codex app-server control socket path.
    pub async fn resolve_remote_app_server_control_socket_path(&self) -> Result<String, SshError> {
        const SCRIPT: &str = r#"codex_home="${CODEX_HOME:-$HOME/.codex}"
codex_home="${codex_home%/}"
printf '%s/app-server-control/app-server-control.sock' "$codex_home""#;
        let result = self.exec_posix(SCRIPT).await?;
        let path = result.stdout.trim().to_string();
        if path.is_empty() {
            return Err(SshError::ExecFailed {
                exit_code: result.exit_code,
                stderr: "failed to resolve remote app-server control socket path".to_string(),
            });
        }
        Ok(path)
    }

    /// Return the app-server control socket path if it exists on the remote host.
    pub async fn remote_app_server_control_socket_if_present(
        &self,
    ) -> Result<Option<String>, SshError> {
        let socket_path = self.resolve_remote_app_server_control_socket_path().await?;
        let check = format!(
            "if [ -S {path} ]; then printf '%s' {path}; fi",
            path = shell_quote(&socket_path),
        );
        let result = self.exec_posix(&check).await?;
        if result.exit_code != 0 {
            return Err(SshError::ExecFailed {
                exit_code: result.exit_code,
                stderr: result.stderr,
            });
        }
        let resolved = result.stdout.trim();
        if resolved.is_empty() {
            Ok(None)
        } else {
            Ok(Some(resolved.to_string()))
        }
    }
}
