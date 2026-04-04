use crate::http::HttpMangler;
use crate::{AppState, ProxyTarget};
use crate::{dns::DnsError, settings::SplitMode, tls::TlsMangler};
use log::{debug, trace, warn};
use std::io::ErrorKind;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, copy_bidirectional};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Timeout")]
    Timeout(#[from] tokio::time::error::Elapsed),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Manipulation failed ({stage}): {details}")]
    Manipulation { stage: &'static str, details: String },

    #[error("Relay error to {host}: {source}")]
    Relay { host: String, source: std::io::Error },

    #[error("DNS error: {0}")]
    Dns(#[from] DnsError),
}

pub struct ProxyHandler;

impl ProxyHandler {
    /// Обработка подключения (TCP-stream) с модификацией и пробросом трафика в обе стороны
    #[allow(clippy::too_many_lines)]
    pub async fn handle_connection(
        stream_in: TcpStream,
        state: Arc<AppState>,
        cancel_token: CancellationToken,
    ) -> Result<(), ProxyError> {
        stream_in.set_nodelay(true)?;

        let args = &state.settings.args;
        let engine = &state.settings.engine;

        // Настройка TCP Keepalive
        let socket_ref = socket2::SockRef::from(&stream_in);
        let keepalive = socket2::TcpKeepalive::new()
            .with_time(Duration::from_secs(engine.keepalive.time_secs))
            .with_interval(Duration::from_secs(engine.keepalive.interval_secs))
            .with_retries(engine.keepalive.retries);
        if let Err(err) = socket_ref.set_tcp_keepalive(&keepalive) {
            debug!("Failed to set TCP Keepalive: {err}");
        }

        let mut reader = BufReader::with_capacity(engine.buffer_capacity, stream_in);
        let mut header_buffer = Vec::new();
        let mut line = String::new();

        // Читаем все заголовки до пустой строки
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => break,
                Err(ref err) if err.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(err) => return Err(err.into()),
                Ok(_) => {
                    header_buffer.extend_from_slice(line.as_bytes());
                    if line == "\r\n" || line == "\n" {
                        break;
                    }
                }
            }
        }

        if header_buffer.is_empty() {
            return Ok(());
        }

        let target = Self::extract_target(&header_buffer)?;

        let (host, port, is_https) = match target {
            ProxyTarget::Https { host } => (host, 443, true),
            ProxyTarget::Http { host } => (host, 80, false),
        };

        let mut stream_out = timeout(
            Duration::from_millis(engine.dns_connect_timeout_millis),
            state.resolver.race_connect_to_target(&host, port),
        )
        .await??;

        if is_https {
            // Пишем ack для клиента
            let ack = "HTTP/1.1 200 Connection Established\r\n\r\n";
            reader.write_all(ack.as_bytes()).await?;

            // Вычитываем полную TLS-запись (ожидаем ClientHello)
            let tls_record =
                TlsMangler::read_full_record(&mut reader)
                    .await
                    .map_err(|err| ProxyError::Manipulation {
                        stage: "TLS Read",
                        details: err.to_string(),
                    })?;

            match args.https_split_mode {
                SplitMode::None => {
                    stream_out.write_all(&tls_record).await?;
                }
                SplitMode::Fragment => {
                    // Фрагментируем с учетом выбранной стратегии TTL и отправляем TLS-ClientHello
                    TlsMangler::fragment_handshake(args, &engine.tls_fragmentation, &mut stream_out, &tls_record)
                        .await
                        .map_err(|err| ProxyError::Manipulation {
                            stage: "TLS Fragment",
                            details: err.to_string(),
                        })?;
                }
            }
        } else {
            match args.http_split_mode {
                SplitMode::None => {
                    stream_out
                        .write_all(&header_buffer)
                        .await
                        .map_err(|err| ProxyError::Relay {
                            host: host.clone(),
                            source: err,
                        })?;
                }
                SplitMode::Fragment => {
                    // Модифицируем HTTP-headers
                    let modified_headers =
                        HttpMangler::modify_http_headers(&header_buffer).map_err(|err| ProxyError::Manipulation {
                            stage: "HTTP Mangle",
                            details: err.to_string(),
                        })?;

                    // Фрагментируем и отправляем HTTP-headers
                    HttpMangler::send_split_request(&engine.http_fragmentation, &mut stream_out, &modified_headers)
                        .await
                        .map_err(|err| ProxyError::Manipulation {
                            stage: "НTTP Fragment",
                            details: err.to_string(),
                        })?;
                }
            }

            // Доотправляем остатки данных из буфера
            let pending_data = reader.buffer();
            if !pending_data.is_empty() {
                let len = pending_data.len();
                stream_out
                    .write_all(pending_data)
                    .await
                    .map_err(|err| ProxyError::Relay {
                        host: host.clone(),
                        source: err,
                    })?;
                reader.consume(len);
            }
        }

        let mut stream_in = reader;

        let relay_task = copy_bidirectional(&mut stream_in, &mut stream_out);

        match tokio::select! {
            biased;
            () = cancel_token.cancelled() => {
                trace!("Shutdown: stopping relay for {host}");
                Ok((0, 0))
            }
            res = timeout(Duration::from_secs(engine.tcp_idle_timeout_secs), relay_task) => res.map_err(|_| {
                trace!("Connection to {host} timed out (Idle)");
                std::io::Error::new(std::io::ErrorKind::TimedOut, "Idle timeout")
            })?,
        } {
            Ok((up, down)) => trace!("Relay finish | Up: {up} bytes | Down: {down} bytes"),
            Err(err) => match err.kind() {
                ErrorKind::NotConnected | ErrorKind::BrokenPipe | ErrorKind::ConnectionReset => {
                    trace!("Connection closed by peer");
                }
                _ => warn!("Relay error with {host}: {err}"),
            },
        }

        Ok(())
    }

    /// Определение целевого адреса (host)
    fn extract_target(buffer: &[u8]) -> Result<ProxyTarget, ProxyError> {
        if buffer.is_empty() {
            return Err(ProxyError::BadRequest("Empty buffer".into()));
        }

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);

        let status = req
            .parse(buffer)
            .map_err(|err| ProxyError::BadRequest(err.to_string()))?;

        if status.is_partial() {
            return Err(ProxyError::BadRequest("Incomplete headers".into()));
        }

        let method = req.method.ok_or(ProxyError::BadRequest("Missing method".into()))?;
        let is_connect = method == "CONNECT";

        let raw_host = if is_connect {
            req.path.ok_or(ProxyError::BadRequest("Missing path".into()))?
        } else {
            let host_header = req
                .headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case("Host"))
                .ok_or(ProxyError::BadRequest("Host header not found".into()))?;

            std::str::from_utf8(host_header.value).map_err(|err| ProxyError::BadRequest(err.to_string()))?
        };

        let host = raw_host
            .split(':')
            .next()
            .ok_or_else(|| ProxyError::BadRequest("Empty host".into()))?
            .to_string();

        Ok(if is_connect {
            ProxyTarget::Https { host }
        } else {
            ProxyTarget::Http { host }
        })
    }
}
