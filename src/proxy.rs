use crate::http::HttpMangler;
use crate::{AppState, ProxyTarget};
use crate::{cli_args::SplitMode, dns::DnsError, tls::TlsMangler};
use log::debug;
use std::{error::Error, sync::Arc};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::Duration;
use tokio::time::timeout;

const BUFFER_CAPACITY: usize = 2048;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub struct ProxyHandler;

impl ProxyHandler {
    /// Обработка подключения (TCP-stream) с модификацией и пробросом трафика в обе стороны
    pub async fn handle_connection(
        stream_in: TcpStream,
        state: Arc<AppState>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        stream_in.set_nodelay(true)?;

        let mut reader = BufReader::with_capacity(BUFFER_CAPACITY, stream_in);
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

        // Достаем целевой адрес (host)
        let target = match Self::extract_target(&header_buffer) {
            Ok(data) => data,
            Err(err) => return Err(format!("Host extract error: {err}").into()),
        };

        let (host, port, is_https) = match target {
            ProxyTarget::Https { host } => (host, 443, true),
            ProxyTarget::Http { host } => (host, 80, false),
        };

        let mut stream_out = timeout(
            CONNECT_TIMEOUT,
            state.resolver.race_connect_to_target(&host, port),
        )
        .await
        .map_err(|_| DnsError::ConnectionFailed("Timeout".to_string()))??;

        if is_https {
            // Пишем ack для клиента
            let ack = "HTTP/1.1 200 Connection Established\r\n\r\n";
            reader
                .write_all(ack.as_bytes())
                .await
                .map_err(|err| format!("Failed to send ACK to client: {err}"))?;

            // Вычитываем полный TLS-ClientHello + проверяем что это вообще он
            let tls_record = TlsMangler::read_full_record(&mut reader).await?;

            // Выбор режима обработки TLS-ClientHello
            match state.args.https_split_mode {
                SplitMode::None => {
                    // Проксируем без модификаций
                    stream_out.write_all(&tls_record).await?;
                }
                SplitMode::Fragment => {
                    // Фрагментируем с учетом выбранной стратегии TTL и отправляем TLS-ClientHello
                    TlsMangler::fragment_handshake(
                        &state.args.https_fake_ttl,
                        &mut stream_out,
                        &tls_record,
                    )
                    .await
                    .map_err(|err| format!("Fragmentation/TTL error: {err}"))?;
                }
            }
        } else {
            match state.args.http_split_mode {
                SplitMode::None => {
                    // Проксируем без модификаций
                    stream_out
                        .write_all(&header_buffer)
                        .await
                        .map_err(|err| format!("Failed to send raw headers to {host}: {err}"))?;
                }
                SplitMode::Fragment => {
                    // Модифицируем HTTP-headers
                    let modified_headers = HttpMangler::modify_http_headers(&header_buffer)?;

                    // Фрагментируем и отправляем HTTP-headers
                    HttpMangler::send_split_request(&mut stream_out, &modified_headers)
                        .await
                        .map_err(|err| format!("Failed to send split headers to {host}: {err}"))?;
                }
            }

            // Доотправляем остатки данных из буфера
            let pending_data = reader.buffer();
            if !pending_data.is_empty() {
                let len = pending_data.len();
                stream_out
                    .write_all(pending_data)
                    .await
                    .map_err(|err| format!("Failed to flush pending buffer to {host}: {err}"))?;
                reader.consume(len);
            }
        }

        let mut stream_in = reader;

        if let Err(err) = tokio::io::copy_bidirectional(&mut stream_in, &mut stream_out).await
            && err.kind() != std::io::ErrorKind::NotConnected
            && err.kind() != std::io::ErrorKind::BrokenPipe
        {
            debug!("Relay finished with error: {err}");
        }

        Ok(())
    }

    /// Определение целевого адреса (host)
    fn extract_target(buffer: &[u8]) -> Result<ProxyTarget, Box<dyn Error>> {
        if buffer.is_empty() {
            return Err("Empty buffer".into());
        }

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);

        let status = req.parse(buffer)?;

        if status.is_partial() {
            return Err("Incomplete HTTP headers".into());
        }

        let method = req.method.ok_or("Missing HTTP method")?;
        let is_connect = method == "CONNECT";

        let raw_host = if is_connect {
            req.path.ok_or("Missing path in CONNECT request")?
        } else {
            let host_header = req
                .headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case("Host"))
                .ok_or("Host header not found")?;

            std::str::from_utf8(host_header.value)?
        };

        let host = raw_host
            .split(':')
            .next()
            .ok_or("Empty host string")?
            .to_string();

        Ok(if is_connect {
            ProxyTarget::Https { host }
        } else {
            ProxyTarget::Http { host }
        })
    }
}
