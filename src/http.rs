use rand::RngExt;
use rand::seq::SliceRandom;
use std::io;
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

#[derive(Error, Debug)]
pub enum HttpManglerError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Malformed HTTP request")]
    MalformedRequest,

    #[error("Missing Host header")]
    MissingHost,
}

pub struct HttpMangler;

impl HttpMangler {
    /// Модификация HTTP-headers
    pub fn modify_http_headers(data: &[u8]) -> Result<Vec<u8>, HttpManglerError> {
        let mut rng = rand::rng();

        let header_end = data
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or(HttpManglerError::MalformedRequest)?;

        let (header_part, body_part) = (&data[..header_end], &data[header_end + 4..]);
        let header_str = std::str::from_utf8(header_part).map_err(|_| HttpManglerError::MalformedRequest)?;
        let mut lines = header_str.lines();

        let first_line = lines.next().ok_or(HttpManglerError::MalformedRequest)?;
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(HttpManglerError::MalformedRequest);
        }

        let method = parts[0];
        let raw_path = parts[1];

        let mut all_headers = Vec::new();
        let mut host_val: Option<String> = None;

        for line in lines {
            if let Some((key, val)) = line.split_once(':') {
                let trimmed_key = key.trim();
                if trimmed_key.eq_ignore_ascii_case("Host") {
                    let original_host = val.trim();
                    // Применяем Header Case + Dot Trick
                    let scrambled = Self::scramble_host(original_host);

                    let host_keys = [
                        "host", "Host", "hOst", "hoSt", "hosT", "HOst", "HoSt", "HosT", "hOSt", "hOsT", "hoST", "HOSt",
                        "HoST", "hOST", "HOsT", "HOST",
                    ];
                    let host_key = host_keys[rand::random_range(0..6)];

                    let formatted_host = format!("{host_key}: {scrambled}\r\n");
                    host_val = Some(scrambled);

                    all_headers.push(formatted_host);
                    continue;
                }
            }
            if !line.is_empty() {
                all_headers.push(format!("{line}\r\n"));
            }
        }

        let host = host_val.ok_or(HttpManglerError::MissingHost)?;

        all_headers.shuffle(&mut rng);

        let clean_path = if raw_path.starts_with("http") {
            raw_path.splitn(4, '/').last().unwrap_or("/")
        } else {
            raw_path
        };

        let mut final_data = Vec::with_capacity(data.len() + 128);

        // Применяем Space Trick + Absolute URI
        let request_line = Self::build_request_line(method, &host, clean_path);
        final_data.extend_from_slice(request_line.as_bytes());

        // Добавляем перемешанные заголовки
        for header in all_headers {
            final_data.extend_from_slice(header.as_bytes());
        }

        // Добавляем разделитель и тело
        final_data.extend_from_slice(b"\r\n");
        final_data.extend_from_slice(body_part);

        Ok(final_data)
    }

    /// Фрагментация и отправка HTTP-headers
    pub async fn send_split_request(target: &mut TcpStream, modified_headers: &[u8]) -> Result<(), HttpManglerError> {
        target.set_nodelay(true)?;

        if modified_headers.len() < 4 {
            target.write_all(modified_headers).await?;
            return Ok(());
        }

        // Отправляем первые 2 байта
        target.write_all(&modified_headers[0..2]).await?;
        target.flush().await?;

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        // Отправляем следующие несколько байт
        target.write_all(&modified_headers[2..5]).await?;
        target.flush().await?;

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        // Отправляем всё остальное (нарезав на части по 32 байта)
        for chunk in modified_headers[5..].chunks(32) {
            target.write_all(chunk).await?;
            target.flush().await?;
            tokio::time::sleep(std::time::Duration::from_millis(3)).await;
        }

        Ok(())
    }

    /// Применение методов Header Case + Dot Trick
    fn scramble_host(host: &str) -> String {
        let mut rng = rand::rng();

        let mut scrambled: String = host
            .chars()
            .map(|c| {
                // С вероятностью 50% меняем регистр на верхний
                if rng.random_bool(0.5) {
                    c.to_ascii_uppercase()
                } else {
                    c.to_ascii_lowercase()
                }
            })
            .collect();

        scrambled.push('.');
        scrambled
    }

    /// Применение методов Space Trick + Absolute URI
    fn build_request_line(method: &str, host: &str, path: &str) -> String {
        let mut rng = rand::rng();

        let space_count = rng.random_range(2..6);
        let spaces = " ".repeat(space_count);

        let path = path.strip_prefix('/').unwrap_or(path);

        format!("{method}{spaces}http://{host}/{path} HTTP/1.1\r\n")
    }
}
