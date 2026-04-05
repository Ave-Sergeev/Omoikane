use crate::rand::SmallRng;
use crate::settings::HttpFragmentationConfig;
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
    pub fn modify_http_headers(rng: &mut SmallRng, data: &[u8]) -> Result<Vec<u8>, HttpManglerError> {
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
                    let scrambled = Self::scramble_host(rng, original_host);

                    let host_keys = [
                        "host", "Host", "hOst", "hoSt", "hosT", "HOst", "HoSt", "HosT", "hOSt", "hOsT", "hoST", "HOSt",
                        "HoST", "hOST", "HOsT", "HOST",
                    ];
                    let host_key = host_keys[rng.gen_range_usize(0, 6)];

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

        rng.shuffle(&mut all_headers);

        let clean_path = if raw_path.starts_with("http") {
            raw_path.splitn(4, '/').last().unwrap_or("/")
        } else {
            raw_path
        };

        let mut final_data = Vec::with_capacity(data.len() + 128);

        // Применяем Space Trick + Absolute URI
        let request_line = Self::build_request_line(rng, method, &host, clean_path);
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
    pub async fn send_split_request(
        rng: &mut SmallRng,
        config: &HttpFragmentationConfig,
        target: &mut TcpStream,
        modified_headers: &[u8],
    ) -> Result<(), HttpManglerError> {
        target.set_nodelay(true)?;

        let (rand_jitter, rand_offset, rand_chunk_size) = {
            (
                rng.gen_range_u64(config.first_jitter_ms.0, config.first_jitter_ms.1),
                rng.gen_range_usize(config.first_offset.0, config.first_offset.1),
                rng.gen_range_usize(config.chunk_size.0, config.chunk_size.1),
            )
        };

        let total_len = modified_headers.len();

        // Отправляем первую часть
        let first_split = std::cmp::min(rand_offset, total_len);
        if first_split > 0 {
            target.write_all(&modified_headers[..first_split]).await?;
            target.flush().await?;
            tokio::time::sleep(std::time::Duration::from_millis(rand_jitter)).await;
        }

        // Отправляем всё остальное, нарезая на рандомные чанки
        if first_split < total_len {
            let remaining = &modified_headers[first_split..];

            for chunk in remaining.chunks(rand_chunk_size) {
                target.write_all(chunk).await?;
                target.flush().await?;

                // Jitter для борьбы с тайм-анализом
                let jitter = rng.gen_range_u64(config.chunk_jitter_ms.0, config.chunk_jitter_ms.1);
                tokio::time::sleep(std::time::Duration::from_millis(jitter)).await;
            }
        }

        Ok(())
    }

    /// Применение методов Header Case + Dot Trick
    fn scramble_host(rng: &mut SmallRng, host: &str) -> String {
        let mut scrambled: String = host
            .chars()
            .map(|c| {
                if rng.gen_bool(0.5) {
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
    fn build_request_line(rng: &mut SmallRng, method: &str, host: &str, path: &str) -> String {
        let space_count = rng.gen_range_usize(1, 4);
        let spaces = " ".repeat(space_count);
        let path = path.strip_prefix('/').unwrap_or(path);

        format!("{method}{spaces}http://{host}/{path} HTTP/1.1\r\n")
    }
}
