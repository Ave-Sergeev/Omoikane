use crate::settings::{CliArgs, TtlStrategy};
use log::trace;
use rand::RngExt;
use socket2::SockRef;
use std::io;
use thiserror::Error;
use tls_parser::{TlsExtension, TlsMessage, TlsMessageHandshake, parse_tls_extensions, parse_tls_plaintext};
use tokio::io::AsyncRead;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Error)]
pub enum TlsManglerError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Invalid TLS content type: 0x{0:02X}")]
    InvalidContentType(u8),

    #[error("Unsupported TLS version: {0}.{1}")]
    UnsupportedVersion(u8, u8),

    #[error("TLS record too large: {0} bytes")]
    RecordTooLarge(usize),

    #[error("SNI parsing error")]
    SniParseError,
}

pub struct TlsMangler;

impl TlsMangler {
    /// Чтение одной полной TLS-записи (Record) из TCP-stream
    pub async fn read_full_record<R>(reader: &mut R) -> Result<Vec<u8>, TlsManglerError>
    where
        R: AsyncRead + Unpin,
    {
        let mut header = [0u8; 5];
        reader.read_exact(&mut header).await?;

        // Проверяем тип контента (0x16 (22) — Handshake)
        if header[0] != 0x16 {
            return Err(TlsManglerError::InvalidContentType(header[0]));
        }

        // Проверяем версию протокола
        if header[1] != 0x03 {
            return Err(TlsManglerError::UnsupportedVersion(header[1], header[2]));
        }

        let payload_len = u16::from_be_bytes([header[3], header[4]]) as usize;

        // Лимит - TLS ограничивает запись 16384 байтами + накладные расходы
        if payload_len > 17000 {
            return Err(TlsManglerError::RecordTooLarge(payload_len));
        }

        let mut record = vec![0u8; 5 + payload_len];
        record[..5].copy_from_slice(&header);
        reader.read_exact(&mut record[5..]).await?;

        Ok(record)
    }

    /// Отправка TLS-header с фейк TTL (Fake Packet/TTL-Limited Injection)
    async fn inject_ttl_limited_packet(
        target: &mut TcpStream,
        data: &[u8],
        fake_ttl: u32,
    ) -> Result<(), TlsManglerError> {
        let peer_addr = target.peer_addr()?;
        let is_ipv4 = peer_addr.is_ipv4();

        let original_ttl = {
            let sock = SockRef::from(&target);

            if is_ipv4 {
                let old_ttl = sock.ttl_v4()?;
                sock.set_ttl_v4(fake_ttl)?;
                old_ttl
            } else {
                let old_ttl = sock.unicast_hops_v6()?;
                sock.set_unicast_hops_v6(fake_ttl)?;
                old_ttl
            }
        };

        // Отправляем TLS-header с заданным TTL
        // Сервер переотправит TLS-header благодаря механизму Retransmission, но уже с нормальным TLL
        target.write_all(&data[0..5]).await?;
        target.flush().await?;

        {
            let sock = SockRef::from(&*target);
            if is_ipv4 {
                sock.set_ttl_v4(original_ttl)?;
            } else {
                sock.set_unicast_hops_v6(original_ttl)?;
            }
        }

        Ok(())
    }

    /// Фрагментация и отправка TLS-ClientHello + TTL-Limited Injection
    pub async fn fragment_handshake(
        args: &CliArgs,
        target: &mut TcpStream,
        data: &[u8],
    ) -> Result<(), TlsManglerError> {
        target.set_nodelay(true)?;

        // 0x16 - Handshake, 0x03 - (TLS 1.x)
        if data.len() > 5 && data[0] == 0x16 && data[1] == 0x03 {
            // Пробуем найти SNI и его позицию
            if let Ok((host, sni_range)) = Self::find_sni_with_range(data) {
                trace!("Fragmenting SNI for: [{host}] at range {sni_range:?}");

                let (rand_jitter, rand_chunk_size, rand_offset) = {
                    let mut rng = rand::rng();
                    (
                        rng.random_range(1..7),   // Для Jitter
                        rng.random_range(10..40), // Размер первого фрагмента
                        rng.random_range(1..=5),  // Смещение для критической зоны SNI
                    )
                };

                let mut current_pos = 0;
                let total_len = data.len();

                match args.https_fake_ttl_mode {
                    TtlStrategy::None => {
                        trace!("[{host}] TTL-Limited Injection skipped (Mode: None)");
                    }
                    TtlStrategy::Custom => {
                        let ttl_to_use = u32::from(args.https_fake_ttl_value);

                        Self::inject_ttl_limited_packet(target, &data[0..5], ttl_to_use).await?;
                        current_pos = 5;
                        trace!("[{host}] TTL-Limited Injection executed (TTL={ttl_to_use})");
                    }
                }

                // Определяем границы критической зоны вокруг SNI для фрагментации
                let mut min_critical_zone = sni_range.start.saturating_sub(rand_offset).max(current_pos);
                let max_critical_zone = std::cmp::min(total_len, sni_range.end + rand_offset);

                // Отправляем данные от заголовка до начала критической зоны SNI
                if min_critical_zone > current_pos {
                    target.write_all(&data[current_pos..min_critical_zone]).await?;
                    target.flush().await?;
                }

                // Фрагментируем критическую зону (SNI + окрестности)
                while min_critical_zone < max_critical_zone {
                    let end_pos = std::cmp::min(min_critical_zone + rand_chunk_size, max_critical_zone);

                    target.write_all(&data[min_critical_zone..end_pos]).await?;
                    target.flush().await?;

                    // Добавляем Jitter для борьбы с тайм-анализом
                    tokio::time::sleep(std::time::Duration::from_millis(rand_jitter)).await;
                    min_critical_zone = end_pos;
                }

                // Досылаем остаток TLS-пакета после критической зоны одним фрагментом
                if max_critical_zone < total_len {
                    target.write_all(&data[max_critical_zone..]).await?;
                    target.flush().await?;
                }

                return Ok(());
            }
        }

        // Отправляем данные без изменений если это не TLS-handshake, или SNI не найден
        target.write_all(data).await?;
        target.flush().await?;

        Ok(())
    }

    /// Поиск диапазон байт, где лежит SNI внутри TLS-ClientHello
    fn find_sni_with_range(data: &[u8]) -> Result<(String, std::ops::Range<usize>), TlsManglerError> {
        let (_, record) = parse_tls_plaintext(data).map_err(|_| TlsManglerError::SniParseError)?;

        for msg in record.msg {
            if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) = msg {
                let ext_data = ch.ext.ok_or(TlsManglerError::SniParseError)?;

                if let Ok((_, extensions)) = parse_tls_extensions(ext_data) {
                    for ext in extensions {
                        if let TlsExtension::SNI(sni_list) = ext {
                            for (name_type, name_bytes) in sni_list {
                                if name_type.0 == 0 {
                                    let hostname = std::str::from_utf8(name_bytes)
                                        .map_err(|_| TlsManglerError::SniParseError)?
                                        .to_string();

                                    let start_offset =
                                        unsafe { name_bytes.as_ptr().offset_from(data.as_ptr()) }.cast_unsigned();
                                    let range = start_offset..start_offset + name_bytes.len();

                                    if range.end <= data.len() {
                                        return Ok((hostname, range));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Err(TlsManglerError::SniParseError)
    }
}
