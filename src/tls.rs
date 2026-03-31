use log::debug;
use rand::RngExt;
use socket2::SockRef;
use std::io;
use thiserror::Error;
use tls_parser::{
    TlsExtension, TlsMessage, TlsMessageHandshake, parse_tls_extensions, parse_tls_plaintext,
};
use tokio::io::AsyncRead;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::cli_args::TtlStrategy;

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
        // Читаем заголовок (5 байт)
        let mut header = [0u8; 5];
        reader.read_exact(&mut header).await?;

        // Проверяем тип контента (Content Type)
        // 0x16 (22) — это Handshake (куда входит ClientHello)
        // 0x17 (23) — это Application Data (уже зашифрованные данные)
        if header[0] != 0x16 && header[0] != 0x17 {
            return Err(TlsManglerError::InvalidContentType(header[0]));
        }

        // Проверяем версию протокола
        if header[1] != 0x03 {
            return Err(TlsManglerError::UnsupportedVersion(header[1], header[2]));
        }

        // Определяем длину полезной нагрузки (байты 3 и 4)
        let payload_len = u16::from_be_bytes([header[3], header[4]]) as usize;

        // Лимит - TLS ограничивает запись 16384 байтами + накладные расходы
        if payload_len > 17000 {
            return Err(TlsManglerError::RecordTooLarge(payload_len));
        }

        let mut record = vec![0u8; 5 + payload_len];
        // Копируем заголовок в начало
        record[..5].copy_from_slice(&header);
        // Читаем остальное сразу в срез вектора
        reader.read_exact(&mut record[5..]).await?;

        Ok(record)
    }

    /// Отправка TLS-header с ограниченным TTL (Fake Packet/TTL-Limited Injection)
    async fn inject_ttl_limited_packet(
        target: &mut TcpStream,
        data: &[u8],
        fake_ttl: u32,
    ) -> Result<(), TlsManglerError> {
        let original_ttl = {
            let sock = SockRef::from(&*target);
            let old_ttl = sock.ttl_v4()?;
            sock.set_ttl_v4(fake_ttl)?;
            old_ttl
        };

        // Отправляем TLS-header с низким TTL
        // Сервер все же отправит TLS-header благодаря механизму Retransmission, но уже с нормальным TLL
        target.write_all(&data[0..5]).await?;
        target.flush().await?;

        // Возвращаем исходный TTL
        {
            let sock = SockRef::from(&*target);
            sock.set_ttl_v4(original_ttl)?;
        }

        Ok(())
    }

    /// Фрагментация и отправка TLS-ClientHello + TTL-Limited Injection
    pub async fn fragment_handshake(
        fake_ttl_mode: &TtlStrategy,
        target: &mut TcpStream,
        data: &[u8],
    ) -> Result<(), TlsManglerError> {
        target.set_nodelay(true)?;

        // 0x16 - Handshake, 0x03 - (TLS 1.x)
        if data.len() > 5 && data[0] == 0x16 && data[1] == 0x03 {
            // Пробуем найти SNI и его позицию
            if let Ok((host, sni_range)) = Self::find_sni_with_range(data) {
                debug!("Fragmenting SNI for: [{host}] at range {sni_range:?}");

                // Генерируем случайные параметры сразу
                let (rand_jitter, rand_offset, rand_chunk_size, rand_ttl) = {
                    let mut rng = rand::rng();
                    (
                        rng.random_range(1..7),   // Для Jitter
                        rng.random_range(0..10),  // Для массива TTL
                        rng.random_range(10..40), // Размер первого фрагмента
                        rng.random_range(1..=5),  // Смещение для критической зоны SNI
                    )
                };

                match fake_ttl_mode {
                    TtlStrategy::Auto => {
                        // Генерируем случайный TTL в диапазоне 1..5 с весами (1: 40%, 2: 30%, 3: 10%, 4: 10%, 5: 10%)
                        let scope_ttl = [1, 1, 1, 1, 2, 2, 2, 3, 4, 5];
                        let random_ttl = { scope_ttl[rand_ttl] };

                        // Делаем иньекцию фейк TLS-header (если выбран режим Auto)
                        Self::inject_ttl_limited_packet(target, &data[0..5], random_ttl).await?;
                        debug!("TTL-Limited Injection executed (TTL={random_ttl})");
                    }
                    TtlStrategy::None => {
                        debug!("TTL-Limited Injection skipped (Mode: None)");
                    }
                }

                let current_pos = 5;
                let total_len = data.len();
                // Определяем границы критической зоны вокруг SNI для фрагментации
                let mut min_critical_zone = sni_range.start.saturating_sub(rand_offset);
                let max_critical_zone = std::cmp::min(total_len, sni_range.end + rand_offset);

                // Отправляем данные от заголовка до начала критической зоны SNI
                if min_critical_zone > current_pos {
                    target
                        .write_all(&data[current_pos..min_critical_zone])
                        .await?;
                    target.flush().await?;
                }

                // Фрагментируем критическую зону (SNI + окрестности)
                while min_critical_zone < max_critical_zone {
                    let end_pos =
                        std::cmp::min(min_critical_zone + rand_chunk_size, max_critical_zone);

                    target.write_all(&data[min_critical_zone..end_pos]).await?;
                    target.flush().await?;

                    // Добавляем Jitter для борьбы с тайминг-анализом
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
        } else {
            // Отправляем данные без изменений если это не TLS-handshake, или SNI не найден
            target.write_all(data).await?;
            target.flush().await?;
        }

        Ok(())
    }

    /// Поиск диапазон байт, где лежит SNI внутри TLS-ClientHello
    fn find_sni_with_range(
        data: &[u8],
    ) -> Result<(String, std::ops::Range<usize>), TlsManglerError> {
        let (_, record) = parse_tls_plaintext(data).map_err(|_| TlsManglerError::SniParseError)?;

        for msg in record.msg {
            if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) = msg
                && let Some(ext_data) = ch.ext
            {
                let ext_start_offset = data
                    .windows(ext_data.len())
                    .position(|window| window == ext_data)
                    .ok_or(TlsManglerError::SniParseError)?;

                if let Ok((_, extensions)) = parse_tls_extensions(ext_data) {
                    for ext in extensions {
                        if let TlsExtension::SNI(sni_list) = ext {
                            for (name_type, name_bytes) in sni_list {
                                if name_type.0 == 0 {
                                    let hostname = std::str::from_utf8(name_bytes)
                                        .map_err(|_| TlsManglerError::SniParseError)?
                                        .to_string();

                                    let start = data[ext_start_offset..]
                                        .windows(name_bytes.len())
                                        .position(|w| w == name_bytes)
                                        .ok_or(TlsManglerError::SniParseError)?
                                        + ext_start_offset;

                                    return Ok((hostname, start..start + name_bytes.len()));
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
