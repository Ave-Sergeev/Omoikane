use crate::fingerprint::TlsFingerprint;
use crate::rand::SmallRng;
use crate::settings::{CliArgs, EngineConfig, TlsClientHelloShapingConfig, TlsSplitMode, TtlStrategy};
use log::trace;
use socket2::SockRef;
use std::io;
use std::net::SocketAddr;
use std::ops::Range;
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

    #[error("Invalid TLS handshake type: 0x{0:02X}, expected ClientHello (0x01)")]
    InvalidHandshakeType(u8),

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

        // 0x16 (22) — Handshake
        if header[0] != 0x16 {
            return Err(TlsManglerError::InvalidContentType(header[0]));
        }

        // 0x03 - TLS 1.x
        if header[1] != 0x03 {
            return Err(TlsManglerError::UnsupportedVersion(header[1], header[2]));
        }

        // Лимит записи TLS 16384 байт + накладные расходы
        let payload_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if payload_len > 17000 {
            return Err(TlsManglerError::RecordTooLarge(payload_len));
        }

        let mut payload = vec![0u8; payload_len];
        reader.read_exact(&mut payload).await?;

        // 0x01 — Client Hello
        if payload.is_empty() || payload[0] != 0x01 {
            return Err(TlsManglerError::InvalidHandshakeType(payload[0]));
        }

        let mut record = Vec::with_capacity(5 + payload_len);
        record.extend_from_slice(&header);
        record.extend_from_slice(&payload);

        Ok(record)
    }

    /// Отправка TLS-header с фейк TTL (Fake Packet/TTL-Limited Injection)
    async fn inject_ttl_limited_packet(
        target: &mut TcpStream,
        data: &[u8],
        fake_ttl: u32,
    ) -> Result<(), TlsManglerError> {
        let peer_addr = target.peer_addr()?;

        let original_ttl = {
            let sock = SockRef::from(&*target);

            match peer_addr {
                SocketAddr::V4(_) => {
                    let old_ttl = sock.ttl_v4()?;
                    sock.set_ttl_v4(fake_ttl)?;
                    old_ttl
                }
                SocketAddr::V6(_) => {
                    let old_ttl = sock.unicast_hops_v6()?;
                    sock.set_unicast_hops_v6(fake_ttl)?;
                    old_ttl
                }
            }
        };

        // TLS-header переотправится через Retransmission уже с нормальным TLL
        target.write_all(data).await?;
        target.flush().await?;

        let sock = SockRef::from(&*target);
        match peer_addr {
            SocketAddr::V4(_) => sock.set_ttl_v4(original_ttl)?,
            SocketAddr::V6(_) => sock.set_unicast_hops_v6(original_ttl)?,
        }

        Ok(())
    }

    /// Фрагментация и отправка TLS-ClientHello + TTL-Limited Injection
    pub async fn tls_fragmentation(
        rng: &mut SmallRng,
        args: &CliArgs,
        config: &EngineConfig,
        target: &mut TcpStream,
        data: &[u8],
    ) -> Result<(), TlsManglerError> {
        target.set_nodelay(true)?;

        // 0x16 - Handshake, 0x03 - TLS 1.x
        if data.len() > 5
            && data[0] == 0x16
            && data[1] == 0x03
            && let Ok((host, sni_range)) = Self::find_sni_with_range(data)
        {
            let mut current_pos = 0;
            let total_len = data.len();

            match args.tls_fake_ttl_mode {
                TtlStrategy::Custom => {
                    let ttl_to_use = u32::from(args.tls_fake_ttl_value);
                    Self::inject_ttl_limited_packet(target, &data[0..5], ttl_to_use).await?;
                    current_pos = 5;
                    trace!("[{host}] TTL-Limited Injection executed (TTL={ttl_to_use})");
                }
                TtlStrategy::None => {
                    trace!("[{host}] TTL-Limited Injection skipped (FakeTtlMode: None)");
                }
            }

            match args.tls_split_mode {
                TlsSplitMode::None => {
                    trace!("Sending remaining data as-is (SplitMode: None)");
                    target.write_all(&data[current_pos..]).await?;
                }
                TlsSplitMode::Sni => {
                    trace!("Start fragmenting [{host}] using `SNI strategy` at range {sni_range:?}");
                    let config = &config.tls_fragmentation_sni;

                    let (rand_jitter, rand_sni_offset) = (
                        rng.gen_range_u64(config.first_jitter_ms.0, config.first_jitter_ms.1),
                        rng.gen_range_usize(config.sni_offset.0, config.sni_offset.1),
                    );

                    // Определяем границы критической зоны вокруг SNI для фрагментации
                    let min_critical_zone = sni_range.start.saturating_sub(rand_sni_offset).max(current_pos);
                    let max_critical_zone = std::cmp::min(total_len, sni_range.end + rand_sni_offset);

                    // Отправляем данные от заголовка до начала критической зоны SNI
                    if min_critical_zone > current_pos {
                        target.write_all(&data[current_pos..min_critical_zone]).await?;
                        target.flush().await?;
                        tokio::time::sleep(std::time::Duration::from_millis(rand_jitter)).await;
                    }

                    // Фрагментируем критическую зону (SNI + окрестности) и отправляем
                    Self::write_in_chunks(
                        rng,
                        target,
                        &data[min_critical_zone..max_critical_zone],
                        config.chunk_size,
                        config.chunk_jitter_ms,
                    )
                    .await?;

                    // Досылаем остаток TLS-пакета после критической зоны одним фрагментом
                    if max_critical_zone < total_len {
                        target.write_all(&data[max_critical_zone..]).await?;
                        target.flush().await?;
                    }
                }
                TlsSplitMode::Random => {
                    trace!("Start fragmenting [{host}] using `Random` strategy`");
                    let config = &config.tls_fragmentation_random;

                    // Фрагментируем и отправляем все данные (header отправлен ранее)
                    Self::write_in_chunks(rng, target, &data[current_pos..], config.chunk_size, config.chunk_jitter_ms)
                        .await?;
                }
            }

            return Ok(());
        }

        // Отправляем без изменений если это не TLS-handshake, или SNI не найден
        trace!("Skipping fragmentation: SNI missing or non-handshake data");
        target.write_all(data).await?;
        target.flush().await?;

        Ok(())
    }

    /// Логика фрагментации на чанки, и их отправка
    async fn write_in_chunks(
        rng: &mut SmallRng,
        target: &mut TcpStream,
        data: &[u8],
        chunk_size: (usize, usize),
        jitter_range: (u64, u64),
    ) -> Result<(), TlsManglerError> {
        let mut current_position = 0;
        let end_position = data.len();

        while current_position < end_position {
            let min_size = chunk_size.0.max(1);
            let max_size = chunk_size.1.max(min_size);
            let current_rand_chunk_size = rng.gen_range_usize(min_size, max_size);
            let end_pos = std::cmp::min(current_position + current_rand_chunk_size, end_position);

            target.write_all(&data[current_position..end_pos]).await?;
            target.flush().await?;

            // Jitter для борьбы с тайм-анализом
            let jitter = rng.gen_range_u64(jitter_range.0, jitter_range.1);
            if jitter > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(jitter)).await;
            }

            current_position = end_pos;
        }

        Ok(())
    }

    /// Подготовка данных TLS (GREASE + Padding)
    pub fn prepare_tls_data(rng: &mut SmallRng, data: &[u8], config: &TlsClientHelloShapingConfig) -> Vec<u8> {
        // 0x16 - Handshake, 0x03 - TLS 1.x
        let is_tls_handshake = data.len() > 5 && data[0] == 0x16 && data[1] == 0x03;

        if is_tls_handshake {
            let shuffled = TlsFingerprint::shuffle_grease(rng, data);
            TlsFingerprint::transform_extensions(rng, &shuffled, config)
        } else {
            data.to_vec()
        }
    }

    /// Поиск диапазон байт, где лежит SNI внутри TLS-ClientHello
    fn find_sni_with_range(data: &[u8]) -> Result<(String, Range<usize>), TlsManglerError> {
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
