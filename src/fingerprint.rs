use crate::{rand::SmallRng, settings::TlsClientHelloShapingConfig};
use log::trace;

struct TlsContext<'a> {
    has_sni: bool,
    has_padding: bool,
    ext_len_pos: usize,
    all_extensions: Vec<&'a [u8]>,
}

impl Default for TlsContext<'_> {
    fn default() -> Self {
        Self {
            has_sni: false,
            has_padding: false,
            ext_len_pos: 0,
            all_extensions: Vec::with_capacity(16),
        }
    }
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExtensionType {
    Sni = 0x0000,
    Psk = 0x0029,
    Alpn = 0x0010,
    Padding = 0x0015,
    KeyShare = 0x0033,
    StatusRequest = 0x0005,
    SessionTicket = 0x0023,
    EcPointFormats = 0x000B,
    RecordSizeLimit = 0x001C,
    SupportedGroups = 0x000A,
    SupportedVersions = 0x002B,
    RenegotiationInfo = 0xFF01,
    SignatureAlgorithms = 0x000D,
    PskKeyExchangeModes = 0x002D,
    CompressCertificate = 0x001B,
    ExtendedMasterSecret = 0x0017,
    DelegatedCredentials = 0x0022,
    EncryptedClientHello = 0xFE0D,
    QuicTransportParameters = 0x44CD,
    SignedCertificateTimestamp = 0x0012,
}

impl ExtensionType {
    fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0000 => Some(Self::Sni),
            0x0029 => Some(Self::Psk),
            0x0010 => Some(Self::Alpn),
            0x0015 => Some(Self::Padding),
            0x0033 => Some(Self::KeyShare),
            0x0005 => Some(Self::StatusRequest),
            0x0023 => Some(Self::SessionTicket),
            0x000B => Some(Self::EcPointFormats),
            0x001C => Some(Self::RecordSizeLimit),
            0x000A => Some(Self::SupportedGroups),
            0xFF01 => Some(Self::RenegotiationInfo),
            0x002B => Some(Self::SupportedVersions),
            0x000D => Some(Self::SignatureAlgorithms),
            0x001B => Some(Self::CompressCertificate),
            0x002D => Some(Self::PskKeyExchangeModes),
            0x0017 => Some(Self::ExtendedMasterSecret),
            0x0022 => Some(Self::DelegatedCredentials),
            0xFE0D => Some(Self::EncryptedClientHello),
            0x44CD => Some(Self::QuicTransportParameters),
            0x0012 => Some(Self::SignedCertificateTimestamp),
            _ => None,
        }
    }
}

pub struct TlsFingerprint;

impl TlsFingerprint {
    // Record Header (5) + Handshake Header (4) + Version (2) + Client Random (32) = 43
    const CLIENT_HELLO_BASE_LEN: usize = 43;
    const GREASE_VALUES: [u16; 16] = [
        0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA,
        0xEAEA, 0xFAFA,
    ];

    /// Перемешиваем существующие GREASE в Cipher Suites
    pub fn shuffle_grease(rng: &mut SmallRng, data: &[u8]) -> Vec<u8> {
        // Начальная позиция после Record Header и Handshake Header
        let mut index = Self::CLIENT_HELLO_BASE_LEN;
        let mut new_data = data.to_vec();
        let mut positions = Vec::with_capacity(16);

        // Пропускаем Session ID
        index = match Self::skip_u8_len(&new_data, index) {
            Some(next_index) => next_index,
            None => return new_data,
        };

        // Перемешиваем GREASE в блоке Cipher Suites
        if let Some(slice) = new_data.get(index..index + 2) {
            let len = u16::from_be_bytes([slice[0], slice[1]]) as usize;
            let start = index + 2;
            let end = (start + len).min(new_data.len());

            for curr in (start..end.saturating_sub(1)).step_by(2) {
                let val = u16::from_be_bytes([new_data[curr], new_data[curr + 1]]);
                if Self::GREASE_VALUES.contains(&val) {
                    positions.push(curr);
                }
            }

            if positions.len() >= 2 {
                rng.shuffle_bytes_at(&mut new_data, &mut positions);
            }
            positions.clear();
        }

        new_data
    }

    /// Модифицируем и пересобираем TLS-ClientHello (по возможности)
    pub fn transform_extensions(rng: &mut SmallRng, data: &[u8], config: &TlsClientHelloShapingConfig) -> Vec<u8> {
        let Some(ctx) = Self::parse_tls_layout(data) else {
            trace!("Skipping padding transformation: Failed to parse TLS-layout");
            return data.to_vec();
        };

        if !ctx.has_sni {
            trace!("Skipping padding transformation: SNI not found");
            return data.to_vec();
        }

        // TODO: Убрать, чтоб в transform_tls_client_hello оставлять перемешивание, даже если нет Padding
        if !ctx.has_padding {
            trace!("Skipping padding transformation: Padding not found");
            return data.to_vec();
        }

        Self::transform_tls_client_hello(rng, data, ctx, config)
    }

    /// Парсим TLS-ClientHello
    fn parse_tls_layout(data: &[u8]) -> Option<TlsContext<'_>> {
        // Начальная позиция после Record Header и Handshake Header
        let mut index = Self::CLIENT_HELLO_BASE_LEN;

        index = Self::skip_u8_len(data, index)?; // Пропускаем Session ID
        index = Self::skip_u16_len(data, index)?; // Пропускаем Cipher Suites
        index = Self::skip_u8_len(data, index)?; // Пропускаем Compression Methods

        if index + 2 > data.len() {
            return None;
        }

        // Определяем границы блока Extensions
        let total_ext_len = u16::from_be_bytes([data[index], data[index + 1]]) as usize;
        let mut curr = index + 2;
        let ext_end = curr + total_ext_len;

        if ext_end > data.len() {
            return None;
        }

        let mut ctx = TlsContext {
            ext_len_pos: index,
            ..Default::default()
        };

        // Итерируемся по расширениям
        while curr + 4 <= ext_end {
            let etype = u16::from_be_bytes([data[curr], data[curr + 1]]);
            let elen = u16::from_be_bytes([data[curr + 2], data[curr + 3]]) as usize;
            let full_len = 4 + elen;
            if curr + full_len > data.len() {
                break;
            }

            // Перебираем Extensions, помечая что нашли SNI и Padding
            match ExtensionType::from_u16(etype) {
                Some(ExtensionType::Sni) => {
                    ctx.has_sni = true;
                    ctx.all_extensions.push(&data[curr..curr + full_len]);
                }
                Some(ExtensionType::Padding) => {
                    ctx.has_padding = true;
                    ctx.all_extensions.push(&data[curr..curr + full_len]);
                }
                _ => ctx.all_extensions.push(&data[curr..curr + full_len]),
            }
            curr += full_len;
        }
        Some(ctx)
    }

    /// Пересобираем TLS-ClientHello, c модификацией Padding и перемешиванием содержимого некоторых Extension
    #[allow(clippy::cast_possible_truncation)]
    fn transform_tls_client_hello(
        rng: &mut SmallRng,
        data: &[u8],
        ctx: TlsContext,
        config: &TlsClientHelloShapingConfig,
    ) -> Vec<u8> {
        // Определяем целевой размер TLS-ClientHello
        let target_total_len = {
            let old_target = data.len();
            let (min, max) = if rng.gen_bool(config.light_profile_ratio) {
                config.light_client_hello_delta
            } else {
                config.heavy_client_hello_delta
            };

            let mut target = old_target + rng.gen_range_usize(min, max);

            if (256..=511).contains(&target) {
                target = 512 + rng.gen_range_usize(min, max);
            }

            target.min(60000)
        };

        // Копируем изначальный TLS-ClientHello до блока Extensions
        let mut final_data = Vec::with_capacity(target_total_len);
        final_data.extend_from_slice(&data[..ctx.ext_len_pos]);
        final_data.extend_from_slice(&[0, 0]); // Заглушка под новую длину Extensions
        let ext_start_in_final = final_data.len();

        for ext in ctx.all_extensions {
            let ext_type = u16::from_be_bytes([ext[0], ext[1]]);

            match ext_type {
                // Расширяем найденный Padding
                0x0015 => {
                    let diff = target_total_len.saturating_sub(data.len());
                    let real_pad_payload_len = ext.len().saturating_sub(4);
                    let total_pad_len = real_pad_payload_len + diff;

                    // Выбираем тип Padding
                    let padding_type = if rng.gen_bool(config.grease_ratio) {
                        let grease_val = Self::GREASE_VALUES[rng.gen_range_usize(0, Self::GREASE_VALUES.len() - 1)];
                        grease_val.to_be_bytes()
                    } else {
                        [0x00, 0x15]
                    };

                    final_data.extend_from_slice(&padding_type);
                    final_data.extend_from_slice(&(total_pad_len as u16).to_be_bytes());

                    // Заполняем Padding
                    let padding_bytes = (0..total_pad_len).map(|_| {
                        if rng.gen_bool(config.padding_entropy_ratio) {
                            rng.gen_range_usize(0, 256) as u8
                        } else {
                            0_u8
                        }
                    });

                    final_data.extend(padding_bytes);
                }
                // Премешиваем содержимое Supported Groups (0x000a) и Supported Versions (0x002b)
                0x000a | 0x002b if ext.len() >= 6 => {
                    let mut shuffled_ext = ext.to_vec();

                    // Type(2) + ExtLen(2) + ListLen(2)
                    let list_start = 6;
                    let list_end = shuffled_ext.len();

                    let mut positions: Vec<usize> = (list_start..list_end.saturating_sub(1)).step_by(2).collect();

                    if positions.len() >= 2 {
                        rng.shuffle_bytes_at(&mut shuffled_ext, &mut positions);
                    }

                    final_data.extend_from_slice(&shuffled_ext);
                }
                _ => {
                    final_data.extend_from_slice(ext);
                }
            }
        }

        // Корректируем длины в заголовках
        Self::finalize_headers(final_data, ctx.ext_len_pos, ext_start_in_final)
    }

    /// Корректируем поля длины в TLS-record и Handshake заголовках
    #[allow(clippy::cast_possible_truncation)]
    fn finalize_headers(mut final_data: Vec<u8>, ext_len_pos: usize, ext_start: usize) -> Vec<u8> {
        // Обновляем длину блока Extensions
        let final_ext_len = (final_data.len() - ext_start) as u16;
        let ext_bytes = (final_ext_len).to_be_bytes();
        final_data[ext_len_pos] = ext_bytes[0];
        final_data[ext_len_pos + 1] = ext_bytes[1];

        let total_len = final_data.len();

        // Обновляем длину всей TLS-record (за вычетом 5 байт Record)
        let rec_len = (total_len.saturating_sub(5)) as u16;
        final_data[3..5].copy_from_slice(&rec_len.to_be_bytes());

        // Обновляем длину Handshake (за вычетом 9 байт: 5 Record + 4 Handshake)
        let hs_len = (total_len.saturating_sub(9)) as u32;
        let hlb = hs_len.to_be_bytes();
        // Длина Handshake 3 байта (с 6-го по 9-й)
        final_data[6..9].copy_from_slice(&hlb[1..4]);

        final_data
    }

    fn skip_u8_len(data: &[u8], pos: usize) -> Option<usize> {
        data.get(pos)
            .map(|&len| pos + 1 + len as usize)
            .filter(|&next| next <= data.len())
    }

    fn skip_u16_len(data: &[u8], pos: usize) -> Option<usize> {
        data.get(pos..pos + 2)
            .map(|slice| pos + 2 + u16::from_be_bytes([slice[0], slice[1]]) as usize)
            .filter(|&next| next <= data.len())
    }
}
