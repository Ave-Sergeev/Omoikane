use crate::{rand::SmallRng, settings::TlsClientHelloShapingConfig};
use log::trace;

struct TlsContext<'a> {
    ext_len_pos: usize,
    sni_slice: &'a [u8],
    psk_slice: &'a [u8],
    padding_slice: &'a [u8],
    other_exts: Vec<&'a [u8]>,
}

impl Default for TlsContext<'_> {
    fn default() -> Self {
        Self {
            ext_len_pos: 0,
            sni_slice: &[],
            psk_slice: &[],
            padding_slice: &[],
            other_exts: Vec::with_capacity(32),
        }
    }
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExtensionType {
    Sni = 0x0000,
    Alpn = 0x0010,
    Padding = 0x0015,
    Psk = 0x0029,
    SupportedVersions = 0x002B,
    KeyShare = 0x0033,
}

impl ExtensionType {
    fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0000 => Some(Self::Sni),
            0x0010 => Some(Self::Alpn),
            0x0015 => Some(Self::Padding),
            0x0029 => Some(Self::Psk),
            0x002B => Some(Self::SupportedVersions),
            0x0033 => Some(Self::KeyShare),
            _ => None,
        }
    }

    fn value(self) -> u16 {
        self as u16
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

    /// Перемешивание существующих GREASE в полях Cipher Suites и Extensions
    pub fn shuffle_grease(rng: &mut SmallRng, data: &[u8]) -> Vec<u8> {
        let shuffle_in_place = |rng: &mut SmallRng, pos: &mut Vec<usize>, data: &mut [u8]| {
            if pos.len() < 2 {
                pos.clear();
                return;
            }

            rng.shuffle_bytes_at(data, pos);
            pos.clear();
        };

        let mut new_data = data.to_vec();
        let mut positions = Vec::with_capacity(16);
        let mut inner_positions = Vec::with_capacity(16);

        let mut index = Self::CLIENT_HELLO_BASE_LEN;

        // Пропускаем Session ID
        index = match Self::skip_u8_len(&new_data, index) {
            Some(next_index) => next_index,
            None => return new_data,
        };

        // Блок Cipher Suites
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
            shuffle_in_place(rng, &mut positions, &mut new_data);
            index = end;
        }

        // Пропуск Compression Methods
        index = match Self::skip_u8_len(&new_data, index) {
            Some(next_index) => next_index,
            None => return new_data,
        };

        // Блок Extensions
        if let Some(slice) = new_data.get(index..index + 2) {
            let total_len = u16::from_be_bytes([slice[0], slice[1]]) as usize;
            let mut curr = index + 2;
            let end = (curr + total_len).min(new_data.len());

            while curr + 3 < end {
                let ext_type = u16::from_be_bytes([new_data[curr], new_data[curr + 1]]);
                let ext_len = u16::from_be_bytes([new_data[curr + 2], new_data[curr + 3]]) as usize;
                let body_start = curr + 4;
                let body_end = (body_start + ext_len).min(end);

                if Self::GREASE_VALUES.contains(&ext_type) {
                    positions.push(curr);
                }

                let mut ptr = body_start;
                if let Some(ExtensionType::Alpn | ExtensionType::SupportedVersions | ExtensionType::KeyShare) =
                    ExtensionType::from_u16(ext_type)
                    && ptr + 2 <= body_end
                {
                    ptr += 2;
                }

                while ptr + 1 < body_end {
                    let val = u16::from_be_bytes([new_data[ptr], new_data[ptr + 1]]);
                    if Self::GREASE_VALUES.contains(&val) {
                        inner_positions.push(ptr);
                    }
                    ptr += 2;
                }
                curr = body_end;
            }

            shuffle_in_place(rng, &mut positions, &mut new_data);
            shuffle_in_place(rng, &mut inner_positions, &mut new_data);
        }

        new_data
    }

    /// Пересобираем TLS-ClientHello (если возможно)
    pub fn padding_encap(rng: &mut SmallRng, data: &[u8], config: &TlsClientHelloShapingConfig) -> Vec<u8> {
        let Some(ctx) = Self::parse_tls_layout(data) else {
            trace!("Skipping padding transformation: Failed to parse TLS-layout");
            return data.to_vec();
        };

        if ctx.sni_slice.is_empty() {
            trace!("Skipping padding transformation: SNI not found OR Padding not found");
            return data.to_vec();
        }

        Self::transform_padding(rng, data, ctx, config)
    }

    /// Разбираем структуру TLS-ClientHello на компоненты без копирования данных
    fn parse_tls_layout(data: &[u8]) -> Option<TlsContext<'_>> {
        let mut index = Self::CLIENT_HELLO_BASE_LEN;

        index = Self::skip_u8_len(data, index)?; // Пропускаем Session ID
        index = Self::skip_u16_len(data, index)?; // Пропускаем Cipher Suites
        index = Self::skip_u8_len(data, index)?; // Пропускаем Compression Methods

        if index + 2 > data.len() {
            return None;
        }

        // Определяем границы блока расширений
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

            // SNI, Padding, PSK берем отдельно, остальное в общий список
            match ExtensionType::from_u16(etype) {
                Some(ExtensionType::Sni) => ctx.sni_slice = &data[curr..curr + full_len],
                Some(ExtensionType::Padding) => ctx.padding_slice = &data[curr..curr + full_len],
                Some(ExtensionType::Psk) => ctx.psk_slice = &data[curr..curr + full_len],
                _ => ctx.other_exts.push(&data[curr..curr + full_len]),
            }
            curr += full_len;
        }
        Some(ctx)
    }

    /// Пересобираем TLS-ClientHello, c модификацией Padding и перемешиванием Extension
    #[allow(clippy::cast_possible_truncation)]
    fn transform_padding(
        rng: &mut SmallRng,
        data: &[u8],
        ctx: TlsContext,
        config: &TlsClientHelloShapingConfig,
    ) -> Vec<u8> {
        // Определяем целевой размер TLS-ClientHello
        let target_total_len = if ctx.padding_slice.is_empty() {
            data.len()
        } else {
            let (min, max) = if rng.gen_bool(config.light_profile_ratio) {
                config.light_client_hello_size
            } else {
                config.heavy_client_hello_size
            };
            rng.gen_range_usize(min, max)
        };

        // Копируем изначальный TLS-ClientHello до блока Extensions
        let mut final_data = Vec::with_capacity(target_total_len);
        final_data.extend_from_slice(&data[..ctx.ext_len_pos]);
        final_data.extend_from_slice(&[0, 0]); // Заглушка под новую длину Extensions
        let ext_start_in_final = final_data.len();

        // Добавляем SNI
        final_data.extend_from_slice(ctx.sni_slice);

        // Добавляем остальные Extensions
        for ext in ctx.other_exts {
            final_data.extend_from_slice(ext);
        }

        // Добавляем Padding если был (с новым наполнением)
        if !ctx.padding_slice.is_empty() {
            let diff = target_total_len.saturating_sub(data.len());
            let real_pad_payload_len = ctx.padding_slice.len().saturating_sub(4);
            let total_pad_len = real_pad_payload_len + diff;

            // Выбираем тип Padding
            let padding_type = if rng.gen_bool(config.grease_ratio) {
                let grease_val = Self::GREASE_VALUES[rng.gen_range_usize(0, Self::GREASE_VALUES.len() - 1)];
                grease_val.to_be_bytes()
            } else {
                ExtensionType::Padding.value().to_be_bytes()
            };

            final_data.extend_from_slice(&padding_type); // Докидываем тип Padding
            final_data.extend_from_slice(&(total_pad_len as u16).to_be_bytes()); // Докидываем длину

            // Забиваем значениями
            let padding_bytes = (0..total_pad_len).map(|_| {
                if rng.gen_bool(config.padding_entropy_ratio) {
                    rng.gen_range_usize(0, 256) as u8
                } else {
                    0_u8
                }
            });
            final_data.extend(padding_bytes);
        }

        // PSK в конце
        if !ctx.psk_slice.is_empty() {
            final_data.extend_from_slice(ctx.psk_slice);
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
