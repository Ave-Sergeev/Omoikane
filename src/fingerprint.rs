use crate::rand::SmallRng;

pub struct TlsFingerprint;

impl TlsFingerprint {
    /// Перемешивание существующих GREASE-значения в полях Cipher Suites и Extensions
    pub fn shuffle_grease(rng: &mut SmallRng, data: &[u8]) -> Vec<u8> {
        // Точно знаем что у нас приходит полная TLS-record (внутри по крайней мере 1 TLS-ClientHello)
        // Набор GREASE значений согласно RFC 8701
        const GREASE_VALUES: [u16; 16] = [
            0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA,
            0xDADA, 0xEAEA, 0xFAFA,
        ];

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

        // Record Header (5) + Handshake Header (4) + Version (2) + Client Random (32) = 43
        let mut index = 43;

        // Пропускаем Session ID
        if let Some(next) = Self::skip_u8_len(&new_data, index) {
            index = next;
        } else {
            return new_data;
        }

        // Блок Cipher Suites
        if let Some(slice) = new_data.get(index..index + 2) {
            let len = u16::from_be_bytes([slice[0], slice[1]]) as usize;
            let start = index + 2;
            let end = (start + len).min(new_data.len());

            for curr in (start..end.saturating_sub(1)).step_by(2) {
                let val = u16::from_be_bytes([new_data[curr], new_data[curr + 1]]);
                if GREASE_VALUES.contains(&val) {
                    positions.push(curr);
                }
            }
            shuffle_in_place(rng, &mut positions, &mut new_data);
            index = end;
        }

        // Пропуск Compression Methods
        if let Some(next) = Self::skip_u8_len(&new_data, index) {
            index = next;
        } else {
            return new_data;
        }

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

                if GREASE_VALUES.contains(&ext_type) {
                    positions.push(curr);
                }

                let mut ptr = body_start;
                if matches!(ext_type, 0x000a | 0x000d | 0x002d | 0x0033) && ptr + 2 <= body_end {
                    ptr += 2;
                }

                while ptr + 1 < body_end {
                    let val = u16::from_be_bytes([new_data[ptr], new_data[ptr + 1]]);
                    if GREASE_VALUES.contains(&val) {
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

    /// Затенение SNI расширением Padding (перемена их мест и увеличиение общего размера блока Padding)
    pub fn padding_encap(rng: &mut SmallRng, data: Vec<u8>) -> Vec<u8> {
        // Record Header (5) + Handshake Header (4) + Version (2) + Client Random (32) = 43
        let index = 43;

        // Пропускаем Session ID
        let Some(index) = Self::skip_u8_len(&data, index) else {
            return data;
        };
        // Пропускаем Cipher Suites
        let Some(index) = Self::skip_u16_len(&data, index) else {
            return data;
        };
        // Пропускаем Compression Methods
        let Some(index) = Self::skip_u8_len(&data, index) else {
            return data;
        };

        let ext_len_pos = index;
        if index + 2 > data.len() {
            return data;
        }

        let total_ext_len = u16::from_be_bytes([data[index], data[index + 1]]) as usize;
        let mut curr = index + 2;
        let ext_end = (curr + total_ext_len).min(data.len());

        let mut sni_slice: &[u8] = &[];
        let mut padding_slice: &[u8] = &[];
        let mut other_exts_ranges = Vec::with_capacity(16);

        // Собираем расширения
        while curr + 4 <= ext_end {
            let etype = u16::from_be_bytes([data[curr], data[curr + 1]]);
            let elen = u16::from_be_bytes([data[curr + 2], data[curr + 3]]) as usize;
            let full_len = 4 + elen;

            if curr + full_len > data.len() {
                break;
            }
            let block = &data[curr..curr + full_len];

            match etype {
                0x0000 => sni_slice = block,
                0x0015 => padding_slice = block,
                _ => other_exts_ranges.push(curr..curr + full_len),
            }
            curr += full_len;
        }

        // TODO: Добавить создание своего padding_block при отсутствии
        if sni_slice.is_empty() || padding_slice.is_empty() {
            return data;
        }

        let target_total_len = rng.gen_range_usize(512, 780);
        let current_total = data.len();
        let diff = target_total_len.saturating_sub(current_total);

        let mut final_data = Vec::with_capacity(current_total + diff);

        final_data.extend_from_slice(&data[..ext_len_pos]);
        final_data.extend_from_slice(&[0, 0]);

        let ext_start_in_final = final_data.len();

        // Собираем Padding первым (маскируя в нем SNI)
        let real_pad_payload_len = padding_slice.len().saturating_sub(4);
        let fake_pad_len = real_pad_payload_len + diff + sni_slice.len();

        final_data.extend_from_slice(&[0x00, 0x15]); // Type
        final_data.extend_from_slice(&(fake_pad_len).to_be_bytes()); // Fake Length
        final_data.extend_from_slice(&padding_slice[4..]); // Оригинальные нули
        if diff > 0 {
            final_data.resize(final_data.len() + diff, 0); // Новые нули
        }
        final_data.extend_from_slice(sni_slice); // Вставляем SNI внутрь

        // Добавляем остальные расширения
        for range in other_exts_ranges {
            final_data.extend_from_slice(&data[range]);
        }

        // Финализация длин
        let final_ext_len = final_data.len() - ext_start_in_final;
        let ext_bytes = (final_ext_len).to_be_bytes();
        final_data[ext_len_pos] = ext_bytes[0];
        final_data[ext_len_pos + 1] = ext_bytes[1];

        let total_len = final_data.len();

        // Глобальная длина Record
        #[allow(clippy::cast_possible_truncation)]
        let rec_len = (total_len.saturating_sub(5)) as u16;
        final_data[3..5].copy_from_slice(&rec_len.to_be_bytes());

        // Глобальная длина Handshake
        #[allow(clippy::cast_possible_truncation)]
        let hs_len = (total_len.saturating_sub(9)) as u32;
        let hlb = hs_len.to_be_bytes();
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
