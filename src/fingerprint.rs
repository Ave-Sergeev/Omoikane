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

        let mut new_data = data.to_vec();
        // Record Header (5) + Handshake Header (4) + Version (2) + Client Random (32) = 43
        let mut index = 43;

        // Пропускаем Session ID
        let Some(next) = Self::skip_u8_len(&new_data, index) else {
            return new_data;
        };
        index = next;

        let mut cipher_pos = Vec::new();
        let mut cipher_val = Vec::new();
        let mut ext_type_pos = Vec::new();
        let mut ext_type_vals = Vec::new();
        let mut ext_inner_pos = Vec::new();
        let mut ext_inner_vals = Vec::new();

        // Блок Cipher Suites
        if let Some(slice) = new_data.get(index..index + 2) {
            let ciphers_len = u16::from_be_bytes([slice[0], slice[1]]) as usize;
            let ciphers_start = index + 2;
            let ciphers_end = ciphers_start + ciphers_len;

            let mut curr = ciphers_start;
            while curr + 1 < ciphers_end && curr + 1 < new_data.len() {
                let val = u16::from_be_bytes([new_data[curr], new_data[curr + 1]]);
                if GREASE_VALUES.contains(&val) {
                    cipher_pos.push(curr);
                    cipher_val.push(val);
                }
                curr += 2;
            }
            index = ciphers_end;
        }

        // Пропуск Compression Methods
        let Some(next) = Self::skip_u8_len(&new_data, index) else {
            return new_data;
        };
        index = next;

        // Блок Extensions
        if let Some(slice) = new_data.get(index..index + 2) {
            let ext_total_len = u16::from_be_bytes([slice[0], slice[1]]) as usize;
            let mut curr = index + 2;
            let ext_end = curr + ext_total_len;

            while curr + 3 < ext_end && curr + 3 < new_data.len() {
                let ext_type = u16::from_be_bytes([new_data[curr], new_data[curr + 1]]);
                let ext_len = u16::from_be_bytes([new_data[curr + 2], new_data[curr + 3]]) as usize;

                // Проверяем тип расширения (был ли это GREASE-extension)
                if GREASE_VALUES.contains(&ext_type) {
                    ext_type_pos.push(curr);
                    ext_type_vals.push(ext_type);
                }

                // Проверяем содержимое расширения
                // Нам нужно убедиться, что внутри не просто мусор, а список u16
                let body_start = curr + 4;
                let body_end = body_start + ext_len;

                // Важно: проверяем, что мы не выходим за границы данных
                if body_end <= new_data.len() {
                    let mut body_ptr = body_start;

                    // Пропускаем 2 байта длины списка, если это расширение со списком значений
                    // 0x000a (groups), 0x000d (sig_algos), 0x002d (psk_kex_modes) и т.д.
                    if matches!(ext_type, 0x000a | 0x000d | 0x002d | 0x0033) {
                        body_ptr += 2;
                    }

                    while body_ptr + 1 < body_end {
                        let val = u16::from_be_bytes([new_data[body_ptr], new_data[body_ptr + 1]]);
                        if GREASE_VALUES.contains(&val) {
                            ext_inner_pos.push(body_ptr);
                            ext_inner_vals.push(val);
                        }
                        body_ptr += 2;
                    }
                }

                curr = body_end;
            }
        }

        let apply_shuffle = |rng: &mut SmallRng, pos: Vec<usize>, mut vals: Vec<u16>, data: &mut Vec<u8>| {
            if !vals.is_empty() {
                rng.shuffle(&mut vals);
                for (idx, p) in pos.into_iter().enumerate() {
                    data[p..p + 2].copy_from_slice(&vals[idx].to_be_bytes());
                }
            }
        };

        // Перемешиваем и записываем обратно для Cipher Suites и Extensions
        apply_shuffle(rng, cipher_pos, cipher_val, &mut new_data);
        apply_shuffle(rng, ext_type_pos, ext_type_vals, &mut new_data);
        apply_shuffle(rng, ext_inner_pos, ext_inner_vals, &mut new_data);

        new_data
    }

    /// Затенение SNI расширением Padding (перемена их мест и увеличиение общего размера блока Padding)
    pub fn padding_encap(rng: &mut SmallRng, data: Vec<u8>) -> Vec<u8> {
        let new_data = data;
        // Record Header (5) + Handshake Header (4) + Version (2) + Client Random (32) = 43
        let index = 43;

        // Пропускаем Session ID
        let Some(index) = Self::skip_u8_len(&new_data, index) else {
            return new_data;
        };
        // Пропускаем Cipher Suites
        let Some(index) = Self::skip_u16_len(&new_data, index) else {
            return new_data;
        };
        // Пропускаем Compression Methods
        let Some(index) = Self::skip_u8_len(&new_data, index) else {
            return new_data;
        };

        let ext_len_pos = index;
        if index + 2 > new_data.len() {
            return new_data;
        }

        let total_ext_len = u16::from_be_bytes([new_data[index], new_data[index + 1]]) as usize;
        let mut curr = index + 2;
        let ext_end = curr + total_ext_len;

        let mut sni_block = Vec::new();
        let mut padding_block = Vec::new();
        let mut other_exts = Vec::new();

        // Собираем расширения по отдельности
        while curr + 4 <= ext_end && curr + 4 <= new_data.len() {
            let etype = u16::from_be_bytes([new_data[curr], new_data[curr + 1]]);
            let elen = u16::from_be_bytes([new_data[curr + 2], new_data[curr + 3]]) as usize;
            let full_len = 4 + elen;

            if curr + full_len > new_data.len() {
                break;
            }
            let block = &new_data[curr..curr + full_len];

            match etype {
                0x0000 => sni_block = block.to_vec(),
                0x0015 => padding_block = block.to_vec(),
                _ => other_exts.extend_from_slice(block),
            }
            curr += full_len;
        }

        // TODO: Добавить создание своего padding_block при отсутствии
        if sni_block.is_empty() || padding_block.is_empty() {
            return new_data;
        }

        // Выбираем целевой размер всего пакета (например, 512-780 байт)
        let target_total_len = rng.gen_range_usize(512, 780);
        let current_total = new_data.len();

        if target_total_len > current_total {
            let diff = target_total_len - current_total;
            padding_block.resize(padding_block.len() + diff, 0); // Физически увеличиваем блок нулей в паддинге
        }

        // Формируем новый блок расширений
        let mut new_extensions = Vec::new();

        // Расчет фейк длины Padding:
        // Она должна покрыть свои данные + весь блок SNI (4 байта заголовка SNI + его payload)
        let real_pad_payload_len = padding_block.len().saturating_sub(4);
        let fake_pad_len = real_pad_payload_len + sni_block.len();

        // Добавляем Padding первым
        new_extensions.extend_from_slice(&[0x00, 0x15]); // Type
        new_extensions.extend_from_slice(&(fake_pad_len).to_be_bytes()); // Fake Length

        // Тело Padding
        new_extensions.extend_from_slice(&padding_block[4..]);

        // Тело SNI (внутри fake_pad_len)
        new_extensions.extend_from_slice(&sni_block);

        // Добавляем всё остальное
        new_extensions.extend_from_slice(&other_exts);

        // Сборка финального пакета
        let mut final_data = new_data[..ext_len_pos].to_vec();

        // Обновляем общую длину Extensions (2 байта)
        final_data.extend_from_slice(&(new_extensions.len()).to_be_bytes());
        final_data.extend_from_slice(&new_extensions);

        // Пересчет глобальных длин TLS
        let total_len = final_data.len();
        if total_len < 9 {
            return final_data;
        }

        // Record Length (смещение 3, 2 байта) = Total - 5 байт заголовка Record
        let rec_len = total_len.saturating_sub(5);
        let rb = rec_len.to_be_bytes();
        final_data[3] = rb[0];
        final_data[4] = rb[1];

        // Handshake Length (смещение 6, 3 байта) = Total - 5 (Record) - 4 (Handshake Head)
        let hs_len = total_len.saturating_sub(5).saturating_sub(4);
        let hb = hs_len.to_be_bytes();
        final_data[6] = hb[1];
        final_data[7] = hb[2];
        final_data[8] = hb[3];

        final_data
    }

    fn skip_u8_len(data: &[u8], index: usize) -> Option<usize> {
        let sid_len = *data.get(index)? as usize;
        Some(index + 1 + sid_len)
    }

    fn skip_u16_len(data: &[u8], index: usize) -> Option<usize> {
        let slice = data.get(index..index + 2)?;
        let ciphers_len = u16::from_be_bytes([slice[0], slice[1]]) as usize;
        Some(index + 2 + ciphers_len)
    }
}
