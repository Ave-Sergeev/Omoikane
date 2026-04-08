use std::time::{SystemTime, UNIX_EPOCH};

// Можно конечно использовать крейты `rand` или `fastrand`, но для минимизации latency попробуем реализовать все сами
// Автор осознанно избегает дженериков и num-traits для максимального инлайнинга
pub struct SmallRng {
    state: u64,
}

impl SmallRng {
    /// Инициализизация RNG (seed = XOR времени (нс) и адреса стека для энтропии)
    pub fn new() -> Self {
        #[allow(clippy::cast_possible_truncation)]
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        let ptr_noise = &raw const time as u64;
        let seed = time ^ ptr_noise;

        let mut rng = Self {
            state: if seed == 0 { 0xACE1_2345_6789_ABCD } else { seed },
        };

        for _ in 0..5 {
            rng.next();
        }

        rng
    }

    /// Перемешивание элементов (Fisher-Yates shuffle)
    pub fn shuffle<T>(&mut self, slice: &mut [T]) {
        let len = slice.len();
        if len < 2 {
            return;
        }

        for i in (1..len).rev() {
            let random_index = self.gen_range_usize(0, i);
            slice.swap(i, random_index);
        }
    }

    /// Генерация bool с заданной вероятностью (от 0.0 до 1.0)
    #[inline]
    pub fn gen_bool(&mut self, probability: f64) -> bool {
        // 2^53 — предел точности мантиссы f64
        const MAX_SAFE_INT: f64 = 9_007_199_254_740_992.0;

        if probability <= 0.0 {
            return false;
        }
        if probability >= 1.0 {
            return true;
        }

        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let threshold = (probability * (MAX_SAFE_INT)) as u64;
        (self.next() >> 11) < threshold
    }

    /// Генерация u64 в диапазоне [min, max] включительно
    #[inline]
    #[allow(clippy::cast_possible_truncation)]
    pub fn gen_range_u64(&mut self, min: u64, max: u64) -> u64 {
        if min >= max {
            return min;
        }

        let range = max.wrapping_sub(min).wrapping_add(1);

        // Метод Lemire
        let product = u128::from(self.next()).wrapping_mul(u128::from(range));
        let offset = (product >> 64) as u64;

        min.wrapping_add(offset)
    }

    /// Генерация usize в диапазоне [min, max] включительно
    #[inline]
    #[allow(clippy::cast_possible_truncation)]
    pub fn gen_range_usize(&mut self, min: usize, max: usize) -> usize {
        if min >= max {
            return min;
        }
        let range = (max.wrapping_sub(min).wrapping_add(1)) as u64;

        // Метод Lemire
        let product = u128::from(self.next()).wrapping_mul(u128::from(range));
        let offset = (product >> 64) as usize;

        min.wrapping_add(offset)
    }

    /// Алгоритм Xorshift64
    #[inline(always)]
    #[allow(clippy::inline_always)]
    fn next(&mut self) -> u64 {
        let mut curr_state = self.state;
        curr_state ^= curr_state << 13;
        curr_state ^= curr_state >> 7;
        curr_state ^= curr_state << 17;
        self.state = curr_state;
        curr_state
    }
}
