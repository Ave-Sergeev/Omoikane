#[macro_export]
macro_rules! silent {
    ($($arg:tt)*) => {{
        if !$crate::settings::Settings::is_silent() {
            println!($($arg)*);
        }
    }};
}
