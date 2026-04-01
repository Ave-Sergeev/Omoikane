#[macro_export]
macro_rules! silent {
    ($($arg:tt)*) => {{
        if !$crate::cli_args::CliArgs::is_silent() {
            println!($($arg)*);
        }
    }};
}
