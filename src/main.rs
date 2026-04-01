use crate::{
    cli_args::{CliArgs, LogLevel},
    dns::DnsResolver,
    network_manager::NetworkManager,
    proxy::ProxyHandler,
};
use colored::{Color, Colorize};
use env_logger::Builder;
use log::{LevelFilter, error, info, trace, warn};
use std::sync::Arc;
use text_to_ascii_art::to_art;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::time::Duration;
use tokio_util::sync::CancellationToken;

mod cli_args;
mod dns;
mod http;
mod macros;
mod network_manager;
mod proxy;
mod tls;

/// Таймаут ожидания завершения активных соединений при остановке сервиса.
/// Предотвращает бесконечное ожидание процесса при закрытии.
const SHUTDOWN_GRACE_PERIOD: Duration = Duration::from_secs(10);

/// Максимальное время жизни прокси-сессий.
/// Предотвращает утечку дескрипторов и блокировку семафоров из-за зомби-соединений и зависших потоков.
const MAX_SESSION_DURATION: Duration = Duration::from_secs(300);

/// Лимит конкурентных соединений для предотвращения исчерпания файловых дескрипторов.
/// На macOS (soft limit 256) значение 200 оставляет запас для системных нужд, предотвращая ошибку EMFILE (Too many open files).
const MAX_CONCURRENT_CONNECTIONS: usize = 200;

struct AppState {
    args: CliArgs,
    resolver: DnsResolver,
}

pub enum ProxyTarget {
    Https { host: String },
    Http { host: String },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Парсинг CLI-аргументов, и сохранение в глобальное состояние
    let args = CliArgs::init();

    // Инициализация Logger
    init_logger(&args.log_level);

    // Отрисовка баннера и текущих настроек в терминал
    print_app_info(&args);

    // Применение сетевых настроек на уровне ОС
    NetworkManager::set_proxy_mode(true)?;

    // Инициализация DNS-resolver на основе CLI аргументов
    let resolver = DnsResolver::new(&args.dns_mode, &args.dns_qtype, &args.dns_provider);

    // Создание Shared-State приложения
    let app_state = Arc::new(AppState { args, resolver });

    // Инициализация TCP-listener для обработки входящих подключений
    let addr = format!("{}:{}", &app_state.args.addr, &app_state.args.port);
    let listener = TcpListener::bind(addr).await?;
    info!("Listener is running on port: {}", &app_state.args.port);

    // Ограничение количества одновременных соединений (чтоб не исчерпать файловые дескрипторы)
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));

    let cancel_token = CancellationToken::new();
    let ctrl_c_token = cancel_token.clone();

    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        println!("\nShutdown signal received (CTRL+C)\n");
        ctrl_c_token.cancel();
    });

    loop {
        let stream_in = tokio::select! {
            biased;
            () = cancel_token.cancelled() => break,
            res = listener.accept() => {
                match res {
                    Ok((stream, _)) => stream,
                    Err(err) => {
                        error!("Accept error: {err}");
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        continue;
                    }
                }
            }
        };

        let permit = tokio::select! {
            biased;
            () = cancel_token.cancelled() => break,
            p = semaphore.clone().acquire_owned() => p.expect("Semaphore closed"),
        };

        let state_clone = Arc::clone(&app_state);
        let task_token = cancel_token.clone();

        tokio::spawn(async move {
            let _permit = permit;

            tokio::select! {
                biased;
                () = task_token.cancelled() => {
                    trace!("Session closing due to shutdown...");
                }
                _ = tokio::time::timeout(
                    MAX_SESSION_DURATION,
                    ProxyHandler::handle_connection(stream_in, state_clone, task_token.clone()),
                ) => {}
            }
        });
    }

    info!("Waiting for all connections to close...");
    let max_concurrent_conn = u32::try_from(MAX_CONCURRENT_CONNECTIONS)?;
    let shutdown_wait = semaphore.acquire_many(max_concurrent_conn);
    if tokio::time::timeout(SHUTDOWN_GRACE_PERIOD, shutdown_wait)
        .await
        .is_err()
    {
        warn!("Shutdown timed out, forcing exit...");
    }
    info!("All connections closed. Shutdown complete.");

    // Откат сетевых настроек ОС в исходное состояние
    NetworkManager::set_proxy_mode(false)?;

    Ok(())
}

/// Настройка Log-Level и инициализации Logger
fn init_logger(log_level: &LogLevel) {
    let level = match log_level {
        LogLevel::Off => LevelFilter::Off,
        LogLevel::Error => LevelFilter::Error,
        LogLevel::Warn => LevelFilter::Warn,
        LogLevel::Info => LevelFilter::Info,
        LogLevel::Debug => LevelFilter::Debug,
        LogLevel::Trace => LevelFilter::Trace,
    };
    Builder::new()
        .filter_level(LevelFilter::Info) // Для всех зависимостей/крейтов
        .filter_module("omoikane", level) // Для этого проекта
        .init();
}

/// Отрисовка баннера и текущих настроек в терминале
fn print_app_info(args: &CliArgs) {
    if args.silent {
        return;
    }

    if let Ok(banner) = to_art("OMOIKANE".to_string(), "standard", 0, 0, 0) {
        let colors = [
            Color::BrightCyan,
            Color::Cyan,
            Color::Blue,
            Color::BrightBlue,
            Color::Magenta,
            Color::BrightMagenta,
        ];

        for (i, line) in banner.lines().enumerate() {
            let color = colors[i % colors.len()];
            println!("{}", line.color(color).bold());
        }
    }

    println!("\n• {:<22} : {}", "ADDR", args.addr);
    println!("• {:<22} : {}", "PORT", args.port);
    println!("• {:<22} : {:?}", "DNS MODE", args.dns_mode);
    println!("• {:<22} : {:?}", "DNS QTYPE", args.dns_qtype);
    println!("• {:<22} : {:?}", "DNS PROVIDER", args.dns_provider);
    println!("• {:<22} : {:?}", "HTTP SPLIT_MODE", args.http_split_mode);
    println!("• {:<22} : {:?}", "HTTPS SPLIT_MODE", args.https_split_mode);
    println!("• {:<22} : {:?}", "HTTPS FAKE_TTL_MODE", args.https_fake_ttl_mode);
    println!("• {:<22} : {:?}", "HTTPS FAKE_TTL_VALUE", args.https_fake_ttl_value);
    println!("• {:<22} : {:?}", "LOG LEVEL", args.log_level);
}
