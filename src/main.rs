use crate::{
    dns::DnsResolver,
    network_manager::NetworkManager,
    proxy::ProxyHandler,
    settings::Settings,
    settings::{CliArgs, LogLevel},
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

mod dns;
mod http;
mod macros;
mod network_manager;
mod proxy;
mod settings;
mod tls;

struct AppState {
    settings: Settings,
    resolver: DnsResolver,
}

pub enum ProxyTarget {
    Https { host: String },
    Http { host: String },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Загрузка конфигурации (CliArgs, YAML)
    let settings = Settings::new("config.yaml")?;

    let args = &settings.args;
    let engine = &settings.engine;
    let max_conns = engine.max_concurrent_connections;
    let session_duration = Duration::from_secs(engine.max_session_duration_secs);
    let shutdown_timeout = Duration::from_secs(engine.shutdown_grace_period_secs);

    // Инициализация Logger
    init_logger(&args.log_level);

    // Отрисовка баннера и текущих настроек в терминале
    print_app_info(args);

    // Применение сетевых настроек на уровне ОС
    NetworkManager::set_proxy_mode(true)?;

    // Инициализация DNS-resolver
    let resolver = DnsResolver::new(&args.dns_mode, &args.dns_qtype, &args.dns_provider);

    // Создание Shared-State приложения
    let app_state = Arc::new(AppState { settings, resolver });

    // Инициализация TCP-listener для обработки входящих подключений
    let addr = format!("{}:{}", &app_state.settings.args.addr, &app_state.settings.args.port);
    let listener = TcpListener::bind(addr).await?;
    info!("Listener is running on port: {}", &app_state.settings.args.port);

    // Ограничение количества одновременных соединений (чтоб не исчерпать файловые дескрипторы)
    let semaphore = Arc::new(Semaphore::new(max_conns));

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
                    session_duration,
                    ProxyHandler::handle_connection(stream_in, state_clone, task_token.clone()),
                ) => {}
            }
        });
    }

    info!("Waiting for all connections to close...");
    let max_concurrent_conn = u32::try_from(max_conns)?;
    let shutdown_wait = semaphore.acquire_many(max_concurrent_conn);
    if tokio::time::timeout(shutdown_timeout, shutdown_wait).await.is_err() {
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
        .filter_level(LevelFilter::Info) // Для зависимостей/крейтов
        .filter_module("omoikane", level)
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
