use crate::{
    cli_args::{CliArgs, LogLevel},
    dns::DnsResolver,
    network_manager::NetworkManager,
    proxy::ProxyHandler,
};
use clap::Parser;
use colored::{Color, Colorize};
use env_logger::Builder;
use log::{LevelFilter, debug, error, info};
use std::sync::Arc;
use text_to_ascii_art::to_art;
use tokio::net::TcpListener;
use tokio::time::Duration;

mod cli_args;
mod dns;
mod http;
mod network_manager;
mod proxy;
mod tls;

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
    // Парсинг CLI-аргументов
    let args = CliArgs::parse();

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

    loop {
        tokio::select! {
          accept_result = listener.accept() => {
            match accept_result {
                Ok((stream_in, _)) => {
                    let state_clone = Arc::clone(&app_state);

                    tokio::spawn(async move {
                      if let Err(err) = ProxyHandler::handle_connection(stream_in, state_clone).await {
                          debug!("Connection closed: {err}");
                      }
                    });
                }
              Err(err) => {
                error!("Failed to accept incoming connection: {err}");
                tokio::time::sleep(Duration::from_millis(100)).await;
              }
            }
          }
          _ = tokio::signal::ctrl_c() => {
              println!("\nShutdown signal received (CTRL+C)");
              break;
          }
        }
    }

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
        .filter_level(log::LevelFilter::Info) // Для всех зависимостей/крейтов
        .filter_module("omoikane", level) // Для этого проекта
        .init();
}

/// Отрисовка баннера и текущих настроек в терминале
fn print_app_info(args: &CliArgs) {
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

    println!("\n• {:<19} : {}", "ADDR", args.addr);
    println!("• {:<20}: {}", "PORT", args.port);
    println!("• {:<20}: {:?}", "DNS MODE", args.dns_mode);
    println!("• {:<20}: {:?}", "DNS QTYPE", args.dns_qtype);
    println!("• {:<20}: {:?}", "DNS PROVIDER", args.dns_provider);
    println!("• {:<20}: {:?}", "HTTP SPLIT_MODE", args.http_split_mode);
    println!("• {:<20}: {:?}", "HTTPS SPLIT_MODE", args.https_split_mode);
    println!("• {:<20}: {:?}", "HTTPS FAKE_TTL_MODE", args.https_fake_ttl_mode);
    println!("• {:<20}: {:?}", "HTTPS FAKE_TTL_VALUE", args.https_fake_ttl_value);
    println!("• {:<20}: {:?}", "LOG LEVEL", args.log_level);
}
