use crate::{
    cli_args::{CliArgs, DnsMode, DnsProvider, DnsQType},
    network_manager::NetworkManager,
};
use clap::Parser;
use env_logger::Builder;
use hickory_resolver::{
    AsyncResolver, TokioAsyncResolver,
    config::{LookupIpStrategy, ResolverConfig, ResolverOpts},
    name_server::TokioConnectionProvider,
};
use log::{LevelFilter, debug, error, info, warn};
use std::io::Write;
use std::{
    error::Error,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tls_parser::{TlsExtension, TlsMessage, TlsMessageHandshake, parse_tls_plaintext};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

mod cli_args;
mod network_manager;

struct App {
    args: CliArgs,
    resolver: AsyncResolver<TokioConnectionProvider>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Парсим CLI-аргументы
    let args = CliArgs::parse();

    // Настройка логгера
    Builder::new()
        .filter_level(LevelFilter::Info)
        .format(|buf, record| writeln!(buf, "{}", record.args()))
        .init();

    // Конфигурируем резолвер
    let mut opts = ResolverOpts::default();
    // Устанавливаем стратегию разрешения IP-адресов
    opts.ip_strategy = match args.dns_qtype {
        DnsQType::Ipv4 => LookupIpStrategy::Ipv4Only,
        DnsQType::Ipv6 => LookupIpStrategy::Ipv6Only,
        DnsQType::All => LookupIpStrategy::Ipv4AndIpv6,
    };
    // Устанавливаем конфигурацию DNS (режим работы и провайдер)
    let config = match args.dns_mode {
        DnsMode::System => ResolverConfig::default(),
        DnsMode::DoH => match args.dns_provider {
            DnsProvider::Quad9 => ResolverConfig::quad9_https(),
            DnsProvider::Google => ResolverConfig::google_https(),
            DnsProvider::Cloudflare => ResolverConfig::cloudflare_https(),
        },
    };

    // Инициализируем резолвер
    let resolver = TokioAsyncResolver::tokio(config, opts);

    // Отрисовка текущих настроек в терминалу
    info!("\n--- [ SETTINGS ] ---");
    info!("PORT:           {}", args.port);
    info!("DNS MODE:       {:?}", args.dns_mode);
    info!("DNS QTYPE:      {:?}", args.dns_qtype);
    info!("DNS PROVIDER:   {:?}", args.dns_provider);

    // Применение сетевых настроек на уровне ОС
    NetworkManager::set_proxy(true)?;

    // Создаем `Shared State` приложения
    let app_state = Arc::new(App { args, resolver });

    // Инициализация TCP-listener для обработки входящих подключений
    let addr = format!("0.0.0.0:{}", app_state.args.port);
    let listener = TcpListener::bind(addr).await?;
    info!(
        "\n[Status] : TcpListener is running on port: {}\n[Action] : Press CTRL+C to stop",
        app_state.args.port
    );

    loop {
        tokio::select! {
          accept_result = listener.accept() => {
            match accept_result {
                Ok((mut stream_in, _)) => {
                    stream_in.set_nodelay(true).ok();
                    let state_clone = Arc::clone(&app_state);

                    tokio::spawn(async move {
                        let mut buffer = [0u8; 2048];
                        let n = match stream_in.read(&mut buffer).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };

                        // Ищем разделитель заголовка и тела (двойной перенос строки)
                        let header_end_pos = buffer[..n]
                            .windows(4)
                            .position(|window| window == b"\r\n\r\n")
                            .map(|pos| pos + 4);

                        let Some(pos) = header_end_pos else {
                          warn!("HTTP header end not found");
                          return;
                        };

                        // Достаем целевой адрес (host)
                        let Some(host) = extract_host(&buffer[..pos]) else {
                            warn!("Failed to extract SNI/Host from the first {pos} bytes");
                            return;
                        };

                        // Резолвим host в IP через DoH
                        let ip_address = match resolve_host(&state_clone.resolver, host.as_str()).await {
                            Ok(ip) => ip,
                            Err(err) => {
                                error!("Failed to resolve host '{host}': | Error: {err}");
                                return;
                            }
                        };
                        let socket_addr = SocketAddr::new(ip_address, 443);

                        // Устанавливаем исходящее соединение с целевым сервером (Stream №2)
                        let mut stream_out = match TcpStream::connect(socket_addr).await {
                            Ok(s) => {
                              s.set_nodelay(true).ok();
                              s
                            },
                            Err(err) => {
                              error!("Failed to connect to host: {host} | Error: {err}");
                              return
                            }
                        };

                        let ack = "HTTP/1.1 200 Connection Established\r\n\r\n";
                        if let Err(err) = stream_in.write_all(ack.as_bytes()).await {
                            error!("Error sending ACK to client: {err}");
                            return;
                        }

                        // ВСЁ ОСТАЛЬНОЕ (начало TLS Handshake, если оно успело прилететь)
                        let extra_data = &buffer[pos..n];
                        if !extra_data.is_empty() {
                            if let Err(err) = stream_out.write_all(extra_data).await {
                                error!("Error forwarding remaining TLS data: {err}");
                                return;
                            }
                            debug!("Forwarded {} bytes of extra TLS data to server", extra_data.len());
                        }

                        let _ = tokio::io::copy_bidirectional(&mut stream_in, &mut stream_out).await;
                    });
                }
              Err(err) => error!("Accept error: {err}"),
            }
          }
          _ = tokio::signal::ctrl_c() => {
              info!("\nInterrupted by Ctrl+C...");
              break;
          }
        }
    }

    // Откат сетевых настроек ОС в исходное состояние
    NetworkManager::set_proxy(false)?;

    Ok(())
}

fn extract_host(data: &[u8]) -> Option<String> {
    // Пробуем HTTPS (SNI)
    if let Ok((_, record)) = parse_tls_plaintext(data) {
        for msg in record.msg {
            if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(contents)) = msg
                && let Some(extensions_raw) = contents.ext
                && let Ok((_, extensions)) = tls_parser::parse_tls_extensions(extensions_raw)
            {
                for ext in extensions {
                    if let TlsExtension::SNI(sni_list) = ext
                        && let Some((_, name)) = sni_list.into_iter().next()
                    {
                        return std::str::from_utf8(name)
                            .ok()
                            .map(std::string::ToString::to_string);
                    }
                }
            }
        }
    }

    // Пробуем HTTP (Host)
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut req = httparse::Request::new(&mut headers);

    if let Ok(res) = req.parse(data)
        && (res.is_complete() || res.is_partial())
    {
        return req
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("Host"))
            .and_then(|h| std::str::from_utf8(h.value).ok())
            .map(|s| s.split(':').next().unwrap_or(s).to_string());
    }

    None
}

async fn resolve_host(resolver: &TokioAsyncResolver, host: &str) -> Result<IpAddr, Box<dyn Error>> {
    let response = resolver.lookup_ip(host).await?;
    response
        .iter()
        .next()
        .ok_or_else(|| format!("Адрес для {host} не найден").into())
}
