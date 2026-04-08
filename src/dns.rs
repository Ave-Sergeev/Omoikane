use crate::settings::{DnsMode, DnsProvider, DnsQType};
use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
use hickory_resolver::error::ResolveError;
use hickory_resolver::{
    AsyncResolver, TokioAsyncResolver,
    config::{LookupIpStrategy, ResolverConfig, ResolverOpts},
    name_server::TokioConnectionProvider,
};
use std::io;
use std::net::SocketAddr;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::pin;
use tokio::time::{Duration, Instant, sleep};

#[derive(Error, Debug)]
pub enum DnsError {
    #[error("DNS resolution error: {0}")]
    Resolve(#[from] ResolveError),

    #[error("No addresses found for host: {0}")]
    NoAddresses(String),

    #[error("Failed to connect to any address. Last error: {0}")]
    ConnectionFailed(String),

    #[error("IO error: {0}")]
    Io(#[from] io::Error),
}

#[derive(Clone)]
pub struct DnsResolver {
    resolver: AsyncResolver<TokioConnectionProvider>,
}

impl DnsResolver {
    /// Создание нового экземпляра резолвера
    pub fn new(mode: &DnsMode, qtype: &DnsQType, provider: &DnsProvider) -> Self {
        // Конфигурируем резолвер и устанавливаем стратегию разрешения IP-адресов
        let mut opts = ResolverOpts::default();
        opts.ip_strategy = match qtype {
            DnsQType::Ipv4 => LookupIpStrategy::Ipv4Only,
            DnsQType::Ipv6 => LookupIpStrategy::Ipv6Only,
            DnsQType::All => LookupIpStrategy::Ipv4thenIpv6,
        };

        // Устанавливаем конфигурацию DNS (на основе режима и провайдера)
        let config = match (mode, provider) {
            (DnsMode::System, _) => ResolverConfig::default(),
            (DnsMode::DoT, DnsProvider::Quad9) => ResolverConfig::quad9_tls(),
            (DnsMode::DoH, DnsProvider::Quad9) => ResolverConfig::quad9_https(),
            (DnsMode::DoT, DnsProvider::Google) => ResolverConfig::google_tls(),
            (DnsMode::DoH, DnsProvider::Google) => ResolverConfig::google_https(),
            (DnsMode::DoT, DnsProvider::Cloudflare) => ResolverConfig::cloudflare_tls(),
            (DnsMode::DoH, DnsProvider::Cloudflare) => ResolverConfig::cloudflare_https(),
        };

        // Инициализируем резолвер
        let resolver = TokioAsyncResolver::tokio(config, opts);

        Self { resolver }
    }

    /// Выполнение DNS-resolve доменного имени (host) в список сетевых адресов Socket-Addr
    pub async fn resolve_to_socket(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, DnsError> {
        let response = self.resolver.lookup_ip(host).await?;

        let addrs: Vec<SocketAddr> = response.iter().map(|ip| SocketAddr::new(ip, port)).collect();

        if addrs.is_empty() {
            return Err(DnsError::NoAddresses(host.to_string()));
        }

        Ok(addrs)
    }

    /// Параллельное открытие соединений (Happy Eyeballs) для выбора рабочего маршрута
    pub async fn race_connect_to_target(&self, host: &str, port: u16) -> Result<TcpStream, DnsError> {
        let socket_addrs = self.resolve_to_socket(host, port).await?;

        // Задержка (в мс) перед попыткой подключения к следующему IP-адресу
        let delay_duration = Duration::from_millis(250);

        let mut attempts = FuturesUnordered::new();
        let mut addrs_iter = socket_addrs.into_iter().peekable();
        let mut last_err = String::from("No addresses available");

        let sleep_fut = sleep(Duration::ZERO);
        pin!(sleep_fut);

        loop {
            if (attempts.is_empty() || sleep_fut.is_elapsed()) && addrs_iter.peek().is_some() {
                if let Some(addr) = addrs_iter.next() {
                    attempts.push(async move { (TcpStream::connect(addr).await, addr) });
                }
                sleep_fut.as_mut().reset(Instant::now() + delay_duration);
            }

            tokio::select! {
                () = &mut sleep_fut, if addrs_iter.peek().is_some() => {}

                result = attempts.next() => {
                    match result {
                        Some((Ok(stream), _addr)) => {
                            let _ = stream.set_nodelay(true);
                            return Ok(stream);
                        }
                        Some((Err(err), addr)) => {
                            last_err = format!("Failed to connect to {addr}: {err}");
                            if addrs_iter.peek().is_none() && attempts.is_empty() {
                                break;
                            }
                        }
                        None => break,
                    }
                }
            }
        }

        Err(DnsError::ConnectionFailed(last_err))
    }
}
