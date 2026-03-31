use clap::{Parser, ValueEnum};

#[derive(ValueEnum, Clone, Debug)]
#[value(rename_all = "lowercase")]
pub enum DnsMode {
    DoT,    // Использовать протокол DoT (DNS over TLS)
    DoH,    // Использовать протокол DoH (DNS over HTTPS)
    System, // Использовать системный резолвер (Google DNS)
}

#[derive(ValueEnum, Clone, Debug)]
#[value(rename_all = "lowercase")]
pub enum DnsProvider {
    Google,     // Использовать Google DNS
    Quad9,      // Использовать Quad9 DNS
    Cloudflare, // Использовать Cloudflare DNS
}

#[derive(ValueEnum, Clone, Debug)]
#[value(rename_all = "lowercase")]
pub enum DnsQType {
    Ipv4, // Запрашивать только записи типа A (IPv4)
    Ipv6, // Запрашивать только аписи типа AAAA (IPv6)
    All,  // Запрашивать A и AAAA записи
}

#[derive(ValueEnum, Clone, Debug)]
#[value(rename_all = "lowercase")]
pub enum SplitMode {
    None,     // Не использовать фрагментацию
    Fragment, // Разделять на фрагменты
}

#[derive(ValueEnum, Clone, Debug)]
#[value(rename_all = "lowercase")]
pub enum TtlStrategy {
    None, // Использовать стандартный системный TTL (без изменений)
    Auto, // Автоматический подбор TTL для фейковых пакетов
}

#[derive(ValueEnum, Clone, Debug)]
#[value(rename_all = "lowercase")]
pub enum LogLevel {
    Off,   // Полностью отключить логирование
    Error, // Показывать критические сбои
    Warn,  // Показывать некритичные проблемы
    Info,  // Показывать основные события системы
    Debug, // Показывать детали реализации
    Trace, // Показывать максимальную детализацию
}

#[derive(Clone, Parser, Debug)]
#[command(author, version, about = "Omoikane CLI")]
pub struct CliArgs {
    /// IP-адрес для прослушивания.
    #[arg(short = 'a', long = "addr", default_value = "127.0.0.1")]
    pub addr: String,

    /// Порт для приема входящих соединений.
    #[arg(short = 'p', long = "port", default_value = "8080")]
    pub port: u16,

    /// Уровень детализации логов: "off", "error", "warn", "info", "debug", "trace".
    #[arg(long = "log-level", default_value = "info")]
    pub log_level: LogLevel,

    /// Режим работы `DNS`: "system", "doh" (DNS-over-HTTPS), "dot" (DNS-over-TLS).
    #[arg(value_enum, long = "dns-mode", default_value = "system")]
    pub dns_mode: DnsMode,

    /// Провайдер `DoH`/`DoT`: "google", "cloudflare", "quad9".
    #[arg(value_enum, long = "dns-provider", default_value = "google")]
    pub dns_provider: DnsProvider,

    /// Тип запрашиваемых записей: "ipv4", "ipv6", "all".
    #[arg(value_enum, long = "dns-qtype", default_value = "ipv4")]
    pub dns_qtype: DnsQType,

    /// Способ фрагментации `HTTP-request`: "none", "fragment".
    #[arg(value_enum, long = "http-split-mode", default_value = "none")]
    pub http_split_mode: SplitMode,

    /// Способ фрагментации `TLS ClientHello`: "none", "fragment".
    #[arg(value_enum, long = "https-split-mode", default_value = "none")]
    pub https_split_mode: SplitMode,

    /// Стратегия работы с `TTL` для фейк пакетов: "none", "auto".
    #[arg(value_enum, long = "https-fake-ttl", default_value = "none")]
    pub https_fake_ttl: TtlStrategy,
}
