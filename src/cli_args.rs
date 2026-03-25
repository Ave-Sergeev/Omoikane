use clap::{Parser, ValueEnum};

#[derive(ValueEnum, Clone, Debug)]
#[value(rename_all = "lowercase")]
pub enum DnsMode {
    System,
    DoH,
}

#[derive(ValueEnum, Clone, Debug)]
#[value(rename_all = "lowercase")]
pub enum DnsProvider {
    Google,
    Quad9,
    Cloudflare,
}

#[derive(ValueEnum, Clone, Debug)]
#[value(rename_all = "lowercase")]
pub enum DnsQType {
    Ipv4,
    Ipv6,
    All,
}

#[derive(Clone, Parser, Debug)]
#[command(author, version, about = "DPI bypass")]
pub struct CliArgs {
    /// Порт для прослушивания.
    #[arg(short = 'p', long = "port", default_value = "8080")]
    pub port: u16,

    /// Режим работы `DNS`: "system" (обычный) или "doh" (DNS-over-HTTPS).
    #[arg(long = "dns-mode", value_enum, default_value = "system")]
    pub dns_mode: DnsMode,

    /// Провайдер `DoH`: "cloudflare", "google", "quad9".
    #[arg(long = "dns-provider", default_value = "cloudflare")]
    pub dns_provider: DnsProvider,

    /// Тип запрашиваемых записей: "ipv4", "ipv6", "all".
    #[arg(long = "dns-qtype", default_value = "all")]
    pub dns_qtype: DnsQType,
    //
    // /// Метод фрагментации: split, disorder, fake
    // #[arg(short = 'm', long = "method", default_value = "split")]
    // pub method: String,

    // /// Размер фрагментации в байтах (для split метода)
    // #[arg(short = 's', long = "fragment_size", default_value = "32")]
    // pub fragment_size: usize,

    // /// Добавлять фальшивый SNI
    // #[arg(short = 'f', long = "fake_sni", default_value = "false")]
    // pub fake_sni: bool,

    // /// Фальшивый домен для SNI
    // #[arg(short = 'd', long = "fake_domain", default_value = "www.github.com")]
    // pub fake_domain: String,

    // /// Блокировать QUIC
    // #[arg(short = 'q', long = "block_quic", default_value = "true")]
    // pub block_quic: bool,
}
