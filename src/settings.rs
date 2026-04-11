use clap::{Parser, ValueEnum};
use config::Config;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use thiserror::Error;

static ARGS: OnceLock<CliArgs> = OnceLock::new();

#[derive(Error, Debug)]
pub enum SettingsError {
    #[error("Config file not found: {0}")]
    FileNotFound(String),

    #[error("Failed to build config: {0}")]
    BuildError(#[from] config::ConfigError),
}

#[derive(ValueEnum, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[clap(rename_all = "lowercase")]
pub enum DnsMode {
    DoT,    // Использовать протокол DoT (DNS over TLS)
    DoH,    // Использовать протокол DoH (DNS over HTTPS)
    System, // Использовать системный резолвер (Google DNS)
}

#[derive(ValueEnum, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[clap(rename_all = "lowercase")]
pub enum DnsProvider {
    Google,     // Использовать Google DNS
    Quad9,      // Использовать Quad9 DNS
    Cloudflare, // Использовать Cloudflare DNS
}

#[derive(ValueEnum, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[clap(rename_all = "lowercase")]
pub enum DnsQType {
    Ipv4, // Запрашивать только записи типа A (IPv4)
    Ipv6, // Запрашивать только аписи типа AAAA (IPv6)
    All,  // Запрашивать A и AAAA записи
}

#[derive(ValueEnum, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[clap(rename_all = "lowercase")]
pub enum SplitMode {
    None,     // Не использовать фрагментацию
    Fragment, // Разделять на фрагменты
}

#[derive(ValueEnum, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[clap(rename_all = "lowercase")]
pub enum TtlStrategy {
    None,   // Использовать стандартный системный TTL (без изменений)
    Custom, // Использовать конкретное значение TTL
}

#[derive(ValueEnum, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[clap(rename_all = "lowercase")]
pub enum LogLevel {
    Off,   // Полностью отключить логирование
    Error, // Показывать критические сбои
    Warn,  // Показывать некритичные проблемы
    Info,  // Показывать основные события системы
    Debug, // Показывать детали реализации
    Trace, // Показывать максимальную детализацию
}

#[derive(Clone, Parser, Debug, Serialize, Deserialize)]
pub struct RawCliArgs {
    /// Путь к файлу конфигурации (YAML).
    #[arg(short = 'c', long = "config", help_heading = "APP")]
    #[serde(skip)]
    pub config_path: Option<std::path::PathBuf>,

    /// IP-адрес для прослушивания.
    #[arg(short = 'a', long = "addr", help_heading = "APP")]
    #[serde(rename = "args.addr", skip_serializing_if = "Option::is_none")]
    pub addr: Option<String>,

    /// Порт для приема входящих соединений.
    #[arg(short = 'p', long = "port", help_heading = "APP")]
    #[serde(rename = "args.port", skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,

    /// Режим "тишины": не выводить баннер и информационные сообщения в терминал.
    #[arg(short = 's', long = "silent", num_args = 0..=1, default_missing_value = "true", value_parser = clap::value_parser!(bool), help_heading = "APP")]
    #[serde(rename = "args.silent", skip_serializing_if = "Option::is_none")]
    pub silent: Option<bool>,

    /// Уровень детализации логов: "off", "error", "warn", "info", "debug", "trace".
    #[arg(short = 'l', long = "log-level", help_heading = "APP")]
    #[serde(rename = "args.log_level", skip_serializing_if = "Option::is_none")]
    pub log_level: Option<LogLevel>,

    /// Режим работы `DNS`: "system", "doh" (DNS-over-HTTPS), "dot" (DNS-over-TLS).
    #[arg(value_enum, long = "dns-mode", help_heading = "DNS")]
    #[serde(rename = "args.dns_mode", skip_serializing_if = "Option::is_none")]
    pub dns_mode: Option<DnsMode>,

    /// Провайдер `DoH`/`DoT`: "google", "cloudflare", "quad9".
    #[arg(value_enum, long = "dns-provider", help_heading = "DNS")]
    #[serde(rename = "args.dns_provider", skip_serializing_if = "Option::is_none")]
    pub dns_provider: Option<DnsProvider>,

    /// Тип запрашиваемых записей: "ipv4", "ipv6", "all".
    #[arg(value_enum, long = "dns-qtype", help_heading = "DNS")]
    #[serde(rename = "args.dns_qtype", skip_serializing_if = "Option::is_none")]
    pub dns_qtype: Option<DnsQType>,

    /// Способ фрагментации `HTTP-request`: "none", "fragment".
    #[arg(value_enum, long = "http-split-mode", help_heading = "HTTP")]
    #[serde(rename = "args.http_split_mode", skip_serializing_if = "Option::is_none")]
    pub http_split_mode: Option<SplitMode>,

    /// Способ фрагментации `TLS-ClientHello`: "none", "fragment".
    #[arg(value_enum, long = "https-split-mode", help_heading = "HTTPS")]
    #[serde(rename = "args.https_split_mode", skip_serializing_if = "Option::is_none")]
    pub https_split_mode: Option<SplitMode>,

    /// Стратегия работы с `TTL` для фейк пакетов: "none", "custom".
    #[arg(value_enum, long = "https-fake-ttl-mode", help_heading = "HTTPS")]
    #[serde(rename = "args.https_fake_ttl_mode", skip_serializing_if = "Option::is_none")]
    pub https_fake_ttl_mode: Option<TtlStrategy>,

    /// Конкретное значение `TTL` (для стратегии "custom").
    #[arg(long = "https-fake-ttl-value", value_parser = clap::value_parser!(u8).range(1..=255), help_heading = "HTTPS")]
    #[serde(rename = "args.https_fake_ttl_value", skip_serializing_if = "Option::is_none")]
    pub https_fake_ttl_value: Option<u8>,

    /// Динамическое изменение отпечатка (fingerprint) путем повышения энтропии TLS-рукопожатия (GREASE & Padding): "true", "false".
    #[arg(long = "https-greased-padding", help_heading = "HTTPS")]
    #[serde(rename = "args.https_greased_padding", skip_serializing_if = "Option::is_none")]
    pub https_greased_padding: Option<bool>,
}

impl From<RawCliArgs> for CliArgs {
    fn from(raw: RawCliArgs) -> Self {
        let default = CliArgs::default();
        Self {
            addr: raw.addr.unwrap_or(default.addr),
            port: raw.port.unwrap_or(default.port),
            silent: raw.silent.unwrap_or(default.silent),
            log_level: raw.log_level.unwrap_or(default.log_level),
            dns_mode: raw.dns_mode.unwrap_or(default.dns_mode),
            dns_provider: raw.dns_provider.unwrap_or(default.dns_provider),
            dns_qtype: raw.dns_qtype.unwrap_or(default.dns_qtype),
            http_split_mode: raw.http_split_mode.unwrap_or(default.http_split_mode),
            https_split_mode: raw.https_split_mode.unwrap_or(default.https_split_mode),
            https_fake_ttl_mode: raw.https_fake_ttl_mode.unwrap_or(default.https_fake_ttl_mode),
            https_fake_ttl_value: raw.https_fake_ttl_value.unwrap_or(default.https_fake_ttl_value),
            https_greased_padding: raw.https_greased_padding.unwrap_or(default.https_greased_padding),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CliArgs {
    pub addr: String,
    pub port: u16,
    pub silent: bool,
    pub log_level: LogLevel,
    pub dns_mode: DnsMode,
    pub dns_provider: DnsProvider,
    pub dns_qtype: DnsQType,
    pub http_split_mode: SplitMode,
    pub https_split_mode: SplitMode,
    pub https_fake_ttl_mode: TtlStrategy,
    pub https_fake_ttl_value: u8,
    pub https_greased_padding: bool,
}

impl Default for CliArgs {
    fn default() -> Self {
        Self {
            addr: "127.0.0.1".into(),
            port: 8080,
            silent: false,
            log_level: LogLevel::Info,
            dns_mode: DnsMode::System,
            dns_provider: DnsProvider::Google,
            dns_qtype: DnsQType::Ipv4,
            http_split_mode: SplitMode::None,
            https_split_mode: SplitMode::None,
            https_fake_ttl_mode: TtlStrategy::None,
            https_fake_ttl_value: 0,
            https_greased_padding: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KeepaliveConfig {
    /// TCP Keepalive: время простоя (idle) перед отправкой первой проверки.
    pub time_secs: u64,
    /// TCP Keepalive: интервал между повторными проверками (если нет ответа).
    pub interval_secs: u64,
    /// TCP Keepalive: количество неудачных попыток до разрыва соединения.
    pub retries: u32,
}

impl Default for KeepaliveConfig {
    fn default() -> Self {
        Self {
            time_secs: 15,
            interval_secs: 5,
            retries: 3,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TlsFragmentationConfig {
    /// Jitter для первого фрагмента (мс).
    pub first_jitter_ms: (u64, u64),
    /// Jitter для критической зоны SNI (мс).
    pub chunk_jitter_ms: (u64, u64),
    /// Смещение (до/после) для критической зоны SNI (байт).
    pub sni_offset: (usize, usize),
    /// Диапазон размеров чанков для критической зоны SNI (байт).
    pub chunk_size: (usize, usize),
}

impl Default for TlsFragmentationConfig {
    fn default() -> Self {
        Self {
            first_jitter_ms: (1, 5),
            chunk_jitter_ms: (1, 5),
            chunk_size: (1, 8),
            sni_offset: (1, 5),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HttpFragmentationConfig {
    /// Jitter для первого фрагмента (мс).
    pub first_jitter_ms: (u64, u64),
    /// Jitter чанка для последующих данных (мс).
    pub chunk_jitter_ms: (u64, u64),
    /// Смещение первой части заголовка (байт).
    pub first_offset: (usize, usize),
    /// Диапазон размеров чанков для последующих данных (байт).
    pub chunk_size: (usize, usize),
}

impl Default for HttpFragmentationConfig {
    fn default() -> Self {
        Self {
            first_jitter_ms: (2, 6),
            chunk_jitter_ms: (1, 7),
            first_offset: (1, 5),
            chunk_size: (24, 148),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TlsClientHelloShapingConfig {
    /// Вероятность использования GREASE вместо обычного Padding (0.0 — 1.0).
    pub grease_ratio: f64,
    ///  Вероятность появления случайного байта в наполнении Padding (0.0 — 1.0).
    pub padding_entropy_ratio: f64,
    /// Вероятность выбора "легкого" профиля (0.0 — 1.0).
    pub light_profile_ratio: f64,
    /// Диапазон размеров сообщения TLS-ClientHello для легкого профиля (байт).
    pub light_client_hello_size: (usize, usize),
    /// Диапазон размеров сообщения TLS-ClientHello для тяжелого профиля (байт).
    pub heavy_client_hello_size: (usize, usize),
}

impl Default for TlsClientHelloShapingConfig {
    fn default() -> Self {
        Self {
            grease_ratio: 0.15,
            padding_entropy_ratio: 0.5,
            light_profile_ratio: 0.75,
            light_client_hello_size: (512, 780),
            heavy_client_hello_size: (910, 1450),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EngineConfig {
    /// Размер буфера для чтения HTTP-заголовков и данных.
    pub buffer_capacity: usize,
    /// Предел неактивности TCP-соединения.
    pub tcp_idle_timeout_secs: u64,
    /// Тайм-аут на установку исходящего соединения с DNS сервером (race-connect).
    pub dns_connect_timeout_millis: u64,
    /// Лимит конкурентных соединений для предотвращения исчерпания файловых дескрипторов.
    /// На macOS (soft limit 256) значение 200 оставляет запас для системных нужд, предотвращая ошибку EMFILE (Too many open files).
    pub max_concurrent_connections: usize,
    /// Максимальное время жизни прокси-сессий.
    /// Предотвращает утечку дескрипторов и блокировку семафоров из-за зомби-соединений и зависших потоков.
    pub max_session_duration_secs: u64,
    /// Тайм-аут ожидания завершения активных соединений при остановке сервиса.
    /// Предотвращает бесконечное ожидание процесса при закрытии.
    pub shutdown_grace_period_secs: u64,
    /// Настройки TCP Keepalive.
    pub keepalive: KeepaliveConfig,
    /// Настройки фрагментации TLS-ClientHello.
    pub tls_fragmentation: TlsFragmentationConfig,
    /// Настройки фрагментации HTTP-headers.
    pub http_fragmentation: HttpFragmentationConfig,
    /// Настройки формирования TLS-ClientHello.
    pub tls_client_hello_shaping: TlsClientHelloShapingConfig,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            buffer_capacity: 2048,
            tcp_idle_timeout_secs: 60,
            dns_connect_timeout_millis: 3000,
            max_concurrent_connections: 200,
            max_session_duration_secs: 300,
            shutdown_grace_period_secs: 10,
            keepalive: KeepaliveConfig::default(),
            tls_fragmentation: TlsFragmentationConfig::default(),
            http_fragmentation: HttpFragmentationConfig::default(),
            tls_client_hello_shaping: TlsClientHelloShapingConfig::default(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Settings {
    /// CLI-аргументы.
    pub args: CliArgs,
    /// Системные настройки.
    pub engine: EngineConfig,
}

impl Settings {
    pub fn new() -> Result<Self, SettingsError> {
        let cli_args = RawCliArgs::parse();

        let mut builder = Config::builder().add_source(Config::try_from(&Settings {
            args: CliArgs::default(),
            engine: EngineConfig::default(),
        })?);

        if let Some(ref path) = cli_args.config_path {
            if !path.exists() {
                let absolute_path = std::fs::canonicalize(path).unwrap_or_else(|_| path.clone());
                return Err(SettingsError::FileNotFound(format!(
                    "Configuration file not found at: \"{}\".",
                    absolute_path.display()
                )));
            }
            builder = builder.add_source(config::File::from(path.clone()));
        }

        let settings: Self = builder
            .add_source(Config::try_from(&cli_args)?)
            .build()?
            .try_deserialize()?;

        let _ = ARGS.set(settings.args.clone());

        Ok(settings)
    }

    /// Проверка режима --silent (для макроса)
    pub fn is_silent() -> bool {
        ARGS.get().is_some_and(|args| args.silent)
    }
}
