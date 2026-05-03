use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProxyManagerError {
    #[error("active network interface not found")]
    InterfaceNotFound,

    #[error("operation failed: {0}")]
    OperationFailed(String),

    #[error("internal I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub trait ProxyManagerPort: Send + Sync {
    /// Включить/выключить системный HTTP/HTTPS прокси на заданный IP:port
    fn set_system_proxy(&self, enable: bool, proxy_ip: &str, proxy_port: u16) -> Result<(), ProxyManagerError>;
}
