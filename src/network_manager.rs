use crate::silent;
use std::process::Command;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("Active network interface not found")]
    InterfaceNotFound,

    #[error("Command execution failed: {0}")]
    CommandFailed(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("UTF-8 decoding error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
}

pub struct NetworkManager;

impl NetworkManager {
    /// Установка режима работы системного прокси (вкл/выкл)
    pub fn set_proxy_mode(enable: bool) -> Result<(), NetworkError> {
        let interface = Self::detect_active_interface()?;

        let run_cmd = |args: &[&str]| -> Result<(), NetworkError> {
            let status = Command::new("networksetup").args(args).status()?;
            if !status.success() {
                return Err(NetworkError::CommandFailed(format!("Command {:?} failed", args[0])));
            }
            Ok(())
        };

        if enable {
            silent!("\nProxy setup for [{interface}]");
            run_cmd(&["-setwebproxy", &interface, "127.0.0.1", "8080"])?;
            silent!(" ├─ HTTP proxy:  [Enabled]");
            run_cmd(&["-setsecurewebproxy", &interface, "127.0.0.1", "8080"])?;
            silent!(" └─ HTTPS proxy: [Enabled]");
            silent!("\nPress `CTRL+C` to stop proxy\n");
        } else {
            run_cmd(&["-setwebproxystate", &interface, "off"])?;
            run_cmd(&["-setsecurewebproxystate", &interface, "off"])?;
            silent!("\nProxy configuration for [{interface}] has been [Disabled]\n");
        }

        Ok(())
    }

    /// Поиск активного интерфейса
    fn detect_active_interface() -> Result<String, NetworkError> {
        let cmd = "networksetup -listnetworkserviceorder | grep -B 1 $(route -n get default | grep interface | awk '{print $2}') | head -n 1 | cut -d ' ' -f 2-";
        let output = Command::new("sh").arg("-c").arg(cmd).output()?;
        let name = String::from_utf8_lossy(&output.stdout).trim().to_string();

        if name.is_empty() {
            return Err(NetworkError::InterfaceNotFound);
        }

        Ok(name)
    }
}
