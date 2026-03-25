use log::info;
use std::process::Command;
use thiserror::Error;
pub struct NetworkManager;

#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("Активный сетевой интерфейс не найден")]
    InterfaceNotFound,

    #[error("Ошибка выполнения команды: {0}")]
    CommandFailed(String),

    #[error("Ошибка ввода-вывода: {0}")]
    Io(#[from] std::io::Error),

    #[error("Ошибка кодировки UTF-8: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
}

impl NetworkManager {
    /// Функция поиска активного интерфейса
    pub fn get_interface() -> Result<String, NetworkError> {
        let cmd = "networksetup -listnetworkserviceorder | grep -B 1 $(route -n get default | grep interface | awk '{print $2}') | head -n 1 | cut -d ' ' -f 2-";
        let output = Command::new("sh").arg("-c").arg(cmd).output()?;
        let name = String::from_utf8_lossy(&output.stdout).trim().to_string();

        if name.is_empty() {
            return Err(NetworkError::InterfaceNotFound);
        }

        Ok(name)
    }

    pub fn set_proxy(enable: bool) -> Result<(), NetworkError> {
        let interface = Self::get_interface()?;

        let run_cmd = |args: &[&str]| -> Result<(), NetworkError> {
            let status = Command::new("networksetup").args(args).status()?;
            if !status.success() {
                return Err(NetworkError::CommandFailed(format!(
                    "Команда {:?} не удалась",
                    args[0]
                )));
            }
            Ok(())
        };

        if enable {
            info!("\n--- [ SYSTEM ] ---");
            info!("Настройка прокси для [{interface}]:");
            run_cmd(&["-setwebproxy", &interface, "127.0.0.1", "8080"])?;
            info!(" └─ HTTP прокси:  [Включен]");
            run_cmd(&["-setsecurewebproxy", &interface, "127.0.0.1", "8080"])?;
            info!(" └─ HTTPS прокси: [Включен]");
        } else {
            run_cmd(&["-setwebproxystate", &interface, "off"])?;
            run_cmd(&["-setsecurewebproxystate", &interface, "off"])?;
            info!("Прокси для [{interface}] успешно [Отключен]");
        }

        Ok(())
    }
}
