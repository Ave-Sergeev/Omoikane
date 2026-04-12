use crate::silent;
use std::process::Command;
use thiserror::Error;
#[cfg(target_os = "windows")]
use windows_sys::Win32::Networking::WinInet::{
    INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED, InternetSetOptionW,
};
#[cfg(target_os = "windows")]
use winreg::RegKey;
#[cfg(target_os = "windows")]
use winreg::enums::*;

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
    #[cfg(target_os = "macos")]
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
    #[cfg(target_os = "macos")]
    fn detect_active_interface() -> Result<String, NetworkError> {
        let cmd = "networksetup -listnetworkserviceorder | grep -B 1 $(route -n get default | grep interface | awk '{print $2}') | head -n 1 | cut -d ' ' -f 2-";
        let output = Command::new("sh").arg("-c").arg(cmd).output()?;
        let name = String::from_utf8_lossy(&output.stdout).trim().to_string();

        if name.is_empty() {
            return Err(NetworkError::InterfaceNotFound);
        }

        Ok(name)
    }

    /// Установка режима работы системного прокси (вкл/выкл)
    #[cfg(target_os = "windows")]
    pub fn set_proxy_mode(enable: bool) -> Result<(), NetworkError> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
        let key = hkcu
            .open_subkey_with_flags(path, KEY_WRITE)
            .map_err(|e| NetworkError::CommandFailed(e.to_string()))?;

        if enable {
            silent!("\nProxy setup for Windows System");
            key.set_value("ProxyEnable", &1u32)
                .map_err(|e| NetworkError::CommandFailed(e.to_string()))?;
            key.set_value("ProxyServer", &"127.0.0.1:8080")
                .map_err(|e| NetworkError::CommandFailed(e.to_string()))?;
            silent!(" └─ HTTP/HTTPS proxy: [Enabled]");
        } else {
            key.set_value("ProxyEnable", &0u32)
                .map_err(|e| NetworkError::CommandFailed(e.to_string()))?;
            silent!("\nProxy configuration has been [Disabled]");
        }

        unsafe {
            InternetSetOptionW(std::ptr::null_mut(), INTERNET_OPTION_SETTINGS_CHANGED, std::ptr::null_mut(), 0);
            InternetSetOptionW(std::ptr::null_mut(), INTERNET_OPTION_REFRESH, std::ptr::null_mut(), 0);
        }

        if enable {
            silent!("\nPress `CTRL+C` to stop proxy\n");
        } else {
            silent!("\n");
        }

        Ok(())
    }

    /// Поиск активного интерфейса
    #[cfg(target_os = "windows")]
    fn detect_active_interface() -> Result<String, NetworkError> {
        Ok("Windows System Proxy".to_string())
    }

    /// Установка режима работы системного прокси (вкл/выкл)
    #[cfg(target_os = "linux")]
    pub fn set_proxy_mode(enable: bool) -> Result<(), NetworkError> {
        let run_gsettings = |args: &[&str]| -> Result<(), NetworkError> {
            let status = Command::new("gsettings").args(args).status()?;
            if !status.success() {
                return Err(NetworkError::CommandFailed("gsettings failed".to_string()));
            }
            Ok(())
        };

        if enable {
            silent!("\nProxy setup for [System-wide GNOME/Linux]");
            run_gsettings(&["set", "org.gnome.system.proxy.http", "host", "127.0.0.1"])?;
            run_gsettings(&["set", "org.gnome.system.proxy.http", "port", "8080"])?;
            run_gsettings(&["set", "org.gnome.system.proxy.https", "host", "127.0.0.1"])?;
            run_gsettings(&["set", "org.gnome.system.proxy.https", "port", "8080"])?;
            run_gsettings(&["set", "org.gnome.system.proxy", "mode", "manual"])?;
            silent!(" ├─ HTTP proxy:  [Enabled]");
            silent!(" └─ HTTPS proxy: [Enabled]");
            silent!("\nPress `CTRL+C` to stop proxy\n");
        } else {
            run_gsettings(&["set", "org.gnome.system.proxy", "mode", "none"])?;
            silent!("\nProxy configuration has been [Disabled]\n");
        }

        Ok(())
    }

    /// Поиск активного интерфейса
    #[cfg(target_os = "linux")]
    fn detect_active_interface() -> Result<String, NetworkError> {
        let cmd = "ip route get 8.8.8.8 | grep -oP 'dev \\K\\S+'";
        let output = Command::new("sh").arg("-c").arg(cmd).output()?;
        let name = String::from_utf8_lossy(&output.stdout).trim().to_string();

        if name.is_empty() {
            return Err(NetworkError::InterfaceNotFound);
        }
        Ok(name)
    }
}
