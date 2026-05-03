use crate::{
    application::port::output::proxy_manager::{ProxyManagerError, ProxyManagerPort},
    silent,
};
use windows_sys::Win32::Networking::WinInet::{
    INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED, InternetSetOptionW,
};
use winreg::RegKey;
use winreg::enums::*;

pub struct WindowsProxyAdapter;

impl ProxyManagerPort for WindowsProxyAdapter {
    /// Установка режима работы системного прокси (вкл/выкл)
    /// #[cfg(target_os = "windows")]
    fn set_system_proxy(&self, enable: bool, proxy_ip: &str, proxy_port: u16) -> Result<(), ProxyManagerError> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
        let key = hkcu
            .open_subkey_with_flags(path, KEY_WRITE)
            .map_err(|err| ProxyManagerError::OperationFailed(err.to_string()))?;

        // TODO: Логи наверное надо абстрагировать
        if enable {
            silent!("\nProxy setup for Windows System");
            let proxy_addr = format!("{}:{}", proxy_ip, proxy_port);

            key.set_value("ProxyEnable", &1u32)
                .map_err(|err| ProxyManagerError::OperationFailed(err.to_string()))?;
            key.set_value("ProxyServer", &proxy_addr)
                .map_err(|err| ProxyManagerError::OperationFailed(err.to_string()))?;
            silent!(" └─ HTTP/HTTPS proxy: [Enabled]");
        } else {
            key.set_value("ProxyEnable", &0u32)
                .map_err(|err| ProxyManagerError::OperationFailed(err.to_string()))?;
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
}
