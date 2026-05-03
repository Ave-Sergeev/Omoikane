use crate::{
    application::port::output::proxy_manager::{ProxyManagerError, ProxyManagerPort},
    silent,
};
use std::process::Command;

pub struct LinuxProxyAdapter;

impl LinuxProxyAdapter {
    /// Поиск активного интерфейса
    fn detect_active_interface() -> Result<String, ProxyManagerError> {
        let cmd = "ip route get 8.8.8.8 | grep -oP 'dev \\K\\S+'";
        let output = Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .output()
            .map_err(ProxyManagerError::Io)?;
        let name = String::from_utf8_lossy(&output.stdout).trim().to_string();

        if name.is_empty() {
            return Err(ProxyManagerError::InterfaceNotFound);
        }

        Ok(name)
    }
}

impl ProxyManagerPort for LinuxProxyAdapter {
    /// Установка режима работы системного прокси (вкл/выкл)
    fn set_system_proxy(&self, enable: bool, proxy_ip: &str, proxy_port: u16) -> Result<(), ProxyManagerError> {
        let port_str = proxy_port.to_string();
        let run_gsettings = |args: &[&str]| -> Result<(), ProxyManagerError> {
            let status = Command::new("gsettings").args(args).status()?;
            if !status.success() {
                return Err(ProxyManagerError::OperationFailed("gsettings failed".to_string()));
            }
            Ok(())
        };

        // TODO: Логи наверное надо абстрагировать
        if enable {
            silent!("\nProxy setup for [System-wide GNOME/Linux]");
            run_gsettings(&["set", "org.gnome.system.proxy.http", "host", proxy_ip])?;
            run_gsettings(&["set", "org.gnome.system.proxy.http", "port", &port_str])?;
            run_gsettings(&["set", "org.gnome.system.proxy.https", "host", proxy_ip])?;
            run_gsettings(&["set", "org.gnome.system.proxy.https", "port", &port_str])?;
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
}
