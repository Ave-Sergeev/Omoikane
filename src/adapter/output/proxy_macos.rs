use crate::{
    application::port::output::proxy_manager::{ProxyManagerError, ProxyManagerPort},
    silent,
};
use std::process::Command;

pub struct MacOsProxyAdapter;

impl MacOsProxyAdapter {
    /// Поиск активного интерфейса
    fn detect_active_interface() -> Result<String, ProxyManagerError> {
        let cmd = "networksetup -listnetworkserviceorder | grep -B 1 $(route -n get default | grep interface | awk '{print $2}') | head -n 1 | cut -d ' ' -f 2-";
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

impl ProxyManagerPort for MacOsProxyAdapter {
    /// Установка режима работы системного прокси (вкл/выкл)
    fn set_system_proxy(&self, enable: bool, proxy_ip: &str, proxy_port: u16) -> Result<(), ProxyManagerError> {
        let interface = Self::detect_active_interface()?;
        let port_str = proxy_port.to_string();

        let run_cmd = |args: &[&str]| -> Result<(), ProxyManagerError> {
            let status = Command::new("networksetup")
                .args(args)
                .status()
                .map_err(ProxyManagerError::Io)?;
            if !status.success() {
                return Err(ProxyManagerError::OperationFailed(format!("Command {:?} failed", args[0])));
            }
            Ok(())
        };

        // TODO: Логи наверное надо абстрагировать
        if enable {
            silent!("\nProxy setup for [{interface}]");
            run_cmd(&["-setwebproxy", &interface, proxy_ip, &port_str])?;
            silent!(" ├─ HTTP proxy:  [Enabled]");
            run_cmd(&["-setsecurewebproxy", &interface, proxy_ip, &port_str])?;
            silent!(" └─ HTTPS proxy: [Enabled]");
            silent!("\nPress `CTRL+C` to stop proxy\n");
        } else {
            run_cmd(&["-setwebproxystate", &interface, "off"])?;
            run_cmd(&["-setsecurewebproxystate", &interface, "off"])?;
            silent!("\nProxy configuration for [{interface}] has been [Disabled]\n");
        }

        Ok(())
    }
}
