#[cfg(target_os = "macos")]
mod proxy_macos;
#[cfg(target_os = "macos")]
pub use proxy_macos::MacOsProxyAdapter as PlatformProxyAdapter;

#[cfg(target_os = "windows")]
mod proxy_windows;
#[cfg(target_os = "windows")]
pub use proxy_windows::WindowsProxyAdapter as PlatformProxyAdapter;

#[cfg(target_os = "linux")]
mod proxy_linux;
#[cfg(target_os = "linux")]
pub use proxy_linux::LinuxProxyAdapter as PlatformProxyAdapter;
