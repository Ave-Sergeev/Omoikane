## Omoikane

---

[Русский](https://github.com/Ave-Sergeev/Omoikane/blob/main/README.md) | [English](https://github.com/Ave-Sergeev/Omoikane/blob/main/README.en.md)

### Description

This project is a lightweight `Explicit Proxy` written in `Rust`.  
Due to the language's architectural features, it ensures minimal latency and low system resource consumption.

- No root or administrator privileges are required to run and use the application.
- All TCP traffic processing occurs locally on your computer.
- Support for DoH and DoT protocols protects DNS queries from interception and spoofing, ensuring correct address resolution before a connection is established.
- The tool only processes the session initialization phase (TLS-ClientHello, HTTP-headers). The main payload is transmitted transparently without interference, minimizing latency and system load.
- Dynamic session fingerprinting makes traffic blocking by signatures difficult (this feature is in experimental mode).
- Changes are applied to all new connections immediately upon startup and automatically cease when the process is terminated.
- Builds are available for popular operating systems: macOS, Windows, and Linux.

Platforms:
- **macOS**  
    On Apple Silicon (`aarch64-apple-darwin`) & Intel (`x86_64-apple-darwin`).  
    Status: Testing and stable operation confirmed on the author's macOS (Apple Silicon).
- **Windows**  
    On Windows 7, 8, 10, 11 on Intel/AMD processors (`x86_64-pc-windows-msvc`).  
    Status: Testing and stable operation confirmed on the author's Windows 10.
- **Linux**  
    On Ubuntu, Debian, CentOS, Fedora, Alpine, Arch distributions (`x86_64-unknown-linux-musl`).  
    Status: Testing has not been conducted; functionality is theoretical only.
    
### Quick Start

The fastest way to get started is to download the pre-compiled binary for your system:
1. Go to the [Releases](https://github.com/Ave-Sergeev/Omoikane/releases) page.
2. Download the version for your OS.
3. Extract the archive and move the binary to a location of your choice. Run it from [the terminal](#cli-usage-examples).

⚠️ Note ⚠️  
When launching the utility for the first time, macOS may display a "unverified developer" warning. This is standard macOS behavior for third-party software — simply allow the app to run in the settings ("Privacy & Security" section).

### About

**Main Objective**:  
Maintaining the resilience of TCP connections against Deep Packet Inspection (DPI) at intermediate network nodes through TCP stream fragmentation and packet structure manipulation. This includes the implementation of defense mechanisms against DNS Spoofing and Cache Poisoning attacks, as well as dynamic session fingerprinting.

**Current State**:  
Active Research & PoC 🦀  
Despite its `Proof of Concept` status, the tool is fully functional and ready for use.  
Key traffic manipulation mechanisms are already implemented and operate stably in the target environment. However, the architecture and individual components are still undergoing active development and optimization.

**Disclaimer**:  
This software was developed as part of a Master's thesis and is strictly for research purposes.  
The development is presented as a `Proof of Concept` (PoC) to investigate mechanisms for ensuring communication resilience when passing through nodes with Deep Packet Inspection (DPI).

The software is provided on an `as is` basis. Its use is permitted for educational and informational purposes only.  
The author makes no guarantees regarding the tool's performance under specific conditions and bears no responsibility for any direct or indirect damage resulting from the use of this software.

**Development Note**:  
This repository does not strictly follow formal industry standards for Git history (Best Practices).  
Commit history has been intentionally simplified by the author.

**Symbolism**:  
The project is named after a Japanese mythological god of intellect, wisdom, and strategy, who restored light to the world by finding a "clever way" where direct action had failed.

### Building from Source

Environment setup and build instructions can be found in the [development notes](https://github.com/Ave-Sergeev/Omoikane/blob/main/DEVELOPMENT.md).

### Configuration

The service configuration is flexible and supports two priority levels:  
- CLI Arguments — used for quick startup and overriding key parameters. These have the highest priority.
- Configuration File (config.yaml) — intended for fine-tuning internal proxy-engine parameters that rarely require immediate changes. A configuration template with example settings (config_example.yaml) is located in the project root.

**Available CLI Arguments**:  
You can view the full list of available flags and their descriptions by running the `--help` command in your terminal.  
If an argument is not explicitly provided, values from config.yaml or default settings will be used.  

- `APP`
  - `--ip` - IP address to listen on. (Default: `127.0.0.1`)
  - `--port` - Port to listen on. (Default: `8080`)
  - `--config` - Path to the configuration file (YAML). (Default: `not set`)
  - `--silent` - Hides the banner and informational messages in the terminal: 'true', 'false'. (Default: `false`)
  - `--log-level` - Logging verbosity level: `off`, `error`, `warn`, `info`, `debug`, `trace`. (Default: `info`)
- `DNS`
  - `--dns-mode` - DNS operation mode: `system`, `doh`, `dot`. (Default: `system`)
  - `--dns-qtype` - DNS record query type: `ipv4`, `ipv6`, `all`. (Default: `ipv4`)
  - `--dns-provider` - Provider used for DoH/DoT: `google`, `cloudflare`, `quad9`. (Default: `google`)
- `HTTP`
  - `--http-split-mode` - HTTP request fragmentation: `none`, `fragment`. (Default: `none`)
- `HTTPS`
  - `--https-split-mode` - TLS ClientHello fragmentation: `none`, `fragment`. (Default: `none`)
  - `--https-fake-ttl-mode` - TTL strategy for fake packets: `none`, `custom`. (Default: `none`)
  - `--https-fake-ttl-value` - TTL value for `custom` mode. (Default: `0`, range: `1-255`)
  - `--https-greased-padding` - Dynamic modification of the session fingerprint by increasing TLS handshake entropy (GREASE & Padding): `true`, `false`. (Default: `false`)

### CLI Usage Examples

All parameters have default values. If no arguments are provided, the standard settings will be used.  
Network conditions vary by provider. If the default settings do not yield the desired results, you should experiment with CLI arguments and parameters in the config.yaml file to find the optimal combination for your specific case.

- **Silent Mode:** Suppresses banner output and informational messages. Recommended for background processes or service mode.
  > ./<path_to_binary_file> --silent true

- **Basic Mode:** Traffic passes through without modifications, using the system DNS resolver.
  Minimalist launch (uses default parameters):
    > ./<path_to_binary_file>

  Full command (explicitly defined parameters):
    > ./<path_to_binary_file> -i 127.0.0.1 -p 8080 --dns-mode system --log-level info --http-split-mode none --https-split-mode none --https-fake-ttl-mode none

- **Moderate Mode:** Enables packet fragmentation and Cloudflare DNS-over-TLS (IPv4) to bypass simple restrictions.
  > ./<path_to_binary_file> --dns-mode dot --dns-provider cloudflare --http-split-mode fragment --https-split-mode fragment

- **Maximum Mode:** Using DNS-over-HTTPS (IPv4), packet fragmentation, custom TTL adjustment, and fingerprint modification.
  > ./<path_to_binary_file> --dns-mode doh --dns-provider cloudflare --http-split-mode fragment --https-split-mode fragment --https-fake-ttl-mode custom --https-fake-ttl-value 1 --https-greased-padding true

### Implementation Details

Architecture description and key project algorithms can be found in the [development notes](https://github.com/Ave-Sergeev/Omoikane/blob/main/DEVELOPMENT.md).

### License

The source code of this project is distributed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).  
This allows for the use, copying, and modification of the code for educational and research purposes.  

### Support the Project

If you found something interesting or useful in this project, or if you simply liked the code, feel free to give it a ⭐ star as a token of appreciation.
