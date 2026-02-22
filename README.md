<div align="center">

```
  ░░▒▒▓▓████████████████████████████████████████████▓▓▒▒░░

    ████████╗██╗   ██╗███╗  ██╗███╗  ██╗███████╗██╗
    ╚══██╔══╝██║   ██║████╗ ██║████╗ ██║██╔════╝██║
       ██║   ██║   ██║██╔██╗██║██╔██╗██║█████╗  ██║
       ██║   ██║   ██║██║╚████║██║╚████║██╔══╝  ██║
       ██║   ╚██████╔╝██║ ╚███║██║ ╚███║███████╗█████╗
       ╚═╝    ╚═════╝ ╚═╝  ╚══╝╚═╝  ╚══╝╚══════╝╚════╝

               ═══════════╡ ◆ ╞═══════════

         ██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗
         ██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝
         ██║   ██║███████║██║   ██║██║     ██║
         ╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║
          ╚████╔╝ ██║  ██║╚██████╔╝██████╗██║
           ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚═════╝╚═╝

                       v1.0

  ░░▒▒▓▓████████████████████████████████████████████▓▓▒▒░░
```

**Multi-tunnel VPN orchestrator for macOS & Linux**

One command. Three tunnels. Zero manual routing.

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Tests](https://img.shields.io/badge/Tests-477_passed-2ea44f?style=for-the-badge)](tests/)
[![Platform](https://img.shields.io/badge/macOS_|_Linux-lightgrey?style=for-the-badge&logo=apple&logoColor=white)](https://github.com/enyonee/tunnelvault)
[![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)

`OpenVPN` · `FortiVPN` · `sing-box`

[Getting Started](#getting-started) · [Configuration](#configuration) · [Usage](#usage) · [Architecture](#how-it-works) · [Tests](#tests)

</div>

---

## Getting Started

```bash
git clone https://github.com/enyonee/tunnelvault.git
cd tunnelvault
cp defaults.toml.example defaults.toml   # edit with your infrastructure
./setup.sh                                # creates venv, installs deps
sudo ./tvpn                               # interactive wizard
```

The wizard resolves any missing parameters through a priority chain:

```
defaults.toml  →  ENV variable  →  .vpn-settings.json  →  interactive wizard
```

## How It Works

TunnelVault brings up multiple VPN tunnels simultaneously and handles the ugly parts: routing, DNS, IPv6 leak prevention, certificate management, health checks.

```
                    ┌─────────────────────────────────┐
                    │          TunnelVault             │
                    │         ┌───────────┐            │
                    │         │  Engine   │            │
                    │         └─────┬─────┘            │
                    │     ┌─────────┼─────────┐        │
                    │     ▼         ▼         ▼        │
                    │ ┌────────┐┌────────┐┌────────┐   │
                    │ │OpenVPN ││FortiVPN││sing-box│   │
                    │ │  tun0  ││  ppp0  ││ utun99 │   │
                    │ └───┬────┘└───┬────┘└───┬────┘   │
                    └─────┼─────────┼─────────┼────────┘
                          ▼         ▼         ▼
                    ╔═════════════════════════════════╗
                    ║     Routes · DNS · Checks       ║
                    ╚═════════════════════════════════╝
```

The lifecycle:

1. **Cleanup** - kill stale sessions, flush old routes
2. **IPv6 disable** - prevent DNS/traffic leaks
3. **Host routes** - pin VPN server IPs to the default gateway
4. **Connect** - bring up each tunnel via its plugin
5. **Health checks** - ports, ping, DNS, HTTP, external IP
6. **Summary** - terminal report with status per tunnel

## Configuration

### Files

| File | Purpose | In git? |
|---|---|---|
| `defaults.toml.example` | Infrastructure template | Yes |
| `defaults.toml` | Your actual config (copy from .example) | No |
| `.vpn-settings.json` | Credentials (host, login, password, cert) | No |

### defaults.toml

Each tunnel is a `[tunnels.<name>]` section with its own routes, DNS, and checks:

```toml
[global.vpn_server_routes]
hosts = ["203.0.113.10"]
resolve = ["vpn.example.com"]

[tunnels.openvpn]
type = "openvpn"
order = 1
config_file = "client.ovpn"

[tunnels.fortivpn]
type = "fortivpn"
order = 2

[tunnels.fortivpn.auth]
host = "vpn.example.com"
port = "44333"
cert_mode = "auto"

[tunnels.fortivpn.routes]
networks = ["192.168.0.0/16", "10.0.0.0/8"]

[tunnels.fortivpn.dns]
nameservers = ["10.0.1.1", "10.0.1.2"]
domains = ["example.local", "internal.com"]

[tunnels.fortivpn.checks]
ports = [{ host = "10.0.0.1", port = 8080 }]
ping = [{ host = "10.0.0.1", label = "gateway" }]
```

<details>
<summary><b>Environment variables</b></summary>

```bash
# FortiVPN
export VPN_FORTI_HOST="vpn.company.com"
export VPN_FORTI_LOGIN="user"
export VPN_FORTI_PASS="secret"
export VPN_FORTI_PORT="44333"
export VPN_CERT_MODE="auto"             # auto | manual
export VPN_TRUSTED_CERT="sha256hash..."

# OpenVPN / sing-box
export VPN_OVPN_CONFIG="client.ovpn"
export VPN_SINGBOX_CONFIG="singbox.json"
```

</details>

## Usage

```bash
sudo ./tvpn                # connect (wizard fills missing params)
sudo ./tvpn --disconnect   # disconnect all tunnels
sudo ./tvpn --debug        # verbose output to stderr
```

Each plugin declares its own `config_schema()` - parameters are resolved dynamically per tunnel.

## Cross-Platform

| Function | macOS | Linux |
|---|---|---|
| Routing | `route add/delete` | `ip route add/del` |
| DNS resolver | `/etc/resolver/*` | `resolvectl` |
| Interfaces | `ifconfig -l` | `ip -br addr` |
| IPv6 control | `networksetup` | `sysctl` |
| Default gateway | `route -n get default` | `ip route show default` |

Detected via `platform.system()`. Unknown OS falls back to Linux.

## Requirements

- **Python 3.10+**
- **macOS** or **Linux**
- System tools: `openvpn`, `openfortivpn`, `sing-box`, `openssl`, `curl`, `nc`
- sudo access (VPN daemons require root)

## Tests

```bash
source .venv/bin/activate
pytest              # all 477 tests
pytest -v           # verbose
pytest tests/test_vpn_fortivpn.py   # single module
```

477 tests covering happy paths and inverse scenarios (errors, timeouts, empty data, missing files, process crashes). All external calls are mocked.

## Logs

| Tunnel | Default path |
|---|---|
| Main | `tunnelvault.log` |
| FortiVPN | `/tmp/openfortivpn.log` |
| OpenVPN | `/tmp/openvpn.log` |
| sing-box | `/tmp/sing-box.log` |

Log paths are configurable per tunnel via the `log` field in `[tunnels.<name>]`.

<details>
<summary><b>Project structure</b></summary>

```
tunnelvault/
├── setup.sh                 # install: venv, deps, system tool checks
├── tvpn                     # runner: ./tvpn [args] (activates venv)
├── tunnelvault.py           # entrypoint, signal handlers, crash diagnostics
├── defaults.toml.example    # infrastructure config template
├── pyproject.toml
├── tv/
│   ├── __init__.py          # __version__
│   ├── engine.py            # Engine: lifecycle orchestration, hooks
│   ├── defaults.py          # TOML parser, tunnel config builder
│   ├── config.py            # plugin-driven parameter resolution
│   ├── app_config.py        # centralized app settings (timeouts, paths)
│   ├── ui.py                # ANSI colors, logo, summary table, wizard
│   ├── logger.py            # dual logger: file + debug stderr
│   ├── proc.py              # run, background, wait_for, kill, is_alive
│   ├── net.py               # DarwinNet / LinuxNet: routes, DNS, IPv6
│   ├── routing.py           # route table management
│   ├── checks.py            # health-check primitives + runner
│   ├── disconnect.py        # cleanup: kill via registry, restore state
│   └── vpn/
│       ├── base.py          # TunnelConfig, TunnelPlugin ABC, ConfigParam
│       ├── registry.py      # @register, get_plugin, available_types
│       ├── openvpn.py       # OpenVPN + Tunnelblick detection
│       ├── fortivpn.py      # FortiVPN, PPP gateway, routes, DNS
│       └── singbox.py       # sing-box, utun interface, routes
└── tests/                   # 477 tests, pytest
```

</details>

---

<div align="center">
<sub>Built for teams that run multiple VPNs and hate doing it manually.</sub>
</div>
