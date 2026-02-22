"""VPN connection result, tunnel config, plugin base class, and config schema."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from tv import proc
from tv.app_config import cfg
from tv.logger import Logger
from tv.net import NetManager


@dataclass
class VPNResult:
    ok: bool = False
    pid: Optional[int] = None
    detail: str = ""


@dataclass
class ConfigParam:
    """Declarative description of a single config parameter for a plugin."""

    key: str              # key in TunnelConfig.auth / .config_file / .extra
    label: str            # UI label ("Хост FortiVPN")
    required: bool = False
    secret: bool = False
    default: str = ""
    env_var: str = ""     # e.g. "VPN_FORTI_HOST"
    target: str = "auth"  # "auth" | "config_file" | "extra"
    prompt: bool = True   # False = resolve from TOML/ENV/saved only, never wizard


@dataclass
class TunnelConfig:
    """Declarative description of a single tunnel."""

    name: str = ""
    type: str = ""
    order: int = 0
    enabled: bool = True
    config_file: str = ""
    log: str = ""
    interface: str = ""
    routes: dict = field(default_factory=dict)
    dns: dict = field(default_factory=dict)
    checks: dict = field(default_factory=dict)
    auth: dict = field(default_factory=dict)
    extra: dict = field(default_factory=dict)
    _auto_config_file: bool = False


class TunnelPlugin(ABC):
    """Base class for all tunnel plugins.

    Each VPN type implements connect() and process_name.
    Routes, DNS, disconnect get sensible defaults that can be overridden.
    """

    # Process names for emergency cleanup (without plugin instance).
    # Override in subclasses. Used by disconnect.run() to kill lingering processes.
    process_names: list[str] = []

    # Regex patterns for kill_pattern() during emergency cleanup.
    # Override in subclasses that need pattern-based kill (e.g. to avoid killing Tunnelblick).
    kill_patterns: list[str] = []

    def __init__(
        self,
        cfg: TunnelConfig,
        net: NetManager,
        log: Logger,
        script_dir: Path,
    ) -> None:
        self.cfg = cfg
        self.net = net
        self.log = log
        self.script_dir = script_dir
        self._pid: Optional[int] = None

    @classmethod
    def config_schema(cls) -> list[ConfigParam]:
        """Declare config params this plugin needs. Override in subclasses."""
        return []

    @classmethod
    def discover_pid(cls, tcfg: TunnelConfig, script_dir: Path) -> Optional[int]:
        """Best-effort PID discovery without engine context.

        Used by run_plugins() to find processes from a previous run.
        Override in subclasses with type-specific pgrep patterns.
        """
        return None

    @abstractmethod
    def connect(self) -> VPNResult:
        """Establish the tunnel. Return VPNResult."""

    @property
    @abstractmethod
    def process_name(self) -> str:
        """Main process name (e.g. 'openvpn', 'openfortivpn', 'sing-box')."""

    @property
    def display_name(self) -> str:
        """Human-readable name for UI. Override for custom display."""
        return self.cfg.name or self.cfg.type

    def _default_log_path(self) -> Path:
        """Per-instance log path (uses cfg.log or generates from name)."""
        if self.cfg.log:
            return Path(self.cfg.log)
        name = self.cfg.name or self.cfg.type
        return Path(f"{cfg.paths.log_dir}/{self.cfg.type}-{name}.log")

    def _kill_by_pid(self) -> bool:
        """Kill process by PID with timeout. Returns True if killed."""
        if not self._pid or not proc.is_alive(self._pid):
            return False
        proc.kill_by_pid(self._pid, sudo=True)
        steps = int(cfg.timeouts.pid_kill / cfg.timeouts.pid_kill_interval)
        for _ in range(steps):
            if not proc.is_alive(self._pid):
                return True
            time.sleep(cfg.timeouts.pid_kill_interval)
        self.log.log(
            "WARN",
            f"{self.process_name} PID={self._pid} не завершился за "
            f"{cfg.timeouts.pid_kill}с, pattern fallback",
        )
        return False

    def _kill_by_pattern(self) -> None:
        """Per-instance pattern kill. Override in subclasses."""

    def disconnect(self) -> None:
        """Kill by PID, fallback to per-instance pattern."""
        if not self._kill_by_pid():
            self._kill_by_pattern()

    def add_routes(self, gateway: Optional[str] = None) -> None:
        """Add host and network routes from cfg.routes."""
        hosts = self.cfg.routes.get("hosts", [])
        networks = self.cfg.routes.get("networks", [])
        iface = self.cfg.interface

        for host in hosts:
            if iface:
                ok = self.net.add_iface_route(host, iface, host=True)
            elif gateway:
                ok = self.net.add_host_route(host, gateway)
            else:
                continue
            self.log.log(
                "INFO" if ok else "WARN",
                f"route add {host} {'OK' if ok else 'FAIL'}",
            )

        for network in networks:
            if iface:
                ok = self.net.add_iface_route(network, iface, host=False)
            elif gateway:
                ok = self.net.add_net_route(network, gateway)
            else:
                continue
            self.log.log(
                "INFO" if ok else "WARN",
                f"route add {network} {'OK' if ok else 'FAIL'}",
            )

    def setup_dns(self) -> None:
        """Set up DNS resolver from cfg.dns."""
        nameservers = self.cfg.dns.get("nameservers", [])
        domains = self.cfg.dns.get("domains", [])
        if nameservers and domains:
            results = self.net.setup_dns_resolver(
                domains, nameservers, self.cfg.interface,
            )
            for domain, ok in results.items():
                self.log.log(
                    "INFO" if ok else "WARN",
                    f"Resolver для {domain} {'создан' if ok else 'FAIL'}",
                )

    def cleanup_dns(self) -> None:
        """Remove DNS resolver entries."""
        domains = self.cfg.dns.get("domains", [])
        if domains:
            self.net.cleanup_dns_resolver(domains, self.cfg.interface)

    def delete_routes(self) -> None:
        """Remove routes added by add_routes()."""
        for host in self.cfg.routes.get("hosts", []):
            self.net.delete_host_route(host)
        for network in self.cfg.routes.get("networks", []):
            self.net.delete_net_route(network)
