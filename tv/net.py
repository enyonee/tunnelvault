"""Platform-aware networking: routes, interfaces, DNS, gateway."""

from __future__ import annotations

import platform
import re
import shutil
import subprocess
from abc import ABC, abstractmethod
from typing import Optional

from tv.app_config import cfg


def _run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    """subprocess.run with default timeout."""
    kwargs.setdefault("capture_output", True)
    kwargs.setdefault("text", True)
    kwargs.setdefault("timeout", cfg.timeouts.net_command)
    try:
        return subprocess.run(cmd, **kwargs)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(args=cmd, returncode=-1, stdout="", stderr="timeout")


class NetManager(ABC):
    """Abstract network manager. Implementations for Darwin/Linux."""

    @abstractmethod
    def default_gateway(self) -> Optional[str]: ...

    @abstractmethod
    def interfaces(self) -> dict[str, str]: ...

    @abstractmethod
    def check_interface(self, name: str) -> bool: ...

    @abstractmethod
    def add_host_route(self, ip: str, gateway: str) -> bool: ...

    @abstractmethod
    def add_net_route(self, network: str, gateway: str) -> bool: ...

    @abstractmethod
    def add_iface_route(self, target: str, iface: str, host: bool = True) -> bool: ...

    @abstractmethod
    def setup_dns_resolver(
        self, domains: list[str], nameservers: list[str],
        interface: str = "",
    ) -> dict[str, bool]: ...

    @abstractmethod
    def cleanup_dns_resolver(self, domains: list[str], interface: str = "") -> None: ...

    @abstractmethod
    def disable_ipv6(self) -> bool: ...

    @abstractmethod
    def restore_ipv6(self) -> bool: ...

    @abstractmethod
    def delete_host_route(self, ip: str) -> bool: ...

    @abstractmethod
    def delete_net_route(self, network: str) -> bool: ...

    @abstractmethod
    def route_table(self, lines: int | None = None) -> str: ...

    @abstractmethod
    def iface_info(self, name: str) -> str: ...

    def resolve_host(self, hostname: str) -> list[str]:
        """Resolve hostname to IPs (dig -> host -> getent fallback)."""
        if shutil.which("dig"):
            r = _run(["dig", "+short", hostname])
            if r.returncode == 0 and r.stdout.strip():
                ips = []
                for line in r.stdout.strip().splitlines():
                    line = line.strip()
                    if re.match(r"\d+\.\d+\.\d+\.\d+$", line):
                        ips.append(line)
                if ips:
                    return ips

        if shutil.which("host"):
            r = _run(["host", hostname])
            if r.returncode == 0:
                ips = []
                for line in r.stdout.splitlines():
                    if "has address" in line:
                        ips.append(line.split()[-1])
                if ips:
                    return ips

        if shutil.which("getent"):
            r = _run(["getent", "ahosts", hostname])
            if r.returncode == 0:
                for line in r.stdout.splitlines():
                    if "STREAM" in line:
                        return [line.split()[0]]

        return []


# ---------------------------------------------------------------------------
# Darwin (macOS)
# ---------------------------------------------------------------------------

class DarwinNet(NetManager):
    def default_gateway(self) -> Optional[str]:
        r = _run(["route", "-n", "get", "default"])
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                if "gateway:" in line:
                    return line.split("gateway:")[-1].strip()
        return None

    def interfaces(self) -> dict[str, str]:
        result: dict[str, str] = {}
        r = _run(["ifconfig", "-l"])
        if r.returncode != 0:
            return result
        for iface in r.stdout.strip().split():
            r2 = _run(["ifconfig", iface])
            for line in r2.stdout.splitlines():
                if "inet " in line:
                    parts = line.strip().split()
                    try:
                        idx = parts.index("inet")
                        result[iface] = parts[idx + 1]
                    except (ValueError, IndexError):
                        pass
                    break
        return result

    def check_interface(self, name: str) -> bool:
        r = _run(["ifconfig", name])
        return r.returncode == 0

    def add_host_route(self, ip: str, gateway: str) -> bool:
        r = _run(["sudo", "route", "add", "-host", ip, gateway])
        return r.returncode == 0

    def add_net_route(self, network: str, gateway: str) -> bool:
        r = _run(["sudo", "route", "add", "-net", network, gateway])
        return r.returncode == 0

    def add_iface_route(self, target: str, iface: str, host: bool = True) -> bool:
        flag = "-host" if host else "-net"
        r = _run(["sudo", "route", "add", flag, target, "-interface", iface])
        return r.returncode == 0

    def setup_dns_resolver(
        self, domains: list[str], nameservers: list[str],
        interface: str = "",
    ) -> dict[str, bool]:
        # macOS uses /etc/resolver/ files - interface is not needed
        resolver_dir = cfg.paths.resolver_dir
        _run(["sudo", "mkdir", "-p", resolver_dir])
        content = "\n".join(f"nameserver {ns}" for ns in nameservers) + "\n"
        results: dict[str, bool] = {}
        for domain in domains:
            r = _run(
                ["sudo", "tee", f"{resolver_dir}/{domain}"],
                input=content,
            )
            results[domain] = r.returncode == 0
        return results

    def cleanup_dns_resolver(self, domains: list[str], interface: str = "") -> None:
        resolver_dir = cfg.paths.resolver_dir
        files = [f"{resolver_dir}/{d}" for d in domains]
        _run(["sudo", "rm", "-f"] + files)

    def _active_network_services(self) -> list[str]:
        """Discover active network services (Wi-Fi, Ethernet, etc.)."""
        r = _run(["networksetup", "-listallnetworkservices"])
        if r.returncode != 0:
            return [cfg.defaults.network_service]
        services = []
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("*") or not line or line.startswith("An asterisk"):
                continue
            services.append(line)
        return services or [cfg.defaults.network_service]

    def disable_ipv6(self) -> bool:
        ok = True
        for svc in self._active_network_services():
            r = _run(["sudo", "networksetup", "-setv6off", svc])
            if r.returncode != 0:
                ok = False
        return ok

    def restore_ipv6(self) -> bool:
        ok = True
        for svc in self._active_network_services():
            r = _run(["sudo", "networksetup", "-setv6automatic", svc])
            if r.returncode != 0:
                ok = False
        return ok

    def delete_host_route(self, ip: str) -> bool:
        r = _run(["sudo", "route", "delete", "-host", ip])
        return r.returncode == 0

    def delete_net_route(self, network: str) -> bool:
        r = _run(["sudo", "route", "delete", "-net", network])
        return r.returncode == 0

    def route_table(self, lines: int | None = None) -> str:
        if lines is None:
            lines = cfg.display.route_table_lines
        r = _run(["netstat", "-rn"])
        if r.returncode == 0:
            return "\n".join(r.stdout.splitlines()[:lines])
        return ""

    def iface_info(self, name: str) -> str:
        r = _run(["ifconfig", name])
        return r.stdout if r.returncode == 0 else ""


# ---------------------------------------------------------------------------
# Linux
# ---------------------------------------------------------------------------

class LinuxNet(NetManager):
    def default_gateway(self) -> Optional[str]:
        r = _run(["ip", "route", "show", "default"])
        if r.returncode == 0:
            parts = r.stdout.strip().split()
            if "via" in parts:
                idx = parts.index("via")
                if idx + 1 < len(parts):
                    return parts[idx + 1]
        return None

    def interfaces(self) -> dict[str, str]:
        result: dict[str, str] = {}
        r = _run(["ip", "-br", "addr"])
        if r.returncode != 0:
            return result
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                iface = parts[0]
                addr = parts[2].split("/")[0] if "/" in parts[2] else parts[2]
                result[iface] = addr
        return result

    def check_interface(self, name: str) -> bool:
        r = _run(["ip", "link", "show", name])
        return r.returncode == 0

    def add_host_route(self, ip: str, gateway: str) -> bool:
        r = _run(["sudo", "ip", "route", "add", f"{ip}/32", "via", gateway])
        return r.returncode == 0

    def add_net_route(self, network: str, gateway: str) -> bool:
        r = _run(["sudo", "ip", "route", "add", network, "via", gateway])
        return r.returncode == 0

    def add_iface_route(self, target: str, iface: str, host: bool = True) -> bool:
        t = f"{target}/32" if host else target
        r = _run(["sudo", "ip", "route", "add", t, "dev", iface])
        return r.returncode == 0

    def setup_dns_resolver(
        self, domains: list[str], nameservers: list[str],
        interface: str = "",
    ) -> dict[str, bool]:
        results: dict[str, bool] = {}
        iface = interface or "ppp0"
        if shutil.which("resolvectl"):
            r = _run(["ip", "link", "show", iface])
            if r.returncode == 0:
                _run(["sudo", "resolvectl", "dns", iface] + nameservers)
                for domain in domains:
                    r3 = _run(["sudo", "resolvectl", "domain", iface, domain])
                    results[domain] = r3.returncode == 0
                return results
        for domain in domains:
            results[domain] = False
        return results

    def cleanup_dns_resolver(self, domains: list[str], interface: str = "") -> None:
        iface = interface or "ppp0"
        if shutil.which("resolvectl"):
            _run(["sudo", "resolvectl", "revert", iface])

    def disable_ipv6(self) -> bool:
        r = _run(["sudo", "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"])
        return r.returncode == 0

    def restore_ipv6(self) -> bool:
        r = _run(["sudo", "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=0"])
        return r.returncode == 0

    def delete_host_route(self, ip: str) -> bool:
        r = _run(["sudo", "ip", "route", "del", f"{ip}/32"])
        return r.returncode == 0

    def delete_net_route(self, network: str) -> bool:
        r = _run(["sudo", "ip", "route", "del", network])
        return r.returncode == 0

    def route_table(self, lines: int | None = None) -> str:
        if lines is None:
            lines = cfg.display.route_table_lines
        r = _run(["ip", "route"])
        if r.returncode == 0:
            return "\n".join(r.stdout.splitlines()[:lines])
        r = _run(["netstat", "-rn"])
        if r.returncode == 0:
            return "\n".join(r.stdout.splitlines()[:lines])
        return ""

    def iface_info(self, name: str) -> str:
        r = _run(["ip", "addr", "show", name])
        if r.returncode == 0:
            return r.stdout
        r = _run(["ifconfig", name])
        return r.stdout if r.returncode == 0 else ""


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def create() -> NetManager:
    system = platform.system()
    if system == "Darwin":
        return DarwinNet()
    if system != "Linux":
        import warnings
        warnings.warn(
            f"Unsupported OS '{system}', using Linux networking as fallback",
            stacklevel=2,
        )
    return LinuxNet()
