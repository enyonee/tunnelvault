"""FortiVPN (openfortivpn) connection with PPP gateway detection."""

from __future__ import annotations

import os
import platform
import re
import time
from pathlib import Path

from tv import proc, ui
from tv.app_config import cfg
from tv.logger import Logger
from tv.net import NetManager
from tv.vpn.base import ConfigParam, TunnelPlugin, VPNResult
from tv.vpn.registry import register

_IP_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")


def _detect_ppp_gateway(log_path: Path, net: NetManager, interface: str = "ppp0") -> str:
    """Detect PPP peer gateway from forti log, then ifconfig fallback."""
    keywords = ("remote ip address", "ppp gateway", "peer")

    for _ in range(cfg.timeouts.fortivpn_gw_attempts):
        try:
            content = log_path.read_text()
            for line in content.splitlines():
                if any(kw in line.lower() for kw in keywords):
                    m = _IP_RE.search(line)
                    if m:
                        return m.group(1)
        except OSError:
            pass
        time.sleep(cfg.timeouts.fortivpn_gw_poll)

    # Fallback: parse ifconfig for the detected interface
    info = net.iface_info(interface)
    if not info:
        return ""

    if platform.system() == "Darwin":
        for line in info.splitlines():
            if "inet " in line:
                parts = line.split()
                # macOS: inet X.X.X.X --> Y.Y.Y.Y
                if "-->" in parts:
                    idx = parts.index("-->")
                    if idx + 1 < len(parts):
                        return parts[idx + 1]
                # Older: inet X.X.X.X Y.Y.Y.Y (4th field = peer)
                if len(parts) >= 4:
                    return parts[3]
    else:
        m = re.search(r"P-t-P:(\d+\.\d+\.\d+\.\d+)", info)
        if m:
            return m.group(1)
        m = re.search(r"peer (\d+\.\d+\.\d+\.\d+)", info)
        if m:
            return m.group(1)

    return ""


def _show_error(forti_proc, forti_log: Path, log: Logger, label: str = "ppp") -> None:
    """Display FortiVPN error details to user and log."""
    ui.fail(f"FortiVPN не поднялся за {cfg.timeouts.fortivpn_ppp}с")
    log.log("ERROR", f"FortiVPN не поднялся за {cfg.timeouts.fortivpn_ppp}с")

    pid = forti_proc.pid
    if proc.is_alive(pid):
        print(f"  {ui.YELLOW}├─{ui.NC} Процесс жив (PID={pid}), но {label} не появился")
        log.log("WARN", f"Процесс FortiVPN PID={pid} жив, но {label} не появился")
    else:
        rc = forti_proc.poll()
        rc_display = rc if rc is not None else "?"
        print(f"  {ui.RED}├─{ui.NC} Процесс завершился с кодом: {ui.RED}{ui.BOLD}{rc_display}{ui.NC}")
        log.log("ERROR", f"Процесс FortiVPN завершился с кодом {rc}")

    # Show log to user
    try:
        content = forti_log.read_text()
        if content.strip():
            log.log_lines("ERROR", content)
            tail = content.strip().splitlines()[-15:]
            ui.show_log_tail("Лог openfortivpn:", tail, f"cat {forti_log}")
        else:
            print(f"  {ui.YELLOW}├─{ui.NC} Лог пуст (openfortivpn упал мгновенно)")
            print(f"  {ui.YELLOW}└─{ui.NC} Полный лог: {ui.DIM}cat {forti_log}{ui.NC}")
    except OSError:
        print(f"  {ui.YELLOW}├─{ui.NC} Лог недоступен")
        print(f"  {ui.YELLOW}└─{ui.NC} Полный лог: {ui.DIM}cat {forti_log}{ui.NC}")


@register("fortivpn")
class FortiVPNPlugin(TunnelPlugin):
    """FortiVPN tunnel plugin with PPP gateway detection.

    Handles routes through PPP interface and DNS resolver setup.
    """

    process_names = ["openfortivpn"]
    kill_patterns = ["sudo openfortivpn"]

    @classmethod
    def discover_pid(cls, tcfg, script_dir) -> int | None:
        conf_path = f"{cfg.paths.temp_dir}/forti_{tcfg.name}.conf"
        pids = proc.find_pids(f"openfortivpn -c {conf_path}")
        return pids[0] if pids else None

    @classmethod
    def config_schema(cls) -> list[ConfigParam]:
        return [
            ConfigParam("host", "Хост", required=True, env_var="VPN_FORTI_HOST", target="auth"),
            ConfigParam("port", "Порт", default=cfg.defaults.fortivpn_port, env_var="VPN_FORTI_PORT", target="auth"),
            ConfigParam("login", "Логин", required=True, env_var="VPN_FORTI_LOGIN", target="auth"),
            ConfigParam("pass", "Пароль", required=True, secret=True, env_var="VPN_FORTI_PASS", target="auth"),
            ConfigParam("cert_mode", "Сертификат (auto/manual)", default=cfg.defaults.fortivpn_cert_mode, env_var="VPN_CERT_MODE", target="auth"),
            ConfigParam("trusted_cert", "SHA256 сертификата", env_var="VPN_TRUSTED_CERT", target="auth"),
            ConfigParam("fallback_gateway", "Fallback GW", env_var="VPN_FORTI_FALLBACK_GW",
                         target="extra", prompt=False),
        ]

    @property
    def process_name(self) -> str:
        return "openfortivpn"

    @property
    def display_name(self) -> str:
        return "FortiVPN"

    def connect(self) -> VPNResult:
        auth = self.cfg.auth
        host = auth.get("host", "")
        port = auth.get("port", cfg.defaults.fortivpn_port)
        login = auth.get("login", "")
        password = auth.get("pass", "")
        trusted_cert = auth.get("trusted_cert", "")

        dns_servers = self.cfg.dns.get("nameservers", [])
        dns_domains = self.cfg.dns.get("domains", [])
        fallback_gw = self.cfg.extra.get("fallback_gateway", "")

        log_path = self._default_log_path()

        self.log.log("INFO", f"Хост: {host}:{port}  Логин: {login}")
        self.log.log("INFO", f"Cert: {trusted_cert[:24]}...")

        # Snapshot interfaces BEFORE connect (for ppp detection)
        ifaces_before = set(self.net.interfaces().keys())

        # Predictable config path (per tunnel name, not random)
        conf_path = f"{cfg.paths.temp_dir}/forti_{self.cfg.name}.conf"
        conf_fd = os.open(conf_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            conf_content = (
                f"host = {host}\n"
                f"port = {port}\n"
                f"username = {login}\n"
                f"password = {password}\n"
                f"trusted-cert = {trusted_cert}\n"
            )
            os.write(conf_fd, conf_content.encode())
        finally:
            os.close(conf_fd)
        self._conf_path = conf_path

        # Launch in background (log file created as current user)
        self.log.log("INFO", "Запуск: sudo openfortivpn -c <tmpfile> --no-routes --no-dns")
        forti_proc = proc.run_background(
            [
                "openfortivpn", "-c", conf_path,
                "--no-routes", "--no-dns",
            ],
            sudo=True,
            log_path=str(log_path),
        )
        forti_pid = forti_proc.pid
        self._pid = forti_pid
        self.log.log("INFO", f"FortiVPN PID={forti_pid}")

        # Wait for NEW ppp interface (snapshot diff, not hardcoded ppp0)
        detected_iface = None

        def _check_new_ppp():
            nonlocal detected_iface
            ifaces_now = set(self.net.interfaces().keys())
            new_ppp = [i for i in (ifaces_now - ifaces_before) if i.startswith("ppp")]
            if new_ppp:
                detected_iface = sorted(new_ppp)[0]
                return True
            return False

        if not proc.wait_for(
            f"FortiVPN ({self.cfg.name} ppp)", _check_new_ppp, cfg.timeouts.fortivpn_ppp, self.log
        ):
            _show_error(forti_proc, log_path, self.log, label="ppp interface")
            return VPNResult(ok=False, pid=forti_pid)

        ppp_iface = detected_iface
        # Store detected interface for routes/dns/cleanup
        if not self.cfg.interface:
            self.cfg.interface = ppp_iface

        # --- Connected ---
        ui.ok(f"FortiVPN подключен ({ppp_iface})")
        self.log.log("INFO", f"FortiVPN подключен ({ppp_iface})")
        self.log.log_lines("INFO", f"ifconfig {ppp_iface}:\n{self.net.iface_info(ppp_iface)}")

        # PPP gateway
        ppp_gw = _detect_ppp_gateway(log_path, self.net, interface=ppp_iface)
        if not ppp_gw:
            if fallback_gw:
                ui.warn(f"Не удалось определить PPP gateway, используем fallback: {fallback_gw}")
                self.log.log("WARN", f"PPP_GW не определён, fallback={fallback_gw}")
                ppp_gw = fallback_gw
            else:
                ui.warn("Не удалось определить PPP gateway, маршруты могут не работать")
                self.log.log("WARN", "PPP_GW не определён, fallback не задан")
                return VPNResult(ok=True, pid=forti_pid)

        print(f"  ↳ peer: {ui.YELLOW}{ppp_gw}{ui.NC}")
        self.log.log("INFO", f"PPP_GW={ppp_gw}")

        # Routes via PPP gateway (networks + hosts from config/targets)
        self.add_routes(gateway=ppp_gw)

        # Background ping to warm up
        if dns_servers:
            warmup = str(cfg.timeouts.ping_warmup)
            if platform.system() == "Darwin":
                ping_cmd = ["ping", "-c", "2", "-t", warmup, dns_servers[0]]
            else:
                ping_cmd = ["ping", "-c", "2", "-W", warmup, dns_servers[0]]
            proc.run_background(ping_cmd)
            self.log.log("INFO", f"Фоновый ping {dns_servers[0]} запущен")

        # DNS resolver
        if dns_domains and dns_servers:
            dns_iface = self.cfg.interface or ppp_iface
            results = self.net.setup_dns_resolver(dns_domains, dns_servers, dns_iface)
            for domain, ok in results.items():
                self.log.log(
                    "INFO" if ok else "WARN",
                    f"Resolver для {domain} {'создан' if ok else 'FAIL'}",
                )

        # Route snapshot
        self.log.log("INFO", f"Маршруты после FortiVPN:\n{self.net.route_table()}")

        return VPNResult(ok=True, pid=forti_pid)

    def _kill_by_pattern(self) -> None:
        conf_path = self._effective_conf_path()
        proc.kill_pattern(f"openfortivpn -c {conf_path}", sudo=True)

    def disconnect(self) -> None:
        """Kill FortiVPN + clean up temp config."""
        if not self._kill_by_pid():
            self._kill_by_pattern()
        try:
            os.unlink(self._effective_conf_path())
        except OSError:
            pass

    def _effective_conf_path(self) -> str:
        return getattr(self, "_conf_path", f"{cfg.paths.temp_dir}/forti_{self.cfg.name}.conf")
