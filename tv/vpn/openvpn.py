"""OpenVPN connection with Tunnelblick detection."""

from __future__ import annotations

import time

from pathlib import Path

from tv import proc, ui
from tv.app_config import cfg
from tv.logger import Logger
from tv.vpn.base import ConfigParam, TunnelPlugin, VPNResult
from tv.vpn.registry import register


def _show_error(pid: int | None, log_path: Path, log: Logger) -> None:
    """Display OpenVPN error details to user and log."""
    ui.fail(f"OpenVPN не подключился за {cfg.timeouts.openvpn_init}с")
    log.log("ERROR", f"OpenVPN не подключился за {cfg.timeouts.openvpn_init}с")

    details: list[tuple[str, str]] = []
    if pid and proc.is_alive(pid):
        details.append(("", f"Процесс жив (PID={pid}), но интерфейс не появился"))
        log.log("WARN", f"Процесс OpenVPN PID={pid} жив, но интерфейс не появился")
    elif pid:
        details.append(("", f"Процесс завершился (PID={pid})"))
        log.log("ERROR", f"Процесс OpenVPN PID={pid} завершился")
    else:
        details.append(("", "PID не найден после запуска"))
        log.log("ERROR", "OpenVPN PID не найден после запуска")

    details.append(("", f"Лог: cat {log_path}"))
    ui.error_tree(details)


@register("openvpn")
class OpenVPNPlugin(TunnelPlugin):
    """OpenVPN tunnel plugin with Tunnelblick detection."""

    process_names = ["openvpn"]
    kill_patterns = [
        "openvpn --config .*/tunnelvault/",
    ]

    @classmethod
    def discover_pid(cls, tcfg, script_dir) -> int | None:
        config_path = script_dir / tcfg.config_file
        pids = proc.find_pids(f"openvpn --config {config_path}")
        return pids[0] if pids else None

    @classmethod
    def config_schema(cls) -> list[ConfigParam]:
        return [
            ConfigParam("config_file", "OpenVPN конфиг", default=cfg.defaults.openvpn_config,
                         env_var="VPN_OVPN_CONFIG", target="config_file"),
        ]

    @property
    def process_name(self) -> str:
        return "openvpn"

    @property
    def display_name(self) -> str:
        return "OpenVPN"

    def connect(self) -> VPNResult:
        config_path = self.script_dir / self.cfg.config_file
        log_path = self._default_log_path()

        self.log.log("INFO", f"Конфиг: {config_path}")

        # --- Tunnelblick detection ---
        if proc.find_pids("Tunnelblick"):
            tb_ovpn = proc.find_pids("Tunnelblick.*openvpn")
            if tb_ovpn:
                pid = tb_ovpn[0]
                ui.warn(f"Tunnelblick OpenVPN активен (PID={pid}), пропускаю свой OpenVPN")
                self.log.log("WARN", f"Tunnelblick openvpn PID={pid}, пропускаем запуск")
                ui.ok(f"OpenVPN подключен {ui.DIM}(Tunnelblick){ui.NC}")
                self.log.log("INFO", "OpenVPN: используем Tunnelblick")
                return VPNResult(ok=True, detail="Tunnelblick")

        # Snapshot interfaces BEFORE connect (for tun detection)
        ifaces_before = set(self.net.interfaces().keys())

        # --- Launch ---
        self.log.log("INFO", f"Запуск: sudo openvpn --config {config_path} --daemon --log {log_path}")
        proc.run(
            ["openvpn", "--config", str(config_path), "--daemon", "--log", str(log_path)],
            sudo=True,
        )
        time.sleep(0.5)

        # Find PID (openvpn --daemon forks, parent exits immediately)
        pids = proc.find_pids(f"openvpn --config {config_path}")
        pid = pids[0] if pids else None
        self._pid = pid

        if pid:
            detected_iface = None

            def _check_new_tun():
                nonlocal detected_iface
                ifaces_now = set(self.net.interfaces().keys())
                new_tun = [
                    i for i in (ifaces_now - ifaces_before)
                    if i.startswith("tun") or i.startswith("utun")
                ]
                if new_tun:
                    detected_iface = sorted(new_tun)[0]
                    return True
                return False

            if proc.wait_for("OpenVPN", _check_new_tun, cfg.timeouts.openvpn_init, self.log):
                if not self.cfg.interface:
                    self.cfg.interface = detected_iface

                ui.ok(f"OpenVPN подключен ({detected_iface})")
                self.log.log("INFO", f"OpenVPN подключен ({detected_iface})")

                # Extra routes/DNS from TOML (beyond what .ovpn pushes)
                self.add_routes()
                self.setup_dns()

                self.log.log("INFO", f"Маршруты после OpenVPN:\n{self.net.route_table()}")
                return VPNResult(ok=True, pid=pid)

        # --- Failed ---
        _show_error(pid, log_path, self.log)
        return VPNResult(ok=False)

    def _kill_by_pattern(self) -> None:
        config_path = self.script_dir / self.cfg.config_file
        proc.kill_pattern(f"openvpn --config {config_path}", sudo=True)
        log_path = self._default_log_path()
        proc.kill_pattern(f"openvpn.*--log {log_path}", sudo=True)
