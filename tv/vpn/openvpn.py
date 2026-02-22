"""OpenVPN connection with Tunnelblick detection."""

from __future__ import annotations

import time
from pathlib import Path

from tv import proc, ui
from tv.app_config import cfg
from tv.vpn.base import ConfigParam, TunnelPlugin, VPNResult
from tv.vpn.registry import register


@register("openvpn")
class OpenVPNPlugin(TunnelPlugin):
    """OpenVPN tunnel plugin with Tunnelblick detection."""

    process_names = ["openvpn"]
    kill_patterns = [
        "openvpn --config .*/tunnelvault/",
        "openvpn.*--log /tmp/openvpn",
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
            def check_init() -> bool:
                # Log is root-owned (created by openvpn daemon), need sudo
                r = proc.run(
                    ["grep", "-q", "Initialization Sequence Completed", str(log_path)],
                    sudo=True,
                )
                return r.returncode == 0

            if proc.wait_for("OpenVPN", check_init, cfg.timeouts.openvpn_init, self.log):
                ui.ok("OpenVPN подключен")
                self.log.log("INFO", "OpenVPN подключен")

                # Extra routes/DNS from TOML (beyond what .ovpn pushes)
                self.add_routes()
                self.setup_dns()

                self.log.log("INFO", f"Маршруты после OpenVPN:\n{self.net.route_table()}")
                return VPNResult(ok=True, pid=pid)

        # --- Failed ---
        ui.fail("OpenVPN не подключился")
        self.log.log("ERROR", f"OpenVPN не подключился за {cfg.timeouts.openvpn_init}с")

        # Show error details
        r = proc.run(["tail", "-20", str(log_path)], sudo=True)
        if r.stdout.strip():
            self.log.log_lines("ERROR", r.stdout)
            tail_lines = r.stdout.strip().splitlines()[-5:]
            ui.show_log_tail("Лог OpenVPN:", tail_lines, f"sudo cat {log_path}")
        else:
            print(f"  {ui.YELLOW}└─{ui.NC} Лог пуст. {ui.DIM}sudo cat {log_path}{ui.NC}")

        return VPNResult(ok=False)

    def _kill_by_pattern(self) -> None:
        config_path = self.script_dir / self.cfg.config_file
        proc.kill_pattern(f"openvpn --config {config_path}", sudo=True)
        log_path = self._default_log_path()
        proc.kill_pattern(f"openvpn.*--log {log_path}", sudo=True)
