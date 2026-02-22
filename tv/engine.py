"""Engine: lifecycle orchestration for tunnel connections."""

from __future__ import annotations

import time
from collections import defaultdict
from pathlib import Path
from typing import Callable, Optional

from tv import config, ui, disconnect, checks, proc
from tv.app_config import cfg
from tv.disconnect import get_vpn_server_routes
from tv import defaults as defaults_mod
from tv.logger import Logger
from tv.net import NetManager, create as create_net
from tv.vpn.base import TunnelConfig, TunnelPlugin, VPNResult
from tv.vpn.registry import get_plugin


class Engine:
    """Lifecycle orchestration for multi-VPN connections.

    Usage:
        engine = Engine(script_dir, defs)
        engine.prepare()      # parse tunnels, resolve config
        engine.setup()        # cleanup, IPv6, VPN server routes
        engine.connect_all()  # connect tunnels
        results, ext_ip = engine.check_all()  # health checks
    """

    def __init__(
        self,
        script_dir: Path,
        defs: dict,
        *,
        debug: bool = False,
        net: Optional[NetManager] = None,
        log: Optional[Logger] = None,
    ) -> None:
        self.script_dir = script_dir
        self.defs = defs
        self.net = net or create_net()
        self.log = log or Logger(script_dir / cfg.paths.main_log, debug=debug)
        self.tunnels: list[TunnelConfig] = []
        self.plugins: list[TunnelPlugin] = []
        self.results: list[VPNResult] = []
        self._hooks: dict[str, list[Callable]] = defaultdict(list)

    # --- Hooks ---

    def on(self, event: str, fn: Callable) -> None:
        """Register lifecycle hook.

        Events: pre_connect, post_connect, pre_disconnect, post_disconnect,
                on_check_fail, on_all_checks_done.
        """
        self._hooks[event].append(fn)

    def _fire(self, event: str, **ctx) -> None:
        """Fire all hooks for an event."""
        for fn in self._hooks.get(event, []):
            fn(**ctx)

    # --- Lifecycle ---

    def prepare(self) -> None:
        """Load tunnels, resolve configs, save settings.

        Safe to call multiple times (resets state).
        """
        self.tunnels = []
        self.plugins = []
        self.results = []
        self.tunnels = defaults_mod.parse_tunnels(self.defs)
        saved = config.load_settings(self.script_dir)
        print()

        for tcfg in self.tunnels:
            plugin_cls = get_plugin(tcfg.type)
            schema = plugin_cls.config_schema()
            if schema:
                ui.section(f"Параметры: {tcfg.name}")
                print()
                config.resolve_tunnel_params(tcfg, plugin_cls, saved, self.script_dir)
                print()

            # Resolve routes (targets → networks/hosts/dns)
            config.resolve_tunnel_routes(tcfg, saved)

        # Validate config_file uniqueness after resolution
        # (ENV/saved may have overridden auto-applied defaults)
        defaults_mod.validate_config_files(self.tunnels)

        config.save_tunnel_settings(self.tunnels, self.script_dir)
        print()

    def setup(self) -> None:
        """Pre-connection setup: cleanup, IPv6, VPN server routes, clean logs."""
        ui.info("🧹 Отключаю предыдущие подключения...")
        self.log.log("INFO", "--- Очистка предыдущих подключений ---")
        disconnect.run(self.net, self.log, self.defs)
        time.sleep(cfg.timeouts.cleanup_sleep)

        ui.info("🌐 Отключаю IPv6...")
        self.log.log("INFO", "--- Отключение IPv6 ---")
        ipv6_ok = self.net.disable_ipv6()
        self.log.log(
            "INFO" if ipv6_ok else "WARN",
            f"IPv6 {'отключен' if ipv6_ok else 'не удалось отключить'}",
        )

        self._setup_vpn_server_routes()

        # Clean old log files
        log_files = [Path(t.log) for t in self.tunnels if t.log]
        if log_files:
            proc.run(["rm", "-f"] + [str(f) for f in log_files], sudo=True)
            self.log.log("INFO", "Логи VPN очищены")

    def connect_all(self) -> None:
        """Connect all tunnels sequentially.

        Safe to call multiple times (resets plugins/results).
        """
        self.plugins = []
        self.results = []
        total = len(self.tunnels)
        for i, tcfg in enumerate(self.tunnels, 1):
            plugin_cls = get_plugin(tcfg.type)
            plugin = plugin_cls(tcfg, self.net, self.log, self.script_dir)
            self.plugins.append(plugin)

            self._fire("pre_connect", tunnel=tcfg, plugin=plugin, index=i, total=total)

            ui.step(i, total, plugin.display_name, tcfg.name)
            self.log.log("INFO", f"=== [{i}/{total}] {plugin.display_name} ({tcfg.name}) ===")

            result = plugin.connect()
            self.results.append(result)

            self._fire("post_connect", tunnel=tcfg, plugin=plugin, result=result, index=i, total=total)

    def check_all(self) -> tuple[list[checks.CheckResult], str]:
        """Run health checks for all connected tunnels."""
        check_input = [
            (tcfg.name, r.ok, tcfg.checks)
            for tcfg, r in zip(self.tunnels, self.results)
        ]
        results, ext_ip = checks.run_all_from_tunnels(check_input, logger=self.log)

        failed = [r for r in results if r.status == "fail"]
        if failed:
            self._fire("on_check_fail", failed=failed, all_results=results)
        self._fire("on_all_checks_done", results=results, ext_ip=ext_ip)

        return results, ext_ip

    def disconnect_all(self) -> None:
        """Disconnect all tunnels in reverse order.

        Errors in one tunnel don't prevent cleanup of remaining tunnels.
        """
        for plugin, tcfg in zip(reversed(self.plugins), reversed(self.tunnels)):
            self._fire("pre_disconnect", tunnel=tcfg, plugin=plugin)
            try:
                plugin.disconnect()
            except Exception as e:
                self.log.log("WARN", f"disconnect {tcfg.name}: {e}")
            try:
                plugin.delete_routes()
            except Exception as e:
                self.log.log("WARN", f"delete_routes {tcfg.name}: {e}")
            try:
                plugin.cleanup_dns()
            except Exception as e:
                self.log.log("WARN", f"cleanup_dns {tcfg.name}: {e}")
            self._fire("post_disconnect", tunnel=tcfg, plugin=plugin)

        self.net.restore_ipv6()

    def _setup_vpn_server_routes(self) -> None:
        """Add host routes to VPN servers through the default gateway."""
        routes_cfg = get_vpn_server_routes(self.defs)

        static_hosts = routes_cfg.get("hosts", [])
        resolve_hosts = routes_cfg.get("resolve", [])

        gw = self.net.default_gateway()
        if not gw:
            ui.fail("Не удалось определить default gateway")
            self.log.log("ERROR", "default gateway не найден")
            return

        self.log.log("INFO", f"--- Host routes через GW={gw} ---")
        ui.info(f"🔌 Host routes через {ui.YELLOW}{gw}{ui.NC}")

        for hostname in resolve_hosts:
            for ip in self.net.resolve_host(hostname):
                ok = self.net.add_host_route(ip, gw)
                self.log.log(
                    "INFO" if ok else "WARN",
                    f"route add {ip} ({hostname}) → {gw} {'OK' if ok else 'FAIL'}",
                )

        for static_ip in static_hosts:
            ok = self.net.add_host_route(static_ip, gw)
            self.log.log(
                "INFO" if ok else "WARN",
                f"route add {static_ip} {'OK' if ok else 'FAIL'}",
            )
