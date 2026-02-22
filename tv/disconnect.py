"""Disconnect all VPN connections and clean up."""

from __future__ import annotations

import glob
import os
import sys
from typing import TYPE_CHECKING, Optional

from tv import proc
from tv.app_config import cfg

if TYPE_CHECKING:
    from tv.logger import Logger
    from tv.net import NetManager


def _safe(fn, description: str, log: Optional[Logger] = None) -> None:
    """Run fn, swallow exceptions so cleanup continues."""
    try:
        fn()
    except Exception as e:
        print(f"  ⚠ {description}: {e}", file=sys.stderr)
        if log:
            log.log("WARN", f"Disconnect: {description}: {e}")


def get_vpn_server_routes(defs: dict) -> dict:
    """Extract VPN server routes config from defs (supports both formats)."""
    if "global" in defs:
        return defs.get("global", {}).get("vpn_server_routes", {})
    return defs.get("routes", {}).get("vpn_servers", {})


def _cleanup_routes_and_ipv6(
    net: NetManager,
    log: Optional[Logger],
    defs: dict,
) -> None:
    """Shared cleanup: VPN server routes + IPv6 restore."""
    routes_cfg = get_vpn_server_routes(defs)
    static_hosts = routes_cfg.get("hosts", [])
    resolve_hosts = routes_cfg.get("resolve", [])

    if static_hosts or resolve_hosts:
        print("🧹 Удаляю маршруты...")
        for ip in static_hosts:
            _safe(lambda ip=ip: net.delete_host_route(ip), f"del route {ip}", log)
        for hostname in resolve_hosts:
            _safe(
                lambda h=hostname: [net.delete_host_route(ip) for ip in net.resolve_host(h)],
                f"del resolved {hostname}", log,
            )

    print("🌐 Восстанавливаю IPv6...")
    _safe(lambda: net.restore_ipv6(), "restore IPv6", log)

    print("✅ Всё отключено")
    if log:
        log.log("INFO", "Disconnect завершён")


def run(
    net: Optional[NetManager] = None,
    log: Optional[Logger] = None,
    defs: Optional[dict] = None,
) -> None:
    """Emergency cleanup: kill VPN processes via plugin registry and clean routing.

    Used for:
    - Initial cleanup before starting tunnels (processes from previous run)
    - Signal handler cleanup (SIGINT/SIGTERM)
    - Fallback when tunnel configs are not available

    Process names come from plugin registry (process_names class attr).
    For structured disconnect with plugin awareness, use run_plugins().
    """
    if net is None:
        from tv.net import create
        net = create()

    if defs is None:
        defs = {}

    # Kill all known VPN processes via plugin registry
    from tv.vpn.registry import available_types, get_plugin
    for type_name in available_types():
        plugin_cls = get_plugin(type_name)
        for pname in plugin_cls.process_names:
            print(f"🔌 Отключаю {pname}...")
            _safe(lambda p=pname: proc.killall(p, sudo=True), f"kill {pname}", log)
        for pattern in plugin_cls.kill_patterns:
            _safe(lambda p=pattern: proc.kill_pattern(p, sudo=True), f"kill pattern {pattern}", log)

    # Clean up FortiVPN temp configs containing passwords
    for conf in glob.glob(f"{cfg.paths.temp_dir}/forti_*.conf"):
        try:
            os.unlink(conf)
        except OSError:
            pass

    _cleanup_routes_and_ipv6(net, log, defs)


def _discover_pid(tcfg, plugin_cls, script_dir) -> Optional[int]:
    """Best-effort PID discovery for disconnect without engine context.

    Delegates to plugin's discover_pid() classmethod.
    """
    try:
        return plugin_cls.discover_pid(tcfg, script_dir)
    except Exception:
        return None


def run_plugins(
    tunnels: list,
    net: Optional[NetManager] = None,
    log: Optional[Logger] = None,
    defs: Optional[dict] = None,
) -> None:
    """Plugin-driven disconnect: iterate tunnels in reverse order."""
    from pathlib import Path
    from tv.vpn.registry import get_plugin

    if net is None:
        from tv.net import create
        net = create()

    if defs is None:
        defs = {}

    script_dir = Path(__file__).parent.parent

    # Disconnect tunnels in reverse order
    for tcfg in reversed(tunnels):
        plugin_cls = get_plugin(tcfg.type)
        plugin = plugin_cls(tcfg, net, log or _null_logger(), script_dir)

        # Best-effort PID recovery (no engine context)
        plugin._pid = _discover_pid(tcfg, plugin_cls, script_dir)

        print(f"🔌 Отключаю {plugin.display_name}...")
        _safe(lambda p=plugin: p.disconnect(), f"disconnect {tcfg.name}", log)
        _safe(lambda p=plugin: p.delete_routes(), f"del routes {tcfg.name}", log)
        _safe(lambda p=plugin: p.cleanup_dns(), f"cleanup dns {tcfg.name}", log)

    _cleanup_routes_and_ipv6(net, log, defs)


def _null_logger():
    """Minimal stub when no logger is available."""

    class _NullLogger:
        log_path = None
        def log(self, *a, **kw):
            pass
        def log_lines(self, *a, **kw):
            pass

    return _NullLogger()


if __name__ == "__main__":
    run()
