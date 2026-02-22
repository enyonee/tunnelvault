#!/usr/bin/env python3
"""tunnelvault - multi-VPN connection manager.

Подключает VPN-туннели (OpenVPN, FortiVPN, sing-box и др.) с правильной
маршрутизацией и проверяет доступность всех сервисов.

Использование:
    python3 tunnelvault.py                  - интерактивный wizard
    python3 tunnelvault.py --disconnect     - отключить всё

Приоритет конфигурации: defaults.toml -> ENV -> .vpn-settings.json -> wizard
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import traceback
from pathlib import Path

from tv import config, ui, disconnect
from tv import defaults as defaults_mod
from tv.app_config import cfg
from tv.engine import Engine
from tv.logger import Logger
# Ensure all plugins are registered on import
from tv.vpn import openvpn, fortivpn, singbox  # noqa: F401


_log: Logger | None = None  # module-level for crash handler


def main() -> None:
    global _log
    args = config.parse_args()
    script_dir = Path(__file__).parent.resolve()
    defs = defaults_mod.load(script_dir)

    # CLI --log-level overrides config
    if args.log_level:
        cfg.logging.level = args.log_level

    # --- Disconnect-only mode (no Engine needed, net created inside) ---
    if args.disconnect:
        tunnels = defaults_mod.parse_tunnels(defs)
        if tunnels:
            disconnect.run_plugins(tunnels, defs=defs)
        else:
            disconnect.run(defs=defs)
        return

    # --- Engine ---
    engine = Engine(script_dir, defs, debug=args.debug)
    _log = engine.log

    # --- Signal handlers ---
    def on_signal(sig: int, _frame) -> None:
        name = signal.Signals(sig).name
        print(f"\n  {ui.YELLOW}{ui.BOLD}⚠ Прервано ({name}){ui.NC}", file=sys.stderr)
        engine.log.log("WARN", f"Прервано по {name}")
        print(f"  {ui.DIM}Очистка VPN-процессов...{ui.NC}", file=sys.stderr)
        try:
            engine.disconnect_all()
        except Exception:
            # Fallback: emergency killall if engine state is broken
            try:
                disconnect.run(engine.net, engine.log, defs)
            except Exception:
                pass
        print(f"  {ui.DIM}Лог: {engine.log.log_path}{ui.NC}", file=sys.stderr)
        sys.exit(128 + sig)

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    # --- Start ---
    ui.logo()

    engine.log.log("INFO", "=" * 40)
    engine.log.log("INFO", f"tunnelvault запущен (PID={os.getpid()})")
    engine.log.log("INFO", f"Командная строка: {' '.join(sys.argv)}")
    engine.log.log_env(engine.net, script_dir)

    engine.prepare()
    engine.setup()
    engine.connect_all()
    check_results, ext_ip = engine.check_all()

    # --- Summary ---
    _log_summary(engine, check_results, ext_ip)


def _log_summary(engine: Engine, check_results: list, ext_ip: str) -> None:
    """Log results and print summary."""
    engine.log.log("INFO", "=== Итог ===")
    for tcfg, r in zip(engine.tunnels, engine.results):
        engine.log.log("INFO", f"{tcfg.name}: ok={r.ok}")
    engine.log.log("INFO", f"Лог: {engine.log.log_path}")
    engine.log.log("INFO", "=" * 40)

    summary_tunnels = []
    for tcfg, r in zip(engine.tunnels, engine.results):
        detail = r.detail or ("up" if r.ok else "не подключен")
        if tcfg.type == "openvpn" and r.ok and ext_ip:
            detail = detail if detail != "up" else ext_ip
        summary_tunnels.append((tcfg.name, r.ok, detail))

    log_paths = {}
    for tcfg in engine.tunnels:
        if tcfg.log:
            log_paths[tcfg.name] = tcfg.log
    log_paths["debug"] = str(engine.log.log_path)

    ui.print_summary(
        tunnels=summary_tunnels,
        checks=[(r.label, r.status, r.detail) for r in check_results],
        log_paths=log_paths,
    )


def _crash_diagnostics(log: Logger | None, exc: BaseException) -> None:
    """Log crash state for post-mortem debugging."""
    print(f"\n  {ui.RED}{ui.BOLD}💥 Скрипт упал{ui.NC}", file=sys.stderr)
    print(f"  {ui.RED}├─ {type(exc).__name__}: {exc}{ui.NC}", file=sys.stderr)
    if log:
        print(f"  {ui.RED}└─ Лог: {log.log_path}{ui.NC}", file=sys.stderr)
        log.log("FATAL", f"{type(exc).__name__}: {exc}")
        log.log("FATAL", traceback.format_exc())
        from tv.vpn.registry import available_types, get_plugin
        vpn_keywords = []
        for t in available_types():
            vpn_keywords.extend(get_plugin(t).process_names)

        r = subprocess.run(["ps", "aux"], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            if any(kw in line for kw in vpn_keywords):
                log.log("FATAL", f"  {line.strip()}")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except BaseException as e:
        _crash_diagnostics(_log, e)
        sys.exit(1)
