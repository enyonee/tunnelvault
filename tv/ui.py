"""Terminal UI: colors, logo, progress, summary table."""

from __future__ import annotations

import getpass
import re
import sys
from typing import Sequence

# ANSI colors
RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
CYAN = "\033[0;36m"
BLUE = "\033[0;34m"
MAGENTA = "\033[0;35m"
BOLD = "\033[1m"
DIM = "\033[2m"
NC = "\033[0m"

from tv.app_config import cfg

_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def _visible_len(s: str) -> int:
    return len(_ANSI_RE.sub("", s))


# --- Basic messages ---

def step(n: int, total: int, title: str, desc: str) -> None:
    print(f"\n  {BOLD}[{n}/{total}] {title}{NC} - {desc}")


def section(title: str) -> None:
    print(f"\n  {CYAN}{BOLD}━━━ {title} ━━━{NC}")


def ok(msg: str) -> None:
    print(f"  {GREEN}✅ {msg}{NC}")


def fail(msg: str) -> None:
    print(f"  {RED}❌ {msg}{NC}")


def warn(msg: str) -> None:
    print(f"  {YELLOW}⚠{NC}  {msg}")


def info(msg: str) -> None:
    print(f"  {msg}")


def param_found(label: str, value: str, source: str, secret: bool = False) -> None:
    display = "****" if secret else f"{YELLOW}{value}{NC}"
    print(f"  {GREEN}✅{NC} {label}: {DIM}({source}){NC} {display}")


def param_missing(label: str) -> None:
    print(f"  {RED}—{NC}  {label}: {DIM}(не задано){NC}")


def error_tree(lines: list[tuple[str, str]]) -> None:
    """Print indented error details with tree characters (├─ / └─)."""
    for i, (icon, msg) in enumerate(lines):
        connector = "└─" if i == len(lines) - 1 else "├─"
        print(f"  {YELLOW}{connector}{NC} {msg}")


def show_log_tail(title: str, log_lines: list[str], hint: str = "") -> None:
    """Show log excerpt to user."""
    if log_lines:
        print(f"  {YELLOW}├─{NC} {title}")
        for line in log_lines:
            print(f"     │ {line}")
    else:
        print(f"  {YELLOW}├─{NC} Лог пуст")
    if hint:
        print(f"  {YELLOW}└─{NC} Полный лог: {DIM}{hint}{NC}")


# --- Interactive input ---

def wizard_input(label: str, default: str = "", secret: bool = False) -> str:
    """Interactive prompt for missing config values."""
    if default and not secret:
        prompt = f"     {CYAN}↳{NC} Введите [{YELLOW}{default}{NC}]: "
    else:
        prompt = f"     {CYAN}↳{NC} Введите: "

    if secret:
        # getpass reads from /dev/tty, handles echo suppression
        value = getpass.getpass(prompt)
    else:
        try:
            with open("/dev/tty") as tty:
                sys.stderr.write(prompt)
                sys.stderr.flush()
                value = tty.readline().strip()
        except OSError:
            value = input(prompt)

    return value or default


def wizard_targets(tunnel_name: str) -> list[str]:
    """Wizard prompt for tunnel targets with validation and retry."""
    from tv.routing import validate_target

    section(f"Маршруты: {tunnel_name}")
    print(f"  Хосты и сети через этот туннель {DIM}(через запятую, пусто = пропуск){NC}")
    print(f"  {DIM}Форматы:{NC}")
    print(f"  {DIM}  10.0.0.0/8        - подсеть (CIDR){NC}")
    print(f"  {DIM}  192.168.1.1       - IP-адрес{NC}")
    print(f"  {DIM}  *.corp.local      - домен (wildcard → DNS){NC}")
    print(f"  {DIM}  git.example.com   - хост (резолв при подключении){NC}")

    while True:
        raw = wizard_input("Targets")
        items = [t.strip() for t in raw.split(",") if t.strip()]
        if not items:
            return []

        errors = []
        for item in items:
            kind, err = validate_target(item)
            if err:
                errors.append(err)

        if not errors:
            # Show parsed summary
            _show_targets_summary(items)
            return items

        for err in errors:
            print(f"  {RED}✗{NC}  {err}")
        print(f"  {YELLOW}Исправьте и введите заново{NC}")


def _show_targets_summary(items: list[str]) -> None:
    """Show compact summary of validated targets."""
    from tv.routing import validate_target

    type_icons = {
        "network": ("📡", "подсеть"),
        "host": ("🖥 ", "IP"),
        "domain": ("🌐", "домен"),
        "hostname": ("🔗", "хост"),
    }
    for item in items:
        kind, _ = validate_target(item)
        icon, label = type_icons.get(kind, ("?", "?"))
        print(f"  {GREEN}✓{NC}  {icon} {item} {DIM}({label}){NC}")


def wizard_nameservers(domains: list[str]) -> list[str]:
    """Wizard prompt for DNS nameservers with IP validation."""
    import ipaddress

    domain_list = ", ".join(domains)
    print(f"  DNS серверы для доменов {BOLD}{domain_list}{NC}:")
    print(f"  {DIM}(IP-адреса через запятую, пусто = пропуск){NC}")

    while True:
        raw = wizard_input("DNS серверы")
        items = [s.strip() for s in raw.split(",") if s.strip()]
        if not items:
            return []

        errors = []
        for item in items:
            try:
                ipaddress.ip_address(item)
            except ValueError:
                errors.append(f"{item} - невалидный IP-адрес")

        if not errors:
            return items

        for err in errors:
            print(f"  {RED}✗{NC}  {err}")
        print(f"  {YELLOW}Исправьте и введите заново{NC}")


# --- Logo ---

def logo() -> None:
    from tv import __version__

    def _c(n: int) -> str:
        return f"\033[38;5;{n}m"

    R = NC

    # Gradient bar: teal → indigo → purple → crimson (52 visible chars)
    bar = (
        f"  {_c(24)}░░▒▒{_c(30)}▓▓████{_c(37)}████████"
        f"{_c(61)}████████{_c(97)}████████"
        f"{_c(131)}████████{_c(88)}████▓▓{_c(52)}▒▒░░{R}"
    )

    # TUNNEL (teal gradient: dark → light)
    tunnel = [
        "████████╗██╗   ██╗███╗  ██╗███╗  ██╗███████╗██╗  ",
        "╚══██╔══╝██║   ██║████╗ ██║████╗ ██║██╔════╝██║  ",
        "   ██║   ██║   ██║██╔██╗██║██╔██╗██║█████╗  ██║  ",
        "   ██║   ██║   ██║██║╚████║██║╚████║██╔══╝  ██║  ",
        "   ██║   ╚██████╔╝██║ ╚███║██║ ╚███║███████╗█████╗",
        "   ╚═╝    ╚═════╝ ╚═╝  ╚══╝╚═╝  ╚══╝╚══════╝╚════╝",
    ]
    t_colors = [_c(24), _c(24), _c(30), _c(30), _c(37), _c(37)]

    # VAULT (crimson gradient: dark → light)
    vault = [
        "██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗",
        "██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝",
        "██║   ██║███████║██║   ██║██║     ██║   ",
        "╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║   ",
        " ╚████╔╝ ██║  ██║╚██████╔╝██████╗██║   ",
        "  ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚═════╝╚═╝   ",
    ]
    v_colors = [_c(88), _c(88), _c(124), _c(124), _c(131), _c(131)]

    # Ornamental divider (centered within 50-char TUNNEL width)
    div = f"{_c(61)}═══════════╡{R} {_c(130)}◆{R} {_c(61)}╞═══════════{R}"

    print()
    print(bar)
    print()
    for line, c in zip(tunnel, t_colors):
        print(f"    {c}{line}{R}")
    print()
    print(f"{' ' * 15}{div}")
    print()
    for line, c in zip(vault, v_colors):
        print(f"         {c}{line}{R}")
    print()
    ver_text = f"v{__version__} · multi-VPN connection manager"
    ver_pad = 4 + max(0, (50 - len(ver_text)) // 2)
    print(f"{' ' * ver_pad}{_c(109)}v{__version__}{R} {_c(240)}·{R} {_c(243)}multi-VPN connection manager{R}")
    # Dynamic protocol line from registry
    proto_line = _build_proto_line()
    print(f"{' ' * 12}{proto_line}")
    print()
    print(bar)
    print()


def _build_proto_line() -> str:
    """Build protocol display line from registered plugins."""
    from tv.vpn.registry import available_types, get_plugin

    def _c(n: int) -> str:
        return f"\033[38;5;{n}m"
    R = NC

    colors = [_c(37), _c(97), _c(131), _c(61), _c(130)]

    types = available_types()
    if not types:
        return f"{_c(243)}no tunnels registered{R}"

    parts = []
    for i, type_name in enumerate(types):
        color = colors[i % len(colors)]
        try:
            plugin_cls = get_plugin(type_name)
            display = plugin_cls.display_name.fget(plugin_cls)
        except (KeyError, TypeError, AttributeError):
            display = type_name
        parts.append(f"{color}▸{R} {_c(243)}{display}{R}")

    return "  ".join(parts)


# --- Summary table ---

def _box(char_l: str, char_r: str) -> None:
    w = cfg.display.box_width
    print(f"  {CYAN}{char_l}{'━' * (w + 2)}{char_r}{NC}")


def _row(content: str = "") -> None:
    w = cfg.display.box_width
    vis = _visible_len(content)
    pad = max(0, w - vis)
    print(f"  {CYAN}┃{NC} {content}{' ' * pad} {CYAN}┃{NC}")


def _header(text: str) -> None:
    w = cfg.display.box_width
    vis = _visible_len(text)
    pad = max(0, w - vis)
    print(f"  {CYAN}┃{NC} {BOLD}{text}{NC}{' ' * pad} {CYAN}┃{NC}")


def _center(text: str) -> None:
    w = cfg.display.box_width
    vis = _visible_len(text)
    pad_l = (w - vis) // 2
    pad_r = max(0, w - pad_l - vis)
    print(f"  {CYAN}┃{NC}{' ' * pad_l}{BOLD}{text}{NC}{' ' * pad_r} {CYAN}┃{NC}")


def print_summary(
    tunnels: Sequence[tuple[str, bool, str]],
    checks: Sequence[tuple[str, str, str]],  # (label, status, detail)
    log_paths: dict[str, str],
) -> None:
    """Print the final summary box."""
    passed = sum(1 for _, s, _ in checks if s == "ok")
    total = len(checks)

    print()
    _box("┏", "┓")
    _center("ИТОГ ПОДКЛЮЧЕНИЯ")
    _box("┣", "┫")

    _header("ТУННЕЛИ")
    _row()
    for name, is_ok, detail in tunnels:
        icon = "✅" if is_ok else "❌"
        line = f"   {icon}  {name:<22s} {detail}"
        _row(line)
    _row()
    _box("┣", "┫")

    _header(f"ПРОВЕРКИ  {passed}/{total}")
    _row()
    for label, status, detail in checks:
        # Fallback results get a distinct icon
        if status == "ok" and detail.startswith("fallback:"):
            icon = "⚠✅"
        else:
            icon = {"ok": "✅", "fail": "❌", "skip": "⏭ "}.get(status, "?")
        line = f"   {icon}  {label:<30s} {detail}"
        _row(line)
    _row()
    _box("┣", "┫")

    _header("ЛОГИ")
    _row()
    for name, path in log_paths.items():
        prefix = "cat" if name == "debug" else "sudo cat"
        _row(f"   {name:<11s} {prefix} {path}")
    _row()

    _box("┗", "┛")
    print()
