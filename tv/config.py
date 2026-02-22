"""Config: CLI args, ENV, settings file, plugin-driven param resolution."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from tv import ui, routing
from tv.app_config import cfg

if TYPE_CHECKING:
    from tv.vpn.base import TunnelConfig

from tv.vpn.base import ConfigParam


class SetupRequiredError(Exception):
    """Raised when interactive setup is needed but quiet mode is active."""


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="tunnelvault - multi-VPN connection manager",
    )
    p.add_argument("--disconnect", action="store_true", help="Отключить все VPN")
    p.add_argument("--clear", action="store_true",
                   help="Отключить предыдущие VPN перед подключением (по умолчанию не трогает)")
    p.add_argument("--setup", action="store_true",
                   help="Интерактивная настройка (wizard)")
    p.add_argument("--debug", action="store_true", help="DEBUG-вывод в stderr")
    p.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARN", "ERROR", "FATAL"],
        default=None,
        help="Уровень логирования (по умолчанию из конфига)",
    )
    return p.parse_args()


# --- Settings file (JSON) ---


def load_settings(script_dir: Path, *, quiet: bool = False) -> dict:
    path = script_dir / cfg.paths.settings_file
    if path.exists():
        try:
            data = json.loads(path.read_text())
            if not quiet:
                print(f"  {ui.GREEN}📂{ui.NC} Настройки: {ui.GREEN}загружены{ui.NC} {ui.DIM}({cfg.paths.settings_file}){ui.NC}")
            return data
        except (json.JSONDecodeError, OSError) as e:
            if not quiet:
                print(f"  {ui.RED}⚠{ui.NC}  Настройки: {ui.RED}ошибка чтения{ui.NC} {ui.DIM}({e}){ui.NC}")
            # Fall through to bash format instead of returning empty

    # Try migrating from old bash format
    old_path = script_dir / ".vpn-settings"
    if old_path.exists():
        migrated = _migrate_bash_settings(old_path)
        if migrated:
            if not quiet:
                print(f"  {ui.GREEN}📂{ui.NC} Настройки: {ui.GREEN}мигрированы из .vpn-settings{ui.NC}")
            return migrated

    if not quiet:
        print(f"  {ui.YELLOW}📂{ui.NC} Настройки: {ui.YELLOW}не найдены{ui.NC} {ui.DIM}(будет создан {cfg.paths.settings_file}){ui.NC}")
    return {}


def _migrate_bash_settings(path: Path) -> dict:
    """Parse old bash SAVED_FOO=\"bar\" format into per-tunnel nested dict.

    Returns: {"fortivpn": {"host": ..., "port": ...}, "openvpn": {"config_file": ...}, ...}
    Keys match plugin config_schema() param.key values.
    """
    result: dict = {}
    # (tunnel_name, param_key) - matches legacy fixed tunnel names
    key_map: dict[str, tuple[str, str]] = {
        "SAVED_OVPN_CONFIG": ("openvpn", "config_file"),
        "SAVED_PIKLEMA_CONFIG": ("singbox", "config_file"),
        "SAVED_SINGBOX_CONFIG": ("singbox", "config_file"),
        "SAVED_FORTI_HOST": ("fortivpn", "host"),
        "SAVED_FORTI_PORT": ("fortivpn", "port"),
        "SAVED_FORTI_LOGIN": ("fortivpn", "login"),
        "SAVED_FORTI_PASS": ("fortivpn", "pass"),
        "SAVED_TRUSTED_CERT": ("fortivpn", "trusted_cert"),
        "SAVED_CERT_MODE": ("fortivpn", "cert_mode"),
    }
    try:
        for line in path.read_text().splitlines():
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"')
            if key in key_map:
                tunnel_name, param_key = key_map[key]
                result.setdefault(tunnel_name, {})[param_key] = value
    except OSError:
        pass
    return result


# --- Tunnel param resolution via plugin config_schema() ---


def _tunnel_saved(saved: dict, tcfg: TunnelConfig) -> dict:
    """Lookup saved settings for a tunnel: by name, then by type."""
    return saved.get(tcfg.name) or saved.get(tcfg.type, {})


def _get_param_value(tcfg: TunnelConfig, param: ConfigParam) -> str:
    """Get current value of a param from TunnelConfig."""
    if param.target == "auth":
        return tcfg.auth.get(param.key, "")
    if param.target == "config_file":
        return tcfg.config_file
    if param.target == "extra":
        return str(tcfg.extra.get(param.key, ""))
    return ""


def _set_param_value(tcfg: TunnelConfig, param: ConfigParam, value: str) -> None:
    """Set param value on TunnelConfig."""
    if param.target == "auth":
        tcfg.auth[param.key] = value
    elif param.target == "config_file":
        tcfg.config_file = value
    elif param.target == "extra":
        tcfg.extra[param.key] = value


def resolve_tunnel_params(
    tcfg: TunnelConfig,
    plugin_cls: type,
    saved: dict,
    script_dir: Path,
    *,
    quiet: bool = False,
) -> None:
    """Resolve missing params for a tunnel using plugin's config_schema().

    Mutates tcfg.auth / tcfg.config_file / tcfg.extra in place.
    Priority: TOML value -> ENV -> saved -> wizard input.
    In quiet mode: no prints, no wizard. Raises SetupRequiredError if required param missing.
    """
    schema = plugin_cls.config_schema()
    if not schema:
        return

    tunnel_saved = _tunnel_saved(saved, tcfg)

    for param in schema:
        # Current value from TOML (or auto-applied default)
        current = _get_param_value(tcfg, param)
        if current:
            # Auto-applied config_file defaults can be overridden by ENV/saved
            if param.target == "config_file" and tcfg._auto_config_file:
                env_val = os.environ.get(param.env_var, "") if param.env_var else ""
                if env_val:
                    _set_param_value(tcfg, param, env_val)
                    if not quiet:
                        ui.param_found(param.label, env_val, f"${param.env_var}", param.secret)
                    continue
                saved_val = tunnel_saved.get(param.key, "")
                if saved_val:
                    _set_param_value(tcfg, param, saved_val)
                    if not quiet:
                        ui.param_found(param.label, saved_val, cfg.paths.settings_file, param.secret)
                    continue
                if not quiet:
                    ui.param_found(param.label, current, "авто", param.secret)
                continue
            if not quiet:
                ui.param_found(param.label, current, "defaults.toml", param.secret)
            continue

        # FortiVPN trusted_cert with cert_mode=auto: skip wizard, handled below
        if (tcfg.type == "fortivpn" and param.key == "trusted_cert"
                and tcfg.auth.get("cert_mode") == "auto"):
            continue

        # Non-interactive params: resolve from ENV/saved only, no wizard
        if not param.prompt:
            value = _resolve_silent(param, tunnel_saved, quiet=quiet)
            if value:
                _set_param_value(tcfg, param, value)
            continue

        # Resolve: ENV -> saved -> wizard (or default/error in quiet mode)
        value = _resolve_param(
            param.label,
            env_name=param.env_var,
            saved=tunnel_saved.get(param.key, ""),
            default=param.default,
            secret=param.secret,
            quiet=quiet,
        )
        _set_param_value(tcfg, param, value)

    # FortiVPN cert_mode=auto: generate cert after all params resolved
    if tcfg.type == "fortivpn":
        _handle_forti_cert(tcfg, tunnel_saved, quiet=quiet)


def _handle_forti_cert(
    tcfg: TunnelConfig, tunnel_saved: dict, *, quiet: bool = False,
) -> None:
    """Handle FortiVPN trusted_cert: auto-generate or resolve from ENV/saved."""
    cert_mode = tcfg.auth.get("cert_mode", "")
    if cert_mode != "auto":
        return
    if tcfg.auth.get("trusted_cert"):
        return

    # Check ENV
    env_val = os.environ.get("VPN_TRUSTED_CERT", "")
    if env_val:
        if not quiet:
            ui.param_found("SHA256 сертификата", env_val, "$VPN_TRUSTED_CERT", False)
        tcfg.auth["trusted_cert"] = env_val
        return

    # Check saved
    saved_val = tunnel_saved.get("trusted_cert", "")
    if saved_val:
        if not quiet:
            ui.param_found("SHA256 сертификата", saved_val, cfg.paths.settings_file, False)
        tcfg.auth["trusted_cert"] = saved_val
        return

    # Auto-generate
    host = tcfg.auth.get("host", "")
    port = tcfg.auth.get("port", cfg.defaults.fortivpn_port)
    if not host:
        return

    if not quiet:
        print(f"  🔑 Генерация SHA256 сертификата из {ui.BOLD}{host}:{port}{ui.NC}...")
    cert = _generate_cert(host, port)
    if cert:
        if not quiet:
            print(f"  {ui.GREEN}✅{ui.NC} Сгенерирован: {ui.YELLOW}{cert[:24]}...{ui.NC}")
        tcfg.auth["trusted_cert"] = cert
    else:
        if quiet:
            raise SetupRequiredError(
                f"Сертификат не сгенерирован для {host}:{port}. Запустите с --setup."
            )
        print(f"  {ui.RED}❌{ui.NC} Не удалось подключиться к хосту")
        ui.param_missing("SHA256 вручную")
        tcfg.auth["trusted_cert"] = ui.wizard_input("SHA256 вручную", "", False)


def resolve_tunnel_routes(
    tcfg: TunnelConfig,
    saved: dict,
    *,
    quiet: bool = False,
) -> None:
    """Resolve routes for a tunnel: TOML targets -> parse, or wizard.

    Skip wizard if advanced config exists (networks/hosts already in TOML).
    In quiet mode: no prints, no wizard. Unresolved routes default to native routing.
    """
    # Advanced mode: TOML already has explicit routes - skip wizard
    has_advanced = bool(
        tcfg.routes.get("networks")
        or tcfg.routes.get("hosts")
    )
    if has_advanced and not quiet:
        nets = tcfg.routes.get("networks", [])
        hosts = tcfg.routes.get("hosts", [])
        ui.param_found(
            f"Маршруты ({tcfg.name})",
            f"{len(nets)} сетей, {len(hosts)} хостов",
            "defaults.toml", False,
        )

    # Get targets: TOML -> saved -> wizard
    # "targets" key present but empty = user chose native routing (don't re-ask)
    targets = tcfg.routes.get("targets", [])
    resolved = bool(targets) or has_advanced

    if not resolved:
        tunnel_saved = _tunnel_saved(saved, tcfg)
        if "targets" in tunnel_saved:
            targets = tunnel_saved["targets"]
            if not quiet:
                if targets:
                    ui.param_found("Targets", ", ".join(targets), cfg.paths.settings_file, False)
                else:
                    ui.param_found(
                        f"Маршруты ({tcfg.name})", "нативный роутинг",
                        cfg.paths.settings_file, False,
                    )
            resolved = True

    if not resolved:
        if quiet:
            targets = []  # Native routing in quiet mode
        else:
            targets = ui.wizard_targets(tcfg.name)

    # Always store targets for saving ([] = native routing, remembered)
    tcfg.routes["targets"] = targets

    if targets:
        # Parse and merge into tcfg.routes / tcfg.dns
        parsed = routing.parse_targets(targets)
        routing.merge_targets_into_config(tcfg, parsed)

    # DNS nameservers needed for domains (from targets or TOML)?
    all_domains = tcfg.dns.get("domains", [])
    if all_domains and not tcfg.dns.get("nameservers"):
        tunnel_saved = _tunnel_saved(saved, tcfg)
        ns = tunnel_saved.get("dns_nameservers", [])
        if ns:
            if not quiet:
                ui.param_found("DNS серверы", ", ".join(ns), cfg.paths.settings_file, False)
        elif not quiet:
            ns = ui.wizard_nameservers(all_domains)
        if ns:
            tcfg.dns["nameservers"] = ns


def save_tunnel_settings(tunnels: list[TunnelConfig], script_dir: Path) -> None:
    """Save resolved auth/config params to .vpn-settings.json.

    Saves per-tunnel: {tunnel_name: {key: value, ...}, ...}
    """
    from tv.vpn.registry import get_plugin

    data: dict = {}
    for tcfg in tunnels:
        tunnel_data: dict = {}

        # Auth/config params from plugin schema
        try:
            plugin_cls = get_plugin(tcfg.type)
            schema = plugin_cls.config_schema()
            for param in schema:
                value = _get_param_value(tcfg, param)
                if value:
                    tunnel_data[param.key] = value
        except KeyError:
            pass

        # Targets (from wizard or TOML; [] = native routing, save explicitly)
        if "targets" in tcfg.routes:
            tunnel_data["targets"] = tcfg.routes["targets"]

        # DNS nameservers (from wizard)
        ns = tcfg.dns.get("nameservers", [])
        if ns:
            tunnel_data["dns_nameservers"] = ns

        if tunnel_data:
            data[tcfg.name] = tunnel_data

    _write_settings(data, script_dir)


def _write_settings(data: dict, script_dir: Path) -> None:
    """Write settings dict to JSON with 0o600 permissions (atomic via rename).

    If running under sudo, chown to the real user so the file stays readable
    on subsequent non-sudo runs.
    """
    import tempfile

    path = script_dir / cfg.paths.settings_file
    content = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    fd, tmp_path = tempfile.mkstemp(dir=str(script_dir), suffix=".tmp")
    try:
        os.write(fd, content.encode())
    finally:
        os.close(fd)
    try:
        os.chmod(tmp_path, 0o600)
        _chown_to_real_user(tmp_path)
        os.rename(tmp_path, str(path))
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    print(f"  {ui.GREEN}💾 Настройки сохранены{ui.NC} {ui.DIM}({cfg.paths.settings_file}){ui.NC}")


def _chown_to_real_user(path: str) -> None:
    """Chown file/dir to real user when running under sudo."""
    uid_s = os.environ.get("SUDO_UID", "")
    gid_s = os.environ.get("SUDO_GID", "")
    if uid_s and gid_s:
        try:
            os.chown(path, int(uid_s), int(gid_s))
        except OSError:
            pass


def resolve_log_dir(script_dir: Path) -> Path:
    """Resolve log_dir to absolute path (relative to script_dir if needed)."""
    d = Path(cfg.paths.log_dir)
    if not d.is_absolute():
        d = script_dir / d
    return d


def ensure_log_dir(script_dir: Path) -> Path:
    """Create log directory with correct ownership. Returns absolute path."""
    d = resolve_log_dir(script_dir)
    d.mkdir(parents=True, exist_ok=True)
    _chown_to_real_user(str(d))
    return d


def resolve_log_paths(tunnels: list[TunnelConfig], script_dir: Path) -> None:
    """Resolve relative tunnel log paths to absolute (relative to script_dir)."""
    for tc in tunnels:
        if tc.log:
            p = Path(tc.log)
            if not p.is_absolute():
                tc.log = str(script_dir / p)


def prepare_log_files(tunnels: list[TunnelConfig]) -> None:
    """Pre-create log files with correct ownership and readable permissions.

    VPN processes run as root and would create 0600 files.
    Pre-creating as 0644 ensures logs are readable without sudo.
    """
    for tc in tunnels:
        if not tc.log:
            continue
        p = Path(tc.log)
        p.parent.mkdir(parents=True, exist_ok=True)
        _chown_to_real_user(str(p.parent))
        p.write_bytes(b"")
        os.chmod(str(p), 0o644)
        _chown_to_real_user(str(p))


# --- Param resolution: ENV -> saved -> wizard ---

def _resolve_silent(
    param: ConfigParam, tunnel_saved: dict, *, quiet: bool = False,
) -> str:
    """Resolve param from ENV/saved only (no wizard prompt).

    Used for optional params like fallback_gateway that shouldn't
    interrupt the user flow.
    """
    if param.env_var:
        env_val = os.environ.get(param.env_var, "")
        if env_val:
            if not quiet:
                ui.param_found(param.label, env_val, f"${param.env_var}", param.secret)
            return env_val
    saved_val = tunnel_saved.get(param.key, "")
    if saved_val:
        if not quiet:
            ui.param_found(param.label, saved_val, cfg.paths.settings_file, param.secret)
        return saved_val
    return param.default


def _resolve_param(
    label: str,
    env_name: str = "",
    saved: str = "",
    default: str = "",
    secret: bool = False,
    quiet: bool = False,
) -> str:
    """Resolve single param with priority chain: ENV -> saved -> wizard.

    In quiet mode: no prints, no wizard. Uses default or raises SetupRequiredError.
    """
    def display(v: str) -> str:
        return "****" if secret else v

    # 1. ENV
    env_val = os.environ.get(env_name, "")
    if env_val:
        if not quiet:
            ui.param_found(label, display(env_val), f"${env_name}", secret)
        return env_val

    # 2. Saved (.vpn-settings.json)
    if saved:
        if not quiet:
            ui.param_found(label, display(saved), cfg.paths.settings_file, secret)
        return saved

    # 3. Quiet mode: use default or error
    if quiet:
        if default:
            return default
        raise SetupRequiredError(
            f"Параметр '{label}' не задан. Запустите с --setup для настройки."
        )

    # 4. Default from defaults.toml (show as placeholder in wizard)
    if default and not secret:
        ui.param_missing(label)
        return ui.wizard_input(label, default, secret)

    # 5. Wizard without default
    ui.param_missing(label)
    return ui.wizard_input(label, "", secret)


def _generate_cert(host: str, port: str) -> str:
    """Generate SHA256 cert fingerprint via openssl pipe chain."""
    try:
        s_client = subprocess.Popen(
            ["openssl", "s_client", "-connect", f"{host}:{port}"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        x509 = subprocess.Popen(
            ["openssl", "x509", "-outform", "DER"],
            stdin=s_client.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        s_client.stdout.close()

        dgst = subprocess.Popen(
            ["openssl", "dgst", "-sha256"],
            stdin=x509.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        x509.stdout.close()

        # Send empty line to s_client (like "echo |")
        s_client.stdin.write(b"\n")
        s_client.stdin.close()

        out, _ = dgst.communicate(timeout=cfg.timeouts.cert_generation)
        s_client.wait(timeout=cfg.timeouts.cert_openssl)
        x509.wait(timeout=cfg.timeouts.cert_openssl)

        if dgst.returncode == 0 and out:
            text = out.decode().strip()
            if "= " in text:
                return text.split("= ", 1)[1].strip()
            return text
    except (subprocess.TimeoutExpired, OSError):
        pass
    return ""
