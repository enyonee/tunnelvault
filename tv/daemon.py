"""Daemon management: daemonize, PID file, autostart (launchd/systemd)."""

from __future__ import annotations

import os
import platform
import plistlib
import subprocess
import sys
from pathlib import Path

from tv import ui
from tv.app_config import cfg
from tv.i18n import t

PLIST_LABEL = "com.tunnelvault.keepalive"
PLIST_PATH = Path(f"/Library/LaunchDaemons/{PLIST_LABEL}.plist")

SYSTEMD_UNIT = "tunnelvault.service"
SYSTEMD_PATH = Path(f"/etc/systemd/system/{SYSTEMD_UNIT}")


# =========================================================================
# PID file
# =========================================================================


def pid_file_path(script_dir: Path) -> Path:
    """Absolute path to PID file (inside log_dir)."""
    log_dir = Path(cfg.paths.log_dir)
    if not log_dir.is_absolute():
        log_dir = script_dir / log_dir
    return log_dir / cfg.paths.pid_file


def write_pid(script_dir: Path, pid: int | None = None) -> Path:
    """Write current (or given) PID to file. Returns path."""
    path = pid_file_path(script_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(pid or os.getpid()))
    return path


def read_pid(script_dir: Path) -> int | None:
    """Read PID from file. Returns None if missing or invalid."""
    path = pid_file_path(script_dir)
    try:
        return int(path.read_text().strip())
    except (FileNotFoundError, ValueError):
        return None


def remove_pid(script_dir: Path) -> None:
    """Remove PID file if it exists."""
    pid_file_path(script_dir).unlink(missing_ok=True)


def is_pid_alive(pid: int) -> bool:
    """Check if process with given PID is running."""
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


# =========================================================================
# Daemonize (fork + setsid)
# =========================================================================


def daemonize(script_dir: Path) -> int:
    """Fork into background. Returns child PID to parent, 0 to child.

    Parent should print PID and sys.exit(0).
    Child: setsid, redirect stdio to daemon.log, write PID file.
    """
    child_pid = os.fork()
    if child_pid > 0:
        # Parent: return child PID
        return child_pid

    # --- Child process ---
    os.setsid()

    # Redirect stdio to daemon.log (use raw fd numbers: 0=stdin, 1=stdout, 2=stderr)
    log_path = _daemon_log_path(script_dir)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(log_path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    os.dup2(fd, 1)  # stdout
    os.dup2(fd, 2)  # stderr
    os.close(fd)

    devnull = os.open(os.devnull, os.O_RDONLY)
    os.dup2(devnull, 0)  # stdin
    os.close(devnull)

    # Write PID file
    write_pid(script_dir)

    return 0


# =========================================================================
# Autostart: enable / disable
# =========================================================================


def enable(script_dir: Path, *, only: str | None = None) -> None:
    """Enable autostart for current platform."""
    system = platform.system()
    if system == "Darwin":
        _enable_launchd(script_dir, only=only)
    elif system == "Linux":
        _enable_systemd(script_dir, only=only)
    else:
        ui.fail(f"Autostart not supported on {system}")
        sys.exit(1)


def disable() -> None:
    """Disable autostart for current platform."""
    system = platform.system()
    if system == "Darwin":
        _disable_launchd()
    elif system == "Linux":
        _disable_systemd()
    else:
        ui.fail(f"Autostart not supported on {system}")
        sys.exit(1)


# =========================================================================
# Launchd (macOS)
# =========================================================================


def _enable_launchd(script_dir: Path, *, only: str | None = None) -> None:
    """Install and load launchd plist."""
    if PLIST_PATH.exists():
        subprocess.run(
            ["launchctl", "unload", str(PLIST_PATH)],
            capture_output=True,
        )

    plist = _build_plist(script_dir, only=only)
    PLIST_PATH.write_bytes(plistlib.dumps(plist, fmt=plistlib.FMT_XML))

    r = subprocess.run(
        ["launchctl", "load", "-w", str(PLIST_PATH)],
        capture_output=True,
        text=True,
    )
    if r.returncode == 0:
        ui.ok(t("daemon.enabled"))
        ui.info(f"  {ui.DIM}{PLIST_PATH}{ui.NC}")
        log_path = _daemon_log_path(script_dir)
        ui.info(f"  {ui.DIM}{t('daemon.log_hint', path=log_path)}{ui.NC}")
    else:
        ui.fail(t("daemon.enable_failed", error=r.stderr.strip()))


def _disable_launchd() -> None:
    """Unload and remove launchd plist."""
    if not PLIST_PATH.exists():
        ui.warn(t("daemon.already_disabled"))
        return

    subprocess.run(
        ["launchctl", "unload", str(PLIST_PATH)],
        capture_output=True,
    )
    PLIST_PATH.unlink(missing_ok=True)
    ui.ok(t("daemon.disabled"))


# =========================================================================
# Systemd (Linux)
# =========================================================================


def _enable_systemd(script_dir: Path, *, only: str | None = None) -> None:
    """Generate and enable systemd unit."""
    unit = _build_systemd_unit(script_dir, only=only)
    SYSTEMD_PATH.write_text(unit)
    ui.info(t("daemon.systemd_unit_written", path=str(SYSTEMD_PATH)))

    subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
    r = subprocess.run(
        ["systemctl", "enable", "--now", SYSTEMD_UNIT],
        capture_output=True,
        text=True,
    )
    if r.returncode == 0:
        ui.ok(t("daemon.enabled"))
    else:
        ui.fail(t("daemon.enable_failed", error=r.stderr.strip()))


def _disable_systemd() -> None:
    """Disable and remove systemd unit."""
    if not SYSTEMD_PATH.exists():
        ui.warn(t("daemon.already_disabled"))
        return

    subprocess.run(
        ["systemctl", "disable", "--now", SYSTEMD_UNIT],
        capture_output=True,
    )
    SYSTEMD_PATH.unlink(missing_ok=True)
    subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
    ui.ok(t("daemon.disabled"))


def _build_systemd_unit(script_dir: Path, *, only: str | None = None) -> str:
    """Build systemd unit file content."""
    script = str((script_dir / "tunnelvault.py").resolve())
    python = sys.executable
    args = f"{python} {script} --foreground"
    if only:
        args += f" --only {only}"

    return f"""\
[Unit]
Description=TunnelVault VPN keepalive
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={args}
Restart=on-failure
RestartSec=10
WorkingDirectory={script_dir.resolve()}

[Install]
WantedBy=multi-user.target
"""


# =========================================================================
# Internal
# =========================================================================


def _daemon_log_path(script_dir: Path) -> Path:
    log_dir = Path(cfg.paths.log_dir)
    if not log_dir.is_absolute():
        log_dir = script_dir / log_dir
    return log_dir / "daemon.log"


def _build_plist(script_dir: Path, *, only: str | None = None) -> dict:
    """Build launchd plist dictionary."""
    script = str((script_dir / "tunnelvault.py").resolve())
    python = sys.executable

    # launchd manages the process - use --foreground so tunnelvault
    # doesn't fork (launchd needs the PID it launched to stay alive)
    args = [python, script, "--foreground"]
    if only:
        args.extend(["--only", only])

    log_dir = Path(cfg.paths.log_dir)
    if not log_dir.is_absolute():
        log_dir = script_dir / log_dir
    log_dir.mkdir(parents=True, exist_ok=True)
    daemon_log = str(log_dir / "daemon.log")

    return {
        "Label": PLIST_LABEL,
        "ProgramArguments": args,
        "WorkingDirectory": str(script_dir.resolve()),
        "RunAtLoad": True,
        "KeepAlive": True,
        "StandardOutPath": daemon_log,
        "StandardErrorPath": daemon_log,
    }
