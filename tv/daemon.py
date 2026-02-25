"""Daemon management: install/uninstall/status of launchd keepalive service."""

from __future__ import annotations

import plistlib
import subprocess
import sys
from pathlib import Path

from tv import ui
from tv.app_config import cfg
from tv.i18n import t

PLIST_LABEL = "com.tunnelvault.keepalive"
PLIST_PATH = Path(f"/Library/LaunchDaemons/{PLIST_LABEL}.plist")


# --- Public API ---


def run_install(script_dir: Path, *, only: str | None = None) -> None:
    """Install and load launchd daemon for keepalive."""
    if PLIST_PATH.exists():
        # Unload first if already installed
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
        ui.ok(t("daemon.installed"))
        ui.info(f"  {ui.DIM}{PLIST_PATH}{ui.NC}")
        log_path = _daemon_log_path(script_dir)
        ui.info(f"  {ui.DIM}{t('daemon.log_hint', path=log_path)}{ui.NC}")
    else:
        ui.fail(t("daemon.install_failed", error=r.stderr.strip()))


def run_uninstall() -> None:
    """Unload and remove launchd daemon."""
    if not PLIST_PATH.exists():
        ui.warn(t("daemon.not_installed"))
        return

    subprocess.run(
        ["launchctl", "unload", str(PLIST_PATH)],
        capture_output=True,
    )
    PLIST_PATH.unlink(missing_ok=True)
    ui.ok(t("daemon.uninstalled"))


def run_status() -> None:
    """Print daemon status."""
    info = status()

    if not info["installed"]:
        ui.info(f"  {t('daemon.label')}: {ui.DIM}{PLIST_LABEL}{ui.NC}")
        ui.info(
            f"  {t('daemon.status_label')}: {ui.YELLOW}{t('daemon.not_installed')}{ui.NC}"
        )
        return

    ui.info(f"  {t('daemon.label')}: {ui.DIM}{PLIST_LABEL}{ui.NC}")

    if info["running"]:
        ui.info(
            f"  {t('daemon.status_label')}: {ui.GREEN}{t('daemon.running')}{ui.NC} (PID={info['pid']})"
        )
    else:
        ui.info(f"  {t('daemon.status_label')}: {ui.RED}{t('daemon.stopped')}{ui.NC}")

    ui.info(f"  {t('daemon.plist_label')}: {ui.DIM}{PLIST_PATH}{ui.NC}")


def status() -> dict:
    """Get daemon status dict: installed, running, pid."""
    if not PLIST_PATH.exists():
        return {"installed": False, "running": False, "pid": None}

    r = subprocess.run(
        ["launchctl", "list"],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        return {"installed": True, "running": False, "pid": None}

    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] == PLIST_LABEL:
            pid_str = parts[0]
            pid = int(pid_str) if pid_str != "-" else None
            return {"installed": True, "running": pid is not None, "pid": pid}

    return {"installed": True, "running": False, "pid": None}


# --- Internal ---


def _daemon_log_path(script_dir: Path) -> Path:
    log_dir = Path(cfg.paths.log_dir)
    if not log_dir.is_absolute():
        log_dir = script_dir / log_dir
    return log_dir / "daemon.log"


def _build_plist(script_dir: Path, *, only: str | None = None) -> dict:
    """Build launchd plist dictionary."""
    script = str((script_dir / "tunnelvault.py").resolve())
    python = sys.executable

    args = [python, script, "--keepalive"]
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
