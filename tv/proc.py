"""Process management: run, background, wait, kill."""

from __future__ import annotations

import os
import subprocess
import time
from typing import Callable, Optional, IO

from tv.app_config import cfg
from tv.i18n import t
from tv.logger import Logger


def run(
    cmd: list[str],
    sudo: bool = False,
    check: bool = False,
    timeout: Optional[int] = None,
) -> subprocess.CompletedProcess:
    """Run a command synchronously, capture output."""
    if timeout is None:
        timeout = cfg.timeouts.process
    if sudo:
        cmd = ["sudo"] + list(cmd)
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=check,
        timeout=timeout,
    )


def run_background(
    cmd: list[str],
    sudo: bool = False,
    log_path: Optional[str] = None,
) -> subprocess.Popen:
    """Run a command in background. Log file is created as current user."""
    if sudo:
        cmd = ["sudo"] + list(cmd)
    log_file: IO | int = subprocess.DEVNULL
    try:
        if log_path:
            log_file = open(log_path, "w")
        p = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
    except Exception:
        if log_path and log_file != subprocess.DEVNULL:
            log_file.close()  # type: ignore[union-attr]
        raise
    # Close parent's copy - child inherited the fd
    if log_path and log_file != subprocess.DEVNULL:
        log_file.close()  # type: ignore[union-attr]
    return p


def wait_for(
    desc: str,
    check_fn: Callable[[], bool],
    timeout: int,
    logger: Optional[Logger] = None,
) -> bool:
    """Poll check_fn every second until True or timeout."""
    print(f"  ⏳ {t('proc.waiting', desc=desc)}")
    if logger:
        logger.log("WAIT", f"Waiting for '{desc}' (timeout {timeout}s)")
    for i in range(1, timeout + 1):
        if check_fn():
            if logger:
                logger.log("WAIT", f"'{desc}' ready in {i}s")
            return True
        time.sleep(1)
    if logger:
        logger.log("WAIT", f"'{desc}' TIMEOUT ({timeout}s)")
    return False


def find_pids(pattern: str) -> list[int]:
    """Find PIDs matching full command line (like pgrep -f).

    Filters out own PID to prevent self-match.
    """
    r = subprocess.run(
        ["pgrep", "-f", pattern],
        capture_output=True, text=True, timeout=cfg.timeouts.process,
    )
    if r.returncode == 0 and r.stdout.strip():
        own = os.getpid()
        pids = []
        for p in r.stdout.strip().splitlines():
            p = p.strip()
            if not p:
                continue
            try:
                pid = int(p)
            except ValueError:
                continue
            if pid != own:
                pids.append(pid)
        return pids
    return []


def kill_pattern(pattern: str, sudo: bool = False) -> None:
    """Kill processes matching pattern. Uses bracket trick to avoid self-match."""
    if not pattern or len(pattern) < 2:
        return
    safe = f"[{pattern[0]}]{pattern[1:]}"
    cmd = ["pkill", "-f", safe]
    if sudo:
        cmd = ["sudo"] + cmd
    subprocess.run(cmd, capture_output=True, timeout=cfg.timeouts.process)


def killall(name: str, sudo: bool = False) -> None:
    """Kill processes by exact name."""
    cmd = ["killall", name]
    if sudo:
        cmd = ["sudo"] + cmd
    subprocess.run(cmd, capture_output=True, timeout=cfg.timeouts.process)


def kill_by_pid(pid: int, sudo: bool = False) -> bool:
    """Kill a specific process by PID. Returns True if kill succeeded."""
    cmd = ["kill", str(pid)]
    if sudo:
        cmd = ["sudo"] + cmd
    r = subprocess.run(cmd, capture_output=True, timeout=cfg.timeouts.process)
    return r.returncode == 0


def is_alive(pid: int) -> bool:
    """Check if process is alive (like kill -0)."""
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False
