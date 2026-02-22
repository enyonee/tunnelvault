"""Health checks: ports, ping, DNS, HTTP."""

from __future__ import annotations

import os
import platform
import subprocess
from dataclasses import dataclass
from typing import Callable, Optional

from tv import ui
from tv.app_config import cfg
from tv.logger import Logger


@dataclass
class CheckResult:
    label: str
    status: str   # "ok" | "fail" | "skip"
    detail: str


# --- Check primitives (each returns True on success) ---

def _run_check(cmd: list[str], timeout: int | None = None) -> subprocess.CompletedProcess:
    """subprocess.run with timeout protection for check commands."""
    if timeout is None:
        timeout = cfg.timeouts.check_subprocess
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(args=cmd, returncode=-1, stdout="", stderr="timeout")


def _check_port(host: str, port: int, timeout: int | None = None) -> bool:
    if timeout is None:
        timeout = cfg.timeouts.check_port
    r = _run_check(["nc", "-z", "-w", str(timeout), host, str(port)], timeout + 2)
    return r.returncode == 0


def _check_ping(host: str, timeout: int | None = None) -> bool:
    if timeout is None:
        timeout = cfg.timeouts.check_ping
    if platform.system() == "Darwin":
        # macOS: -W is in milliseconds, -t is total timeout in seconds
        args = ["ping", "-c", "1", "-t", str(timeout), host]
    else:
        # Linux: -W is in seconds
        args = ["ping", "-c", "1", "-W", str(timeout), host]
    r = _run_check(args, timeout + 2)
    return r.returncode == 0


def _check_dns(name: str, server: str, timeout: int | None = None) -> bool:
    if timeout is None:
        timeout = cfg.timeouts.check_dns
    r = _run_check(["nslookup", name, server], timeout)
    return r.returncode == 0


def _check_http(url: str, timeout: int | None = None) -> bool:
    if timeout is None:
        timeout = cfg.timeouts.check_http
    r = _run_check(
        ["curl", "-4", "-sk", "--max-time", str(timeout),
         "-o", os.devnull, "-w", "%{http_code}", url],
        timeout + 2,
    )
    if r.returncode != 0:
        return False
    code = r.stdout.strip()
    return code != "000" and code.startswith(("2", "3"))


def _check_http_any(url: str, timeout: int | None = None) -> bool:
    """Returns True if HTTP response is not a timeout (000)."""
    if timeout is None:
        timeout = cfg.timeouts.check_http
    r = _run_check(
        ["curl", "-4", "-s", "--max-time", str(timeout),
         "-o", os.devnull, "-w", "%{http_code}", url],
        timeout + 2,
    )
    return r.returncode == 0 and r.stdout.strip() != "000"


def _get_external_ip(url: str, timeout: int | None = None) -> Optional[str]:
    if timeout is None:
        timeout = cfg.timeouts.check_external_ip
    r = _run_check(["curl", "-4", "-s", "--max-time", str(timeout), url], timeout + 2)
    if r.returncode == 0 and r.stdout.strip():
        return r.stdout.strip()
    return None


# --- Check runner ---

def _run_one(
    idx: int,
    guard: bool,
    label: str,
    fn: Callable[[], bool],
    ok_msg: str,
    fail_msg: str,
    logger: Optional[Logger],
    cmd_hint: str = "",
) -> CheckResult:
    """Run a single check with terminal output."""
    hint = f" {ui.DIM}{cmd_hint}{ui.NC}" if cmd_hint else ""
    print(f"   {ui.DIM}[{idx}]{ui.NC} {label}{hint} ... ", end="", flush=True)

    if not guard:
        print(f"{ui.YELLOW}⏭{ui.NC}")
        if logger:
            logger.log("CHECK", f"[{idx}] {label} → SKIP")
        return CheckResult(label, "skip", "пропуск")

    try:
        ok = fn()
    except Exception:
        ok = False

    if ok:
        print(f"{ui.GREEN}✅{ui.NC}")
        if logger:
            logger.log("CHECK", f"[{idx}] {label} ({cmd_hint}) → OK ({ok_msg})" if cmd_hint else f"[{idx}] {label} → OK ({ok_msg})")
        return CheckResult(label, "ok", ok_msg)
    else:
        print(f"{ui.RED}❌{ui.NC}")
        if logger:
            logger.log("CHECK", f"[{idx}] {label} ({cmd_hint}) → FAIL ({fail_msg})" if cmd_hint else f"[{idx}] {label} → FAIL ({fail_msg})")
        return CheckResult(label, "fail", fail_msg)


# --- Command hints ---

def _ping_hint(host: str) -> str:
    if platform.system() == "Darwin":
        return f"ping -c1 -t3 {host}"
    return f"ping -c1 -W3 {host}"


def _fallback_hint(fallback: str, host: str) -> str:
    if not fallback or ":" not in fallback:
        return ""
    fb_type, fb_arg = fallback.split(":", 1)
    if fb_type == "port":
        return f"nc -z {host} {fb_arg}"
    if fb_type == "dns":
        return f"nslookup {fb_arg} {host}"
    return ""


# --- Ping with fallback ---

def _parse_fallback(fallback: str, host: str) -> tuple[Callable[[], bool], str] | None:
    """Parse fallback spec like 'port:53' or 'dns:some.host'. Returns (fn, label)."""
    if not fallback or ":" not in fallback:
        return None
    fb_type, fb_arg = fallback.split(":", 1)
    if fb_type == "port":
        try:
            port = int(fb_arg)
        except ValueError:
            return None
        return (lambda h=host, p=port: _check_port(h, p)), f"port:{fb_arg}"
    if fb_type == "dns":
        return (lambda n=fb_arg, s=host: _check_dns(n, s)), f"dns:{fb_arg}"
    return None


def _run_ping_check(
    idx: int,
    guard: bool,
    host: str,
    label: str,
    fallback: str,
    logger: Optional[Logger],
) -> CheckResult:
    """Run ping check with optional fallback strategy."""
    check_label = f"{host} ({label})"
    fb = _parse_fallback(fallback, host)
    has_fb = fb is not None

    # Build command hints
    p_hint = _ping_hint(host)
    fb_cmd_hint = _fallback_hint(fallback, host) if has_fb else ""
    hint_parts = [p_hint]
    if fb_cmd_hint:
        hint_parts.append(f"→ {fb_cmd_hint}")
    cmd_display = " ".join(hint_parts)

    print(f"   {ui.DIM}[{idx}]{ui.NC} {check_label} {ui.DIM}{cmd_display}{ui.NC} ... ", end="", flush=True)

    if not guard:
        print(f"{ui.YELLOW}⏭{ui.NC}")
        if logger:
            logger.log("CHECK", f"[{idx}] {check_label} ({cmd_display}) → SKIP")
        return CheckResult(check_label, "skip", "пропуск")

    # Primary: ping
    try:
        ping_ok = _check_ping(host)
    except Exception:
        ping_ok = False

    if ping_ok:
        print(f"{ui.GREEN}✅{ui.NC}")
        if logger:
            logger.log("CHECK", f"[{idx}] {check_label} ({p_hint}) → OK (ping)")
        return CheckResult(check_label, "ok", "ping ok")

    # Fallback
    if has_fb:
        fb_fn, fb_label = fb
        try:
            fb_ok = fb_fn()
        except Exception:
            fb_ok = False

        if fb_ok:
            print(f"{ui.YELLOW}⚠{ui.NC}{ui.GREEN}✅{ui.NC} {ui.DIM}(fallback: {fb_cmd_hint}){ui.NC}")
            detail = f"fallback: {fb_label}"
            if logger:
                logger.log("CHECK", f"[{idx}] {check_label} ({p_hint} fail → {fb_cmd_hint}) → OK")
            return CheckResult(check_label, "ok", detail)
        else:
            print(f"{ui.RED}❌{ui.NC} {ui.DIM}({p_hint} + {fb_cmd_hint}){ui.NC}")
            detail = f"ping + {fb_label} fail"
            if logger:
                logger.log("CHECK", f"[{idx}] {check_label} ({p_hint} fail, {fb_cmd_hint} fail) → FAIL")
            return CheckResult(check_label, "fail", detail)

    # No fallback, plain fail
    print(f"{ui.RED}❌{ui.NC}")
    if logger:
        logger.log("CHECK", f"[{idx}] {check_label} ({p_hint}) → FAIL (не пингуется)")
    return CheckResult(check_label, "fail", "не пингуется")


# --- Per-tunnel checks ---

def run_all_from_tunnels(
    tunnel_checks: list[tuple[str, bool, dict]],
    logger: Optional[Logger] = None,
) -> tuple[list[CheckResult], str]:
    """Run health checks from per-tunnel check configs.

    Args:
        tunnel_checks: list of (tunnel_name, is_ok, checks_dict)
            checks_dict keys: ports, ping, dns, http, external_ip_url
        logger: optional Logger

    Returns:
        (list[CheckResult], external_ip)
    """
    results: list[CheckResult] = []
    idx = 0
    ext_ip = ""

    if logger:
        logger.log("INFO", "=== Проверки ===")

    print()
    print(f"  {ui.BOLD}🧪 Проверка подключений{ui.NC}")
    print()

    for tunnel_name, is_ok, checks_cfg in tunnel_checks:
        if not checks_cfg:
            continue

        print(f"   {ui.DIM}── {tunnel_name} ──{ui.NC}")

        # Ports
        for entry in checks_cfg.get("ports", []):
            host = entry.get("host", "")
            port = entry.get("port", 0)
            if not host or not port:
                continue
            idx += 1
            results.append(_run_one(
                idx, is_ok, f"{host}:{port}",
                lambda h=host, p=port: _check_port(h, p),
                "порт открыт", "порт закрыт", logger,
                cmd_hint=f"nc -z {host} {port}",
            ))

        # Ping (with optional fallback)
        for entry in checks_cfg.get("ping", []):
            host = entry.get("host", "")
            if not host:
                continue
            label = entry.get("label", host)
            fallback = entry.get("fallback", "")
            idx += 1
            results.append(_run_ping_check(
                idx, is_ok, host, label, fallback, logger,
            ))

        # DNS
        for entry in checks_cfg.get("dns", []):
            name = entry.get("name", "")
            server = entry.get("server", "")
            if not name or not server:
                continue
            idx += 1
            results.append(_run_one(
                idx, is_ok, f"{name} @{server}",
                lambda n=name, s=server: _check_dns(n, s),
                "резолвит", "не резолвит", logger,
                cmd_hint=f"nslookup {name} {server}",
            ))

        # HTTP
        for url in checks_cfg.get("http", []):
            label = url.replace("https://", "").replace("http://", "").rstrip("/")
            idx += 1
            results.append(_run_one(
                idx, is_ok, label,
                lambda u=url: _check_http_any(u),
                "ok", "таймаут", logger,
                cmd_hint=f"curl -s {url}",
            ))

        # External IP (special case)
        ext_ip_url = checks_cfg.get("external_ip_url", "")
        if ext_ip_url:
            idx += 1
            ext_hint = f"curl -s {ext_ip_url}"
            print(f"   {ui.DIM}[{idx}]{ui.NC} Внешний IP {ui.DIM}{ext_hint}{ui.NC} ... ", end="", flush=True)
            if is_ok:
                ext_ip = _get_external_ip(ext_ip_url) or ""
                if ext_ip:
                    print(f"{ui.GREEN}✅{ui.NC} {ui.DIM}({ext_ip}){ui.NC}")
                    results.append(CheckResult("Внешний IP", "ok", ext_ip))
                    if logger:
                        logger.log("CHECK", f"[{idx}] Внешний IP → OK ({ext_ip})")
                else:
                    print(f"{ui.RED}❌{ui.NC}")
                    results.append(CheckResult("Внешний IP", "fail", "таймаут"))
                    if logger:
                        logger.log("CHECK", f"[{idx}] Внешний IP → FAIL (таймаут)")
            else:
                print(f"{ui.YELLOW}⏭{ui.NC}")
                results.append(CheckResult("Внешний IP", "skip", "пропуск"))
                if logger:
                    logger.log("CHECK", f"[{idx}] Внешний IP → SKIP")

    if logger:
        passed = sum(1 for r in results if r.status == "ok")
        failed = sum(1 for r in results if r.status == "fail")
        skipped = sum(1 for r in results if r.status == "skip")
        logger.log("INFO", f"Проверки: passed={passed} failed={failed} skipped={skipped} total={len(results)}")

    return results, ext_ip
