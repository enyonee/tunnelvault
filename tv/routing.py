"""Parse user-friendly targets into routes + DNS components."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tv.vpn.base import TunnelConfig

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_CIDR_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$")
_WILDCARD_RE = re.compile(r"^\*\.(.+)$")


@dataclass
class ParsedTargets:
    networks: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)


def validate_target(t: str) -> tuple[str, str]:
    """Validate a single target string.

    Returns (type, error):
        type: "network" | "host" | "domain" | "hostname" | "" (if invalid)
        error: human-readable error or "" if valid
    """
    t = t.strip()
    if not t:
        return "", ""

    m = _WILDCARD_RE.match(t)
    if m:
        domain = m.group(1)
        if "." not in domain:
            return "", f"*.{domain} - домен должен содержать точку (*.example.local)"
        return "domain", ""

    if _CIDR_RE.match(t):
        try:
            ipaddress.ip_network(t, strict=False)
        except ValueError:
            return "", f"{t} - невалидный CIDR"
        return "network", ""

    if _IP_RE.match(t):
        try:
            ipaddress.ip_address(t)
        except ValueError:
            return "", f"{t} - невалидный IP-адрес"
        return "host", ""

    # Bare hostname - basic validation
    if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$", t):
        return "hostname", ""

    return "", f"{t} - нераспознанный формат"


def parse_targets(targets: list[str]) -> ParsedTargets:
    """Parse user-friendly targets into routes + dns components.

    Formats:
        *.domain    → dns domain
        x.x.x.x/N  → network route (CIDR)
        x.x.x.x    → host route
        hostname    → host route (resolved at connect time)
    """
    networks: list[str] = []
    hosts: list[str] = []
    domains: list[str] = []

    for t in targets:
        t = t.strip()
        if not t:
            continue

        m = _WILDCARD_RE.match(t)
        if m:
            domains.append(m.group(1))
            continue

        if _CIDR_RE.match(t):
            try:
                ipaddress.ip_network(t, strict=False)
            except ValueError:
                continue
            networks.append(t)
            continue

        if _IP_RE.match(t):
            try:
                ipaddress.ip_address(t)
            except ValueError:
                continue
            hosts.append(t)
            continue

        # Bare hostname
        hosts.append(t)

    return ParsedTargets(networks=networks, hosts=hosts, domains=domains)


def merge_targets_into_config(tcfg: TunnelConfig, parsed: ParsedTargets) -> None:
    """Merge parsed targets into tcfg.routes and tcfg.dns (no duplicates)."""
    existing_nets = set(tcfg.routes.get("networks", []))
    existing_hosts = set(tcfg.routes.get("hosts", []))
    existing_domains = set(tcfg.dns.get("domains", []))

    new_nets = [n for n in parsed.networks if n not in existing_nets]
    new_hosts = [h for h in parsed.hosts if h not in existing_hosts]
    new_domains = [d for d in parsed.domains if d not in existing_domains]

    if new_nets:
        tcfg.routes.setdefault("networks", []).extend(new_nets)
    if new_hosts:
        tcfg.routes.setdefault("hosts", []).extend(new_hosts)
    if new_domains:
        tcfg.dns.setdefault("domains", []).extend(new_domains)
