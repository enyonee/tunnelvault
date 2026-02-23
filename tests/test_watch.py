"""Tests for tv.watch module."""

from __future__ import annotations

from datetime import datetime
from unittest.mock import patch

import pytest

from tv.watch import (
    Connection,
    TunnelSnapshot,
    _fmt_rate,
    _fmt_total,
    _port_label,
    _build_display,
    _darwin_vpn_ifaces,
    _darwin_iface_bytes,
    _darwin_connections,
    _linux_vpn_ifaces,
    _linux_iface_bytes,
    _linux_connections,
)


# =========================================================================
# Formatting
# =========================================================================

class TestFormatting:
    def test_fmt_rate_bytes(self):
        assert _fmt_rate(500) == "500 B/s"

    def test_fmt_rate_kilobytes(self):
        assert _fmt_rate(12345) == "12.1 KB/s"

    def test_fmt_rate_megabytes(self):
        assert _fmt_rate(1234567) == "1.2 MB/s"

    def test_fmt_rate_zero(self):
        assert _fmt_rate(0) == "0 B/s"

    def test_fmt_total_bytes(self):
        assert _fmt_total(500) == "500 B"

    def test_fmt_total_kb(self):
        assert _fmt_total(12345) == "12.1 KB"

    def test_fmt_total_mb(self):
        assert _fmt_total(1234567) == "1.2 MB"

    def test_fmt_total_gb(self):
        assert _fmt_total(1234567890) == "1.1 GB"

    def test_port_label_https(self):
        assert _port_label("10.0.0.1:443") == "HTTPS"

    def test_port_label_ssh(self):
        assert _port_label("10.0.0.1:22") == "SSH"

    def test_port_label_unknown(self):
        assert _port_label("10.0.0.1:9999") == ""

    def test_port_label_no_port(self):
        assert _port_label("10.0.0.1") == ""


# =========================================================================
# macOS parsing
# =========================================================================

class TestDarwinVpnIfaces:
    IFCONFIG_OUTPUT = """\
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 192.168.1.7 netmask 0xffffff00 broadcast 192.168.1.255
utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500
\tinet 10.8.0.22 --> 10.8.0.21 netmask 0xffffffff
ppp0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1400
\tinet 10.0.0.2 --> 10.0.0.1 netmask 0xffffffff
"""

    def test_parses_vpn_interfaces(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 0
            mock_cmd.return_value.stdout = self.IFCONFIG_OUTPUT
            result = _darwin_vpn_ifaces()

        assert result == {"utun4": "10.8.0.22", "ppp0": "10.0.0.2"}
        assert "en0" not in result
        assert "lo0" not in result

    def test_empty_on_failure(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 1
            mock_cmd.return_value.stdout = ""
            assert _darwin_vpn_ifaces() == {}


class TestDarwinIfaceBytes:
    NETSTAT_IB_OUTPUT = """\
Name    Mtu   Network       Address            Ipkts Ierrs  Ibytes    Opkts Oerrs  Obytes    Coll
lo0     16384 <Link#1>                          1234     0   56789     1234     0   56789       0
en0     1500  <Link#6>                         12345     0  987654     6543     0  654321       0
utun4   1500  <Link#17>                          100     0  100000       50     0   50000       0
utun4   1500  10.8.0/24     10.8.0.22            100     0  100000       50     0   50000       0
"""

    def test_parses_vpn_bytes(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 0
            mock_cmd.return_value.stdout = self.NETSTAT_IB_OUTPUT
            result = _darwin_iface_bytes()

        assert result == {"utun4": (100000, 50000)}
        assert "en0" not in result

    def test_empty_on_failure(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 1
            mock_cmd.return_value.stdout = ""
            assert _darwin_iface_bytes() == {}


class TestDarwinConnections:
    NETSTAT_AN_OUTPUT = """\
Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
tcp4       0      0  10.8.0.22.54108        10.1.5.30.443          ESTABLISHED
tcp4       0      0  10.8.0.22.54109        10.1.5.31.22           ESTABLISHED
tcp4       0      0  192.168.1.7.55000      34.120.1.1.443         ESTABLISHED
tcp4       0      0  *.631                  *.*                    LISTEN
tcp4       0      0  10.8.0.22.54110        10.1.5.32.80           TIME_WAIT
"""

    def test_filters_by_local_ip(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 0
            mock_cmd.return_value.stdout = self.NETSTAT_AN_OUTPUT
            result = _darwin_connections({"10.8.0.22"})

        assert len(result) == 3  # 2 ESTABLISHED + 1 TIME_WAIT
        assert result[0].local == "10.8.0.22:54108"
        assert result[0].remote == "10.1.5.30:443"
        assert result[0].state == "ESTAB"

    def test_excludes_listen(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 0
            mock_cmd.return_value.stdout = self.NETSTAT_AN_OUTPUT
            result = _darwin_connections({"10.8.0.22"})

        states = [c.state for c in result]
        assert "LISTE" not in states

    def test_excludes_non_vpn_ip(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 0
            mock_cmd.return_value.stdout = self.NETSTAT_AN_OUTPUT
            result = _darwin_connections({"10.8.0.22"})

        local_ips = {c.local.rsplit(":", 1)[0] for c in result}
        assert "192.168.1.7" not in local_ips

    def test_empty_on_failure(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 1
            mock_cmd.return_value.stdout = ""
            assert _darwin_connections({"10.8.0.22"}) == []


# =========================================================================
# Linux parsing
# =========================================================================

class TestLinuxVpnIfaces:
    IP_BR_OUTPUT = """\
lo               UNKNOWN        127.0.0.1/8
eth0             UP             192.168.1.5/24
tun0             UNKNOWN        10.8.0.22/24
ppp0             UP             10.0.0.2 peer 10.0.0.1
"""

    def test_parses_vpn_interfaces(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 0
            mock_cmd.return_value.stdout = self.IP_BR_OUTPUT
            result = _linux_vpn_ifaces()

        assert result == {"tun0": "10.8.0.22", "ppp0": "10.0.0.2"}
        assert "eth0" not in result

    def test_empty_on_failure(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 1
            mock_cmd.return_value.stdout = ""
            assert _linux_vpn_ifaces() == {}


class TestLinuxIfaceBytes:
    PROC_NET_DEV = """\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 123456    1234    0    0    0     0          0         0   123456    1234    0    0    0     0       0          0
  eth0: 987654   12345    0    0    0     0          0         0   654321    6543    0    0    0     0       0          0
  tun0: 100000     100    0    0    0     0          0         0    50000      50    0    0    0     0       0          0
"""

    def test_parses_vpn_bytes(self):
        with patch("builtins.open", create=True) as mock_open:
            mock_open.return_value.__enter__ = lambda s: s
            mock_open.return_value.__exit__ = lambda *a: None
            mock_open.return_value.readlines.return_value = self.PROC_NET_DEV.splitlines(True)
            result = _linux_iface_bytes()

        assert result == {"tun0": (100000, 50000)}
        assert "eth0" not in result

    def test_empty_on_error(self):
        with patch("builtins.open", side_effect=OSError):
            assert _linux_iface_bytes() == {}


class TestLinuxConnections:
    SS_TN_OUTPUT = """\
State      Recv-Q Send-Q Local Address:Port   Peer Address:Port Process
ESTAB      0      0      10.8.0.22:54108      10.1.5.30:443
ESTAB      0      0      10.8.0.22:54109      10.1.5.31:22
ESTAB      0      0      192.168.1.7:55000    34.120.1.1:443
TIME-WAIT  0      0      10.8.0.22:54110      10.1.5.32:80
"""

    def test_filters_by_local_ip(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 0
            mock_cmd.return_value.stdout = self.SS_TN_OUTPUT
            result = _linux_connections({"10.8.0.22"})

        assert len(result) == 3
        assert result[0].local == "10.8.0.22:54108"
        assert result[0].remote == "10.1.5.30:443"

    def test_excludes_non_vpn_ip(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 0
            mock_cmd.return_value.stdout = self.SS_TN_OUTPUT
            result = _linux_connections({"10.8.0.22"})

        local_ips = {c.local.rsplit(":", 1)[0] for c in result}
        assert "192.168.1.7" not in local_ips

    def test_empty_on_failure(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 1
            mock_cmd.return_value.stdout = ""
            assert _linux_connections({"10.8.0.22"}) == []


# =========================================================================
# Display rendering
# =========================================================================

class TestBuildDisplay:
    def test_renders_with_snapshots(self):
        snapshots = [
            TunnelSnapshot(
                name="fortivpn", interface="ppp0", ip="10.0.0.2",
                bytes_in=100000, bytes_out=50000,
                rate_in=1234.0, rate_out=567.0,
                connections=[
                    Connection("10.0.0.2:54108", "10.1.5.30:443", "ESTAB"),
                ],
            ),
        ]
        panel = _build_display(snapshots, datetime(2025, 1, 15, 14, 32, 5))
        # Should not raise; panel is a rich renderable
        assert panel is not None

    def test_renders_empty(self):
        panel = _build_display([], datetime(2025, 1, 15, 14, 32, 5))
        assert panel is not None

    def test_renders_no_connections(self):
        snapshots = [
            TunnelSnapshot(
                name="singbox", interface="utun99", ip="172.16.0.1",
            ),
        ]
        panel = _build_display(snapshots, datetime(2025, 1, 15, 14, 32, 5))
        assert panel is not None

    def test_renders_many_connections_truncated(self):
        conns = [
            Connection(f"10.0.0.2:{50000 + i}", f"10.1.5.{i}:443", "ESTAB")
            for i in range(50)
        ]
        snapshots = [
            TunnelSnapshot(
                name="test", interface="ppp0", ip="10.0.0.2",
                connections=conns,
            ),
        ]
        panel = _build_display(snapshots, datetime(2025, 1, 15, 14, 32, 5))
        assert panel is not None

    def test_renders_multiple_tunnels(self):
        snapshots = [
            TunnelSnapshot(name="vpn1", interface="ppp0", ip="10.0.0.2"),
            TunnelSnapshot(name="vpn2", interface="utun99", ip="172.16.0.1"),
        ]
        panel = _build_display(snapshots, datetime(2025, 1, 15, 14, 32, 5))
        assert panel is not None
