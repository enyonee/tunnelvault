"""Tests for FortiVPNPlugin: connection with PPP gateway detection."""

from __future__ import annotations

import contextlib
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from tv.vpn.base import TunnelConfig
from tv.vpn.fortivpn import FortiVPNPlugin, _detect_ppp_gateway


@contextlib.contextmanager
def _patch_config_file():
    """Patch os calls for connect() predictable config file."""
    with patch("tv.vpn.fortivpn.os.open", return_value=99), \
         patch("tv.vpn.fortivpn.os.write"), \
         patch("tv.vpn.fortivpn.os.close"), \
         patch("tv.vpn.fortivpn.os.unlink") as mock_unlink:
        yield mock_unlink


def _setup_mock_net_snapshot(mock_net):
    """Configure mock_net.interfaces() to simulate ppp0 appearing after connect.

    First call returns {en0, lo0} (before snapshot).
    Subsequent calls return {en0, lo0, ppp0} (after connect).
    """
    call_count = 0
    ifaces_before = {"en0": "192.168.1.7", "lo0": "127.0.0.1"}
    ifaces_after = {"en0": "192.168.1.7", "lo0": "127.0.0.1", "ppp0": "10.0.0.2"}

    def _interfaces():
        nonlocal call_count
        call_count += 1
        return ifaces_before if call_count == 1 else ifaces_after

    mock_net.interfaces.side_effect = _interfaces


@pytest.fixture
def forti_cfg(tmp_dir) -> TunnelConfig:
    return TunnelConfig(
        name="office",
        type="fortivpn",
        order=2,
        log=str(tmp_dir / "openfortivpn.log"),
        auth={
            "host": "vpn.example.com",
            "port": "44333",
            "login": "testuser",
            "pass": "testpass",
            "cert_mode": "manual",
            "trusted_cert": "abcdef1234567890" * 4,
        },
        routes={"networks": ["192.168.100.0/24", "10.0.0.0/8"]},
        dns={"nameservers": ["10.0.1.1", "10.0.1.2"], "domains": ["corp.local", "internal.local"]},
        extra={"fallback_gateway": "169.254.2.1"},
    )


@pytest.fixture
def plugin(forti_cfg, mock_net, logger, tmp_dir):
    _setup_mock_net_snapshot(mock_net)
    return FortiVPNPlugin(forti_cfg, mock_net, logger, tmp_dir)


@contextlib.contextmanager
def _forti_connect_ok(plugin, log_text="remote IP address = 10.0.0.1\n"):
    """Set up successful FortiVPN connect: log, popen(pid=9999), ppp0 detected."""
    forti_log = Path(plugin.cfg.log)
    forti_log.parent.mkdir(parents=True, exist_ok=True)
    forti_log.write_text(log_text)
    mock_popen = MagicMock()
    mock_popen.pid = 9999
    with _patch_config_file() as mock_unlink, \
         patch("tv.vpn.fortivpn.proc") as mock_proc:
        mock_proc.run_background.return_value = mock_popen
        mock_proc.wait_for.side_effect = lambda desc, fn, *a, **kw: fn() or fn()
        plugin.net.iface_info.return_value = "ppp0: flags=8051<UP>"
        yield mock_proc, mock_unlink


@contextlib.contextmanager
def _forti_connect_fail(plugin, log_text="", poll=1, is_alive=False):
    """Set up failing FortiVPN connect: log, popen(pid=9999), wait_for=False."""
    forti_log = Path(plugin.cfg.log)
    forti_log.parent.mkdir(parents=True, exist_ok=True)
    forti_log.write_text(log_text)
    mock_popen = MagicMock()
    mock_popen.pid = 9999
    mock_popen.poll.return_value = poll
    with _patch_config_file(), patch("tv.vpn.fortivpn.proc") as mock_proc:
        mock_proc.run_background.return_value = mock_popen
        mock_proc.wait_for.return_value = False
        mock_proc.is_alive.return_value = is_alive
        yield mock_proc


# =========================================================================
# Meta
# =========================================================================

class TestMeta:
    def test_process_name(self, plugin):
        assert plugin.process_name == "openfortivpn"

    def test_display_name(self, plugin):
        assert plugin.display_name == "FortiVPN"

    def test_registered(self):
        from tv.vpn.registry import get_plugin
        assert get_plugin("fortivpn") is FortiVPNPlugin


# =========================================================================
# Positive: PPP gateway detection
# =========================================================================

class TestDetectPppGateway:
    def test_from_log_remote_ip(self, tmp_path, mock_net):
        """Находит gateway из строки 'remote ip address' в логе."""
        log = tmp_path / "forti.log"
        log.write_text("INFO: remote IP address = 192.168.100.1\n")
        gw = _detect_ppp_gateway(log, mock_net)
        assert gw == "192.168.100.1"

    def test_from_log_ppp_gateway(self, tmp_path, mock_net):
        """Находит gateway из строки 'PPP gateway'."""
        log = tmp_path / "forti.log"
        log.write_text("PPP gateway: 10.0.0.1\n")
        gw = _detect_ppp_gateway(log, mock_net)
        assert gw == "10.0.0.1"

    def test_from_log_peer_keyword(self, tmp_path, mock_net):
        """Находит gateway из строки с 'peer'."""
        log = tmp_path / "forti.log"
        log.write_text("peer address: 172.16.0.1\n")
        gw = _detect_ppp_gateway(log, mock_net)
        assert gw == "172.16.0.1"

    @patch("tv.vpn.fortivpn.time.sleep")  # не ждать 5с
    @patch("platform.system", return_value="Darwin")
    def test_ifconfig_fallback_darwin(self, _, mock_sleep, tmp_path, mock_net):
        """Если лог пуст - fallback на ifconfig ppp0 (Darwin)."""
        log = tmp_path / "forti.log"
        log.write_text("")
        mock_net.iface_info.return_value = (
            "ppp0: flags=8051<UP>\n"
            "\tinet 10.0.0.2 --> 10.0.0.1 netmask 0xffffffff\n"
        )
        gw = _detect_ppp_gateway(log, mock_net)
        assert gw == "10.0.0.1"

    @patch("tv.vpn.fortivpn.time.sleep")
    @patch("platform.system", return_value="Linux")
    def test_ifconfig_fallback_linux(self, _, mock_sleep, tmp_path, mock_net):
        """Linux ifconfig формат: P-t-P:X.X.X.X."""
        log = tmp_path / "forti.log"
        log.write_text("")
        mock_net.iface_info.return_value = (
            "ppp0 Link encap:PPP\n"
            "inet addr:10.0.0.2  P-t-P:10.0.0.1  Mask:255.255.255.255\n"
        )
        gw = _detect_ppp_gateway(log, mock_net)
        assert gw == "10.0.0.1"


# =========================================================================
# Negative / inverse: PPP gateway failures
# =========================================================================

class TestDetectPppGatewayInverse:
    @patch("tv.vpn.fortivpn.time.sleep")
    def test_empty_log_no_ifconfig(self, mock_sleep, tmp_path, mock_net):
        """Лог пуст + ifconfig ppp0 пуст -> пустой gateway."""
        log = tmp_path / "forti.log"
        log.write_text("")
        mock_net.iface_info.return_value = ""
        gw = _detect_ppp_gateway(log, mock_net)
        assert gw == ""

    @patch("tv.vpn.fortivpn.time.sleep")
    def test_log_no_ip_in_matching_line(self, mock_sleep, tmp_path, mock_net):
        """Строка с keyword, но без IP."""
        log = tmp_path / "forti.log"
        log.write_text("peer: unknown\n")
        mock_net.iface_info.return_value = ""
        gw = _detect_ppp_gateway(log, mock_net)
        assert gw == ""

    @patch("tv.vpn.fortivpn.time.sleep")
    def test_log_file_not_found(self, mock_sleep, tmp_path, mock_net):
        """Файл лога не существует - OSError, не crash."""
        log = tmp_path / "nonexistent.log"
        mock_net.iface_info.return_value = ""
        gw = _detect_ppp_gateway(log, mock_net)
        assert gw == ""


# =========================================================================
# Positive: full connect flow
# =========================================================================

class TestConnectSuccess:
    def test_successful_connection(self, plugin):
        """Нормальный коннект: ppp interface detected via snapshot, gateway найден."""
        with _forti_connect_ok(plugin):
            r = plugin.connect()

        assert r.ok is True
        assert r.pid == 9999
        assert plugin._pid == 9999
        assert plugin.cfg.interface == "ppp0"

    def test_uses_config_file_not_cli_password(self, plugin):
        """Пароль передаётся через predictable config, а не CLI -p."""
        with _forti_connect_ok(plugin) as (mock_proc, _):
            plugin.connect()
            cmd = mock_proc.run_background.call_args[0][0]
            assert "-c" in cmd
            assert "-p" not in cmd
            assert plugin.cfg.auth["pass"] not in cmd

    def test_predictable_config_path(self, plugin):
        """Config path uses tunnel name, not random tempfile."""
        with _forti_connect_ok(plugin) as (mock_proc, _):
            plugin.connect()
            forti_cmd = mock_proc.run_background.call_args_list[0][0][0]
            assert f"/tmp/forti_{plugin.cfg.name}.conf" in forti_cmd

    def test_sets_network_routes(self, plugin):
        """После коннекта добавляет маршруты через detected interface."""
        with _forti_connect_ok(plugin):
            plugin.connect()

        iface_calls = plugin.net.add_iface_route.call_args_list
        added_targets = [c[0][0] for c in iface_calls]
        for net_route in plugin.cfg.routes["networks"]:
            assert net_route in added_targets

    def test_adds_host_routes_from_targets(self, plugin):
        """После коннекта добавляет host-маршруты через detected interface."""
        plugin.cfg.routes["hosts"] = ["git.corp.com", "5.6.7.8"]
        with _forti_connect_ok(plugin):
            plugin.connect()

        iface_calls = plugin.net.add_iface_route.call_args_list
        added_targets = [c[0][0] for c in iface_calls]
        assert "git.corp.com" in added_targets
        assert "5.6.7.8" in added_targets

    def test_sets_dns_resolvers(self, plugin):
        """После коннекта настраивает DNS resolver."""
        with _forti_connect_ok(plugin):
            plugin.connect()

        plugin.net.setup_dns_resolver.assert_called_once()
        domains_arg = plugin.net.setup_dns_resolver.call_args[0][0]
        assert domains_arg == plugin.cfg.dns["domains"]


# =========================================================================
# Negative / inverse: connection failures
# =========================================================================

class TestConnectFailure:
    def test_ppp_timeout(self, plugin, capsys):
        """ppp interface не появляется за 20с -> fail."""
        with _forti_connect_fail(plugin, "ERROR: connection refused\n"):
            r = plugin.connect()

        assert r.ok is False
        assert r.pid == 9999

    def test_process_alive_but_no_ppp(self, plugin, capsys):
        """Процесс жив, но ppp нет - показывает warning."""
        with _forti_connect_fail(plugin, "Negotiating...\n", is_alive=True):
            r = plugin.connect()

        assert r.ok is False
        out = capsys.readouterr().out
        assert "PID=9999" in out

    def test_process_crashed_shows_exit_code(self, plugin, capsys):
        """Процесс упал - показывает exit code."""
        with _forti_connect_fail(plugin, "FATAL: auth failed\n", poll=2):
            r = plugin.connect()

        assert r.ok is False
        out = capsys.readouterr().out
        assert "FATAL: auth failed" in out

    def test_empty_log_on_failure(self, plugin, capsys):
        """Лог пуст при ошибке - не падает, показывает сообщение."""
        with _forti_connect_fail(plugin):
            r = plugin.connect()

        assert r.ok is False
        out = capsys.readouterr().out
        assert "Лог пуст" in out

    def test_poll_none_shows_question_mark(self, plugin, capsys):
        """poll() возвращает None - показываем '?' вместо None."""
        with _forti_connect_fail(plugin, "something\n", poll=None):
            r = plugin.connect()

        out = capsys.readouterr().out
        assert "?" in out
        assert "None" not in out

    def test_no_ppp_gateway_uses_fallback(self, plugin, capsys):
        """Не нашли PPP gateway - используем fallback."""
        with _forti_connect_ok(plugin, log_text=""), \
             patch("tv.vpn.fortivpn._detect_ppp_gateway", return_value=""):
            r = plugin.connect()

        assert r.ok is True
        out = capsys.readouterr().out
        assert "fallback" in out

    def test_no_fallback_gateway(self, plugin, capsys):
        """Нет fallback gateway - warn, но ok."""
        plugin.cfg.extra = {}
        with _forti_connect_ok(plugin, log_text=""), \
             patch("tv.vpn.fortivpn._detect_ppp_gateway", return_value=""):
            r = plugin.connect()

        assert r.ok is True
        out = capsys.readouterr().out
        assert "маршруты могут не работать" in out

    def test_empty_dns_skips_resolver(self, tmp_dir, mock_net, logger):
        """Пустые dns domains/nameservers - не вызывает setup_dns_resolver."""
        cfg = TunnelConfig(
            name="nodns", type="fortivpn", order=2,
            log=str(tmp_dir / "openfortivpn.log"),
            auth={"host": "vpn.test", "port": "443", "login": "u", "pass": "p", "trusted_cert": "abc"},
            dns={},  # empty!
        )
        _setup_mock_net_snapshot(mock_net)
        p = FortiVPNPlugin(cfg, mock_net, logger, tmp_dir)

        with _forti_connect_ok(p):
            p.connect()

        mock_net.setup_dns_resolver.assert_not_called()

    def test_config_not_deleted_after_connect(self, plugin):
        """Config file is NOT deleted after connect (kept for disconnect)."""
        with _forti_connect_ok(plugin) as (_, mock_unlink):
            plugin.connect()

        mock_unlink.assert_not_called()


# =========================================================================
# Disconnect
# =========================================================================

class TestPlatformPing:
    """Background ping uses correct flags per platform."""

    @pytest.mark.parametrize("platform,flag,absent_flag", [
        ("Darwin", "-t", "-W"),
        ("Linux", "-W", "-t"),
    ])
    def test_ping_uses_platform_flag(self, plugin, platform, flag, absent_flag):
        with _forti_connect_ok(plugin) as (mock_proc, _), \
             patch("tv.vpn.fortivpn.platform.system", return_value=platform):
            plugin.connect()

        ping_calls = [
            c for c in mock_proc.run_background.call_args_list
            if c[0][0][0] == "ping"
        ]
        assert len(ping_calls) == 1
        ping_cmd = ping_calls[0][0][0]
        assert flag in ping_cmd
        assert absent_flag not in ping_cmd


class TestDnsInterface:
    """DNS resolver uses detected ppp interface."""

    def test_dns_passes_detected_interface(self, plugin):
        """setup_dns_resolver called with dynamically detected interface."""
        with _forti_connect_ok(plugin):
            plugin.connect()

        dns_call = plugin.net.setup_dns_resolver.call_args
        assert dns_call is not None
        assert dns_call[0][2] == "ppp0"


# =========================================================================
# Disconnect
# =========================================================================

class TestDisconnect:
    def test_disconnect_by_pid(self, plugin):
        """With PID set, disconnect kills by PID."""
        plugin._pid = 12345
        with patch("tv.vpn.base.proc") as mock_proc, \
             patch("tv.vpn.fortivpn.os.unlink"):
            mock_proc.is_alive.side_effect = [True, False]
            mock_proc.kill_by_pid.return_value = True

            plugin.disconnect()

        mock_proc.kill_by_pid.assert_called_once_with(12345, sudo=True)

    def test_disconnect_fallback_pattern(self, plugin):
        """Without PID, disconnect uses pattern match."""
        plugin._pid = None
        with patch("tv.vpn.fortivpn.proc") as mock_proc, \
             patch("tv.vpn.fortivpn.os.unlink"):
            plugin.disconnect()

        mock_proc.kill_pattern.assert_called_once_with(
            f"openfortivpn -c /tmp/forti_{plugin.cfg.name}.conf", sudo=True
        )

    def test_disconnect_pid_timeout_warns_and_pattern_fallback(self, plugin):
        """PID kill timeout -> warning logged + pattern fallback + config cleaned."""
        plugin._pid = 12345
        plugin._conf_path = "/tmp/forti_office.conf"
        with patch("tv.vpn.base.proc") as base_proc, \
             patch("tv.vpn.base.time.sleep"), \
             patch("tv.vpn.fortivpn.proc") as forti_proc, \
             patch("tv.vpn.fortivpn.os.unlink") as mock_unlink:
            base_proc.is_alive.return_value = True  # never dies
            base_proc.kill_by_pid.return_value = True

            plugin.disconnect()

        # Warning logged
        log_content = plugin.log.log_path.read_text()
        assert "WARN" in log_content
        assert "12345" in log_content
        assert "pattern fallback" in log_content
        # Pattern fallback called
        forti_proc.kill_pattern.assert_called_once()
        # Config cleaned up
        mock_unlink.assert_called_once_with("/tmp/forti_office.conf")

    def test_disconnect_cleans_config(self, plugin):
        """Disconnect removes temp config file."""
        plugin._pid = None
        plugin._conf_path = "/tmp/forti_test.conf"
        with patch("tv.vpn.fortivpn.proc"), \
             patch("tv.vpn.fortivpn.os.unlink") as mock_unlink:
            plugin.disconnect()

        mock_unlink.assert_called_once_with("/tmp/forti_test.conf")

    def test_disconnect_ignores_missing_config(self, plugin):
        """Disconnect doesn't crash if config already deleted."""
        plugin._pid = None
        with patch("tv.vpn.fortivpn.proc"), \
             patch("tv.vpn.fortivpn.os.unlink", side_effect=OSError):
            plugin.disconnect()  # no exception
