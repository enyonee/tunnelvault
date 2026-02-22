"""Tests for OpenVPNPlugin: connection with Tunnelblick detection."""

from __future__ import annotations

import contextlib
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from tv.vpn.base import TunnelConfig
from tv.vpn.openvpn import OpenVPNPlugin


@contextlib.contextmanager
def _openvpn_connect_ok(plugin, pids=None):
    """Set up successful OpenVPN connect: no Tunnelblick, PID found, init ok."""
    if pids is None:
        pids = [[], [12345]]
    with patch("tv.vpn.openvpn.proc") as mock_proc, \
         patch("tv.vpn.openvpn.time.sleep"):
        mock_proc.find_pids.side_effect = pids
        mock_proc.run.return_value = subprocess.CompletedProcess([], 0, "", "")
        mock_proc.wait_for.return_value = True
        yield mock_proc


@pytest.fixture
def ovpn_cfg(tmp_dir) -> TunnelConfig:
    return TunnelConfig(
        name="openvpn",
        type="openvpn",
        order=1,
        config_file="client.ovpn",
        log=str(tmp_dir / "openvpn.log"),
    )


@pytest.fixture
def plugin(ovpn_cfg, mock_net, logger, tmp_dir):
    return OpenVPNPlugin(ovpn_cfg, mock_net, logger, tmp_dir)


# =========================================================================
# Meta
# =========================================================================

class TestMeta:
    def test_process_name(self, plugin):
        assert plugin.process_name == "openvpn"

    def test_display_name(self, plugin):
        assert plugin.display_name == "OpenVPN"

    def test_registered(self):
        from tv.vpn.registry import get_plugin
        assert get_plugin("openvpn") is OpenVPNPlugin


# =========================================================================
# Positive: Tunnelblick detection
# =========================================================================

class TestTunnelblickDetection:
    def test_tunnelblick_active_skips_own_openvpn(self, plugin, capsys):
        """Если Tunnelblick + его openvpn живы - пропускаем свой запуск."""
        with patch("tv.vpn.openvpn.proc") as mock_proc:
            mock_proc.find_pids.side_effect = lambda pat: {
                "Tunnelblick": [111],
                "Tunnelblick.*openvpn": [222],
            }.get(pat, [])

            r = plugin.connect()

        assert r.ok is True
        assert r.detail == "Tunnelblick"
        assert r.pid is None  # не наш процесс

    def test_tunnelblick_running_without_openvpn(self, plugin):
        """Tunnelblick запущен, но его openvpn нет - запускаем свой."""
        with patch("tv.vpn.openvpn.proc") as mock_proc, \
             patch("tv.vpn.openvpn.time.sleep"):
            # 1) Tunnelblick? [111]  2) Tunnelblick.*openvpn? []
            # 3) openvpn --config ... ? [12345]
            mock_proc.find_pids.side_effect = [[111], [], [12345]]
            mock_proc.run.return_value = subprocess.CompletedProcess([], 0, "", "")
            mock_proc.wait_for.return_value = True

            r = plugin.connect()

        assert r.ok is True


# =========================================================================
# Positive: successful connection
# =========================================================================

class TestConnectSuccess:
    def test_normal_connection(self, plugin):
        """Нормальный запуск openvpn -> init complete -> ok."""
        with _openvpn_connect_ok(plugin):
            r = plugin.connect()

        assert r.ok is True
        assert r.pid == 12345

    def test_applies_routes_from_config(self, plugin):
        """TOML routes applied after successful connection."""
        plugin.cfg.routes = {"hosts": ["1.2.3.4"], "networks": ["10.0.0.0/8"]}
        plugin.cfg.interface = "tun0"

        with _openvpn_connect_ok(plugin):
            plugin.connect()

        route_calls = plugin.net.add_iface_route.call_args_list
        targets = [c[0][0] for c in route_calls]
        assert "1.2.3.4" in targets
        assert "10.0.0.0/8" in targets

    def test_sets_up_dns_from_config(self, plugin):
        """DNS resolver set up after successful connection."""
        plugin.cfg.dns = {"nameservers": ["10.0.1.1"], "domains": ["corp.local"]}
        plugin.cfg.interface = "tun0"

        with _openvpn_connect_ok(plugin):
            plugin.connect()

        plugin.net.setup_dns_resolver.assert_called_once_with(
            ["corp.local"], ["10.0.1.1"], "tun0",
        )

    def test_no_routes_when_not_configured(self, plugin):
        """No routes/DNS setup when not configured."""
        plugin.cfg.routes = {}
        plugin.cfg.dns = {}

        with _openvpn_connect_ok(plugin):
            plugin.connect()

        plugin.net.add_iface_route.assert_not_called()
        plugin.net.add_host_route.assert_not_called()
        plugin.net.setup_dns_resolver.assert_not_called()

    def test_calls_openvpn_with_correct_args(self, plugin):
        """Проверяем что вызывает openvpn с правильными аргументами."""
        with _openvpn_connect_ok(plugin, pids=[[], [1]]) as mock_proc:
            plugin.connect()

        run_call = mock_proc.run.call_args_list[0]
        cmd = run_call[0][0]
        assert "openvpn" in cmd
        assert "--daemon" in cmd
        assert "--log" in cmd
        assert run_call[1].get("sudo") is True


# =========================================================================
# Negative / inverse: connection failures
# =========================================================================

class TestConnectFailure:
    def test_no_pid_after_start(self, plugin, capsys):
        """openvpn запустился, но PID не найден -> fail."""
        ovpn_log = Path(plugin.cfg.log)
        ovpn_log.write_text("")

        with patch("tv.vpn.openvpn.proc") as mock_proc, \
             patch("tv.vpn.openvpn.time.sleep"):
            mock_proc.find_pids.side_effect = [
                [],  # Tunnelblick
                [],  # openvpn PID -> не найден!
            ]
            mock_proc.run.return_value = subprocess.CompletedProcess([], 0, "", "")

            r = plugin.connect()

        assert r.ok is False

    def test_init_sequence_timeout(self, plugin, capsys):
        """PID есть, но init sequence не завершается -> fail."""
        ovpn_log = Path(plugin.cfg.log)
        ovpn_log.write_text("")

        with patch("tv.vpn.openvpn.proc") as mock_proc, \
             patch("tv.vpn.openvpn.time.sleep"):
            mock_proc.find_pids.side_effect = [
                [],       # Tunnelblick
                [12345],  # openvpn PID
            ]
            mock_proc.run.return_value = subprocess.CompletedProcess([], 0, "", "")
            mock_proc.wait_for.return_value = False  # timeout!

            r = plugin.connect()

        assert r.ok is False

    def test_failure_shows_log_tail(self, plugin, capsys):
        """При ошибке показывает хвост лога."""
        ovpn_log = Path(plugin.cfg.log)
        ovpn_log.write_text("")

        with patch("tv.vpn.openvpn.proc") as mock_proc, \
             patch("tv.vpn.openvpn.time.sleep"):
            mock_proc.find_pids.side_effect = [[], []]
            # Первый вызов run - запуск openvpn, второй - tail лога
            mock_proc.run.side_effect = [
                subprocess.CompletedProcess([], 0, "", ""),          # openvpn launch
                subprocess.CompletedProcess([], 0, "TLS Error\n", ""),  # tail log
            ]

            r = plugin.connect()

        assert r.ok is False
        out = capsys.readouterr().out
        assert "TLS Error" in out

    def test_failure_empty_log(self, plugin, capsys):
        """Лог пуст - показываем это."""
        ovpn_log = Path(plugin.cfg.log)
        ovpn_log.write_text("")

        with patch("tv.vpn.openvpn.proc") as mock_proc, \
             patch("tv.vpn.openvpn.time.sleep"):
            mock_proc.find_pids.side_effect = [[], []]
            mock_proc.run.side_effect = [
                subprocess.CompletedProcess([], 0, "", ""),  # openvpn launch
                subprocess.CompletedProcess([], 0, "", ""),  # tail -> empty
            ]

            r = plugin.connect()

        assert r.ok is False
        out = capsys.readouterr().out
        assert "Лог пуст" in out


# =========================================================================
# Disconnect
# =========================================================================

class TestDisconnect:
    def test_disconnect_by_pid(self, plugin):
        """With PID set, disconnect kills by PID first."""
        plugin._pid = 12345
        with patch("tv.vpn.base.proc") as mock_proc:
            mock_proc.is_alive.side_effect = [True, False]
            mock_proc.kill_by_pid.return_value = True

            plugin.disconnect()

        mock_proc.kill_by_pid.assert_called_once_with(12345, sudo=True)

    def test_disconnect_fallback_pattern(self, plugin):
        """Without PID, disconnect uses per-instance patterns."""
        plugin._pid = None
        with patch("tv.vpn.openvpn.proc") as mock_proc:
            plugin.disconnect()

        patterns = [c[0][0] for c in mock_proc.kill_pattern.call_args_list]
        assert any("client.ovpn" in p for p in patterns)

    def test_disconnect_pid_timeout_warns_and_falls_through(self, plugin):
        """PID kill timeout -> warning logged + pattern fallback."""
        plugin._pid = 12345
        with patch("tv.vpn.base.proc") as base_proc, \
             patch("tv.vpn.base.time.sleep"), \
             patch("tv.vpn.openvpn.proc") as ovpn_proc:
            base_proc.is_alive.return_value = True  # never dies
            base_proc.kill_by_pid.return_value = True

            plugin.disconnect()

        # Warning logged to file
        log_content = plugin.log.log_path.read_text()
        assert "WARN" in log_content
        assert "12345" in log_content
        assert "pattern fallback" in log_content
        # Pattern fallback called
        assert ovpn_proc.kill_pattern.call_count >= 1

    def test_disconnect_uses_cfg_log_path(self, plugin):
        """Kill pattern uses log path from config, not hardcoded."""
        plugin._pid = None
        with patch("tv.vpn.openvpn.proc") as mock_proc:
            plugin.disconnect()

        patterns = [c[0][0] for c in mock_proc.kill_pattern.call_args_list]
        assert any(str(plugin.cfg.log) in p for p in patterns if "log" in p)
