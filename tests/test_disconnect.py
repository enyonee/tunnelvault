"""Tests for tv.disconnect: cleanup and disconnect logic."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from tv.disconnect import run, run_plugins
from tv.vpn.base import TunnelConfig


# =========================================================================
# Fixtures
# =========================================================================

@pytest.fixture
def v3_defs():
    """V3 format defs for disconnect tests."""
    return {
        "routes": {
            "vpn_servers": {
                "hosts": ["203.0.113.10"],
                "resolve": ["vpn.example.com"],
            },
        },
    }


@pytest.fixture
def global_defs():
    """Global format defs for disconnect tests."""
    return {
        "global": {
            "vpn_server_routes": {
                "hosts": ["10.20.30.40"],
                "resolve": ["vpn.corp.com"],
            },
        },
    }


# =========================================================================
# Positive: emergency disconnect (run)
# =========================================================================

class TestDisconnect:
    def test_kills_all_registered_processes(self, mock_net, logger, v3_defs):
        """Kills all process_names from registered plugins."""
        with patch("tv.disconnect.proc") as mock_proc:
            run(net=mock_net, log=logger, defs=v3_defs)

        killall_calls = [c[0][0] for c in mock_proc.killall.call_args_list]
        # All registered plugins' process_names
        assert "openfortivpn" in killall_calls
        assert "openvpn" in killall_calls
        assert "sing-box" in killall_calls

    def test_kills_plugin_patterns(self, mock_net, logger, v3_defs):
        """Kills plugin-specific patterns from kill_patterns class attr."""
        with patch("tv.disconnect.proc") as mock_proc:
            run(net=mock_net, log=logger, defs=v3_defs)

        kill_patterns = [c[0][0] for c in mock_proc.kill_pattern.call_args_list]
        # OpenVPN tunnelvault pattern
        assert any("tunnelvault" in p for p in kill_patterns)
        # FortiVPN sudo pattern
        assert any("sudo openfortivpn" in p for p in kill_patterns)

    def test_removes_static_routes(self, mock_net, logger, v3_defs):
        """Deletes static VPN server routes from defs."""
        with patch("tv.disconnect.proc"):
            run(net=mock_net, log=logger, defs=v3_defs)

        deleted_hosts = [c[0][0] for c in mock_net.delete_host_route.call_args_list]
        assert "203.0.113.10" in deleted_hosts

    def test_resolves_and_removes_routes(self, mock_net, logger, v3_defs):
        """Resolves VPN hostnames and removes routes."""
        mock_net.resolve_host.return_value = ["5.6.7.8", "9.10.11.12"]

        with patch("tv.disconnect.proc"):
            run(net=mock_net, log=logger, defs=v3_defs)

        mock_net.resolve_host.assert_called_with("vpn.example.com")
        deleted_hosts = [c[0][0] for c in mock_net.delete_host_route.call_args_list]
        assert "5.6.7.8" in deleted_hosts
        assert "9.10.11.12" in deleted_hosts

    def test_global_format_routes(self, mock_net, logger, global_defs):
        """Routes from global.vpn_server_routes format."""
        with patch("tv.disconnect.proc"):
            run(net=mock_net, log=logger, defs=global_defs)

        deleted_hosts = [c[0][0] for c in mock_net.delete_host_route.call_args_list]
        assert "10.20.30.40" in deleted_hosts

    def test_restores_ipv6(self, mock_net, logger, v3_defs):
        """Restores IPv6."""
        with patch("tv.disconnect.proc"):
            run(net=mock_net, log=logger, defs=v3_defs)

        mock_net.restore_ipv6.assert_called_once()

    def test_logs_completion(self, mock_net, logger, v3_defs):
        """Logs disconnect completion."""
        with patch("tv.disconnect.proc"):
            run(net=mock_net, log=logger, defs=v3_defs)

        content = logger.log_path.read_text()
        assert "Disconnect завершён" in content

    def test_prints_done_message(self, mock_net, logger, capsys, v3_defs):
        """Prints final message."""
        with patch("tv.disconnect.proc"):
            run(net=mock_net, log=logger, defs=v3_defs)

        out = capsys.readouterr().out
        assert "Всё отключено" in out


# =========================================================================
# Negative / inverse: edge cases
# =========================================================================

class TestDisconnectInverse:
    def test_without_net_creates_default(self, logger, v3_defs):
        """Without net= -> creates NetManager via create()."""
        mock_net_instance = MagicMock()
        mock_net_instance.resolve_host.return_value = []

        with patch("tv.disconnect.proc"), \
             patch("tv.net.create", return_value=mock_net_instance):
            run(net=None, log=logger, defs=v3_defs)

    def test_without_logger_no_crash(self, mock_net, capsys, v3_defs):
        """Without logger -> no crash."""
        with patch("tv.disconnect.proc"):
            run(net=mock_net, log=None, defs=v3_defs)

        out = capsys.readouterr().out
        assert "Всё отключено" in out

    def test_empty_defs_no_crash(self, mock_net, logger, capsys):
        """Empty defs -> nothing to clean, no crash."""
        with patch("tv.disconnect.proc"):
            run(net=mock_net, log=logger, defs={})

        out = capsys.readouterr().out
        assert "Всё отключено" in out

    def test_none_defs_no_crash(self, mock_net, logger, capsys):
        """defs=None -> no crash."""
        with patch("tv.disconnect.proc"):
            run(net=mock_net, log=logger, defs=None)

        out = capsys.readouterr().out
        assert "Всё отключено" in out

    def test_kill_failure_doesnt_stop_cleanup(self, mock_net, logger, capsys, v3_defs):
        """Kill error does NOT stop cleanup."""
        with patch("tv.disconnect.proc") as mock_proc:
            mock_proc.killall.side_effect = Exception("kill failed")
            mock_proc.kill_pattern.side_effect = Exception("kill failed")
            run(net=mock_net, log=logger, defs=v3_defs)

        out = capsys.readouterr().out
        assert "Всё отключено" in out
        mock_net.restore_ipv6.assert_called_once()

    def test_order_kill_before_routes(self, mock_net, logger, v3_defs):
        """Kill processes before deleting routes."""
        call_order = []

        with patch("tv.disconnect.proc") as mock_proc:
            mock_proc.killall.side_effect = lambda *a, **kw: call_order.append("kill")
            mock_proc.kill_pattern.side_effect = lambda *a, **kw: call_order.append("kill")
            mock_net.delete_host_route.side_effect = lambda *a, **kw: call_order.append("route")

            run(net=mock_net, log=logger, defs=v3_defs)

        first_route = call_order.index("route") if "route" in call_order else len(call_order)
        kills_before = [x for x in call_order[:first_route] if x == "kill"]
        assert len(kills_before) > 0


# =========================================================================
# Plugin-driven disconnect (run_plugins)
# =========================================================================

class TestRunPlugins:
    def test_disconnects_in_reverse_order(self, mock_net, logger, capsys):
        """Tunnels disconnected in reverse order."""
        order = []
        tunnels = [
            TunnelConfig(name="first", type="openvpn"),
            TunnelConfig(name="second", type="singbox"),
        ]
        with patch("tv.vpn.openvpn.OpenVPNPlugin.disconnect",
                    side_effect=lambda: order.append("first")), \
             patch("tv.vpn.singbox.SingBoxPlugin.disconnect",
                    side_effect=lambda: order.append("second")):
            run_plugins(tunnels, net=mock_net, log=logger, defs={})

        assert order == ["second", "first"]

    def test_cleans_vpn_server_routes(self, mock_net, logger, capsys):
        """Removes VPN server routes."""
        tunnels = [TunnelConfig(name="t", type="openvpn")]
        defs = {
            "routes": {
                "vpn_servers": {
                    "hosts": ["1.2.3.4"],
                    "resolve": [],
                },
            },
        }
        with patch("tv.vpn.openvpn.OpenVPNPlugin.disconnect"):
            run_plugins(tunnels, net=mock_net, log=logger, defs=defs)

        deleted = [c[0][0] for c in mock_net.delete_host_route.call_args_list]
        assert "1.2.3.4" in deleted

    def test_restores_ipv6(self, mock_net, logger, capsys):
        """Restores IPv6 after plugin disconnect."""
        tunnels = [TunnelConfig(name="t", type="openvpn")]
        with patch("tv.vpn.openvpn.OpenVPNPlugin.disconnect"):
            run_plugins(tunnels, net=mock_net, log=logger, defs={})

        mock_net.restore_ipv6.assert_called_once()

    def test_exception_doesnt_stop_other_tunnels(self, mock_net, logger, capsys):
        """Exception in one tunnel doesn't block others."""
        tunnels = [
            TunnelConfig(name="first", type="openvpn"),
            TunnelConfig(name="second", type="singbox"),
        ]
        with patch("tv.vpn.openvpn.OpenVPNPlugin.disconnect"), \
             patch("tv.vpn.singbox.SingBoxPlugin.disconnect",
                    side_effect=RuntimeError("boom")):
            run_plugins(tunnels, net=mock_net, log=logger, defs={})

        # Still got to the end
        mock_net.restore_ipv6.assert_called_once()

    def test_cleans_dns(self, mock_net, logger, capsys):
        """Cleans up DNS resolvers after disconnect."""
        tunnels = [
            TunnelConfig(
                name="fortivpn", type="fortivpn", order=1,
                dns={"nameservers": ["10.0.1.1"], "domains": ["corp.local"]},
            ),
        ]
        with patch("tv.vpn.fortivpn.proc"), \
             patch("tv.disconnect.proc"):
            run_plugins(tunnels, net=mock_net, log=logger, defs={})

        mock_net.cleanup_dns_resolver.assert_called()

    def test_deletes_routes(self, mock_net, logger, capsys):
        """Deletes tunnel routes after disconnect."""
        tunnels = [
            TunnelConfig(
                name="fortivpn", type="fortivpn", order=1,
                routes={"networks": ["10.0.0.0/8"]},
            ),
        ]
        with patch("tv.vpn.fortivpn.proc"), \
             patch("tv.disconnect.proc"):
            run_plugins(tunnels, net=mock_net, log=logger, defs={})

        mock_net.delete_net_route.assert_called()

    def test_empty_tunnels(self, mock_net, logger, capsys):
        """Empty tunnel list shouldn't crash."""
        run_plugins([], net=mock_net, log=logger, defs={})
        mock_net.restore_ipv6.assert_called_once()
