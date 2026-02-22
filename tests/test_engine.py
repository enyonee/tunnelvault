"""Tests for tv.engine: Engine lifecycle, hooks, setup, connect, checks."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from tv.engine import Engine
from tv.vpn.base import TunnelConfig, TunnelPlugin, VPNResult
from tv.checks import CheckResult


# =========================================================================
# Fixtures
# =========================================================================

@pytest.fixture
def v3_defs(tmp_dir):
    """Minimal v3 defs with two tunnels for Engine tests."""
    return {
        "tunnels": {
            "openvpn": {
                "type": "openvpn",
                "order": 1,
                "config_file": "client.ovpn",
                "routes": {"networks": ["0.0.0.0/0"]},
            },
            "singbox": {
                "type": "singbox",
                "order": 2,
                "config_file": "singbox.json",
                "interface": "utun99",
                "routes": {"networks": ["172.18.0.0/16"]},
            },
        },
        "routes": {
            "vpn_servers": {
                "hosts": ["10.20.30.40"],
                "resolve": ["vpn.test.com"],
            },
        },
    }


@pytest.fixture
def engine(tmp_dir, v3_defs, mock_net, logger):
    """Engine with mocked net and logger."""
    return Engine(tmp_dir, v3_defs, net=mock_net, log=logger)


@pytest.fixture
def _skip_setup_io():
    """Patch out time.sleep used during engine.setup()."""
    with patch("tv.engine.time.sleep"):
        yield


# =========================================================================
# Init
# =========================================================================

class TestEngineInit:
    def test_stores_params(self, engine, tmp_dir, v3_defs, mock_net, logger):
        assert engine.script_dir == tmp_dir
        assert engine.defs is v3_defs
        assert engine.net is mock_net
        assert engine.log is logger
        assert engine.tunnels == []
        assert engine.plugins == []
        assert engine.results == []

    def test_creates_net_and_log_if_not_provided(self, tmp_dir, v3_defs):
        with patch("tv.engine.create_net") as mock_create:
            mock_create.return_value = MagicMock()
            e = Engine(tmp_dir, v3_defs)
        mock_create.assert_called_once()
        assert e.log is not None


# =========================================================================
# Hooks
# =========================================================================

class TestHooks:
    def test_on_registers_hook(self, engine):
        fn = MagicMock()
        engine.on("pre_connect", fn)
        assert fn in engine._hooks["pre_connect"]

    def test_fire_calls_hooks(self, engine):
        fn1 = MagicMock()
        fn2 = MagicMock()
        engine.on("test_event", fn1)
        engine.on("test_event", fn2)

        engine._fire("test_event", key="value")
        fn1.assert_called_once_with(key="value")
        fn2.assert_called_once_with(key="value")

    def test_fire_unknown_event_noop(self, engine):
        engine._fire("nonexistent_event", foo="bar")  # no crash

    def test_multiple_events_independent(self, engine):
        fn_a = MagicMock()
        fn_b = MagicMock()
        engine.on("event_a", fn_a)
        engine.on("event_b", fn_b)

        engine._fire("event_a", x=1)
        fn_a.assert_called_once()
        fn_b.assert_not_called()

    def test_hook_exception_propagates(self, engine):
        """Hook exceptions propagate to caller (caller decides error handling)."""
        bad_hook = MagicMock(side_effect=ValueError("hook broke"))
        engine.on("test_event", bad_hook)

        with pytest.raises(ValueError, match="hook broke"):
            engine._fire("test_event")


# =========================================================================
# Prepare
# =========================================================================

class TestPrepare:
    def test_populates_tunnels(self, engine):
        engine.prepare()
        assert len(engine.tunnels) == 2
        assert engine.tunnels[0].name == "openvpn"
        assert engine.tunnels[1].name == "singbox"

    def test_resolves_config_files(self, engine):
        engine.prepare()
        assert engine.tunnels[0].config_file == "client.ovpn"
        assert engine.tunnels[1].config_file == "singbox.json"

    def test_saves_settings(self, engine, tmp_dir):
        engine.prepare()
        settings_file = tmp_dir / ".vpn-settings.json"
        assert settings_file.exists()

    def test_prepare_is_idempotent(self, engine):
        engine.prepare()
        engine.prepare()
        # Second call replaces, not appends
        assert len(engine.tunnels) == 2
        assert engine.plugins == []
        assert engine.results == []

    def test_prepare_with_targets_idempotent(self, tmp_dir, mock_net, logger):
        """Targets parsed via prepare() don't pollute defs on second call."""
        defs = {
            "tunnels": {
                "forti": {
                    "type": "fortivpn",
                    "auth": {
                        "host": "vpn.test.com", "port": "443",
                        "login": "u", "pass": "p",
                        "cert_mode": "manual", "trusted_cert": "abc",
                    },
                    "routes": {"targets": ["10.0.0.0/8", "*.alpha.local"]},
                    "dns": {"nameservers": ["10.0.1.1"]},
                },
            },
        }
        e = Engine(tmp_dir, defs, net=mock_net, log=logger)
        e.prepare()
        nets_first = list(e.tunnels[0].routes.get("networks", []))
        e.prepare()
        nets_second = list(e.tunnels[0].routes.get("networks", []))
        # Second prepare should produce identical result, not doubled
        assert nets_first == nets_second
        # Original defs untouched
        assert "networks" not in defs["tunnels"]["forti"]["routes"]

    def test_prepare_calls_wizard_when_no_routes(self, tmp_dir, mock_net, logger):
        """Wizard is called when tunnel has no routes and no targets."""
        defs = {
            "tunnels": {
                "openvpn": {"type": "openvpn", "order": 1, "config_file": "client.ovpn"},
            },
        }
        e = Engine(tmp_dir, defs, net=mock_net, log=logger)
        with patch("tv.ui.wizard_targets", return_value=["10.0.0.0/8"]) as mock_wiz:
            e.prepare()
        mock_wiz.assert_called_once_with("openvpn")
        assert "10.0.0.0/8" in e.tunnels[0].routes["networks"]

    def test_prepare_quiet_with_settings(self, tmp_dir, mock_net, logger, capsys):
        """Settings file exists + setup=False: quiet mode, no wizard, profiles shown."""
        defs = {
            "tunnels": {
                "openvpn": {"type": "openvpn", "order": 1, "config_file": "client.ovpn"},
            },
        }
        settings = {"openvpn": {"config_file": "client.ovpn", "targets": []}}
        (tmp_dir / ".vpn-settings.json").write_text(json.dumps(settings))

        e = Engine(tmp_dir, defs, net=mock_net, log=logger)
        with patch("tv.ui.wizard_targets") as mock_wiz:
            e.prepare(setup=False)

        mock_wiz.assert_not_called()
        assert len(e.tunnels) == 1
        out = capsys.readouterr().out
        assert "Профили:" in out
        assert "openvpn" in out

    def test_prepare_setup_forces_wizard(self, tmp_dir, mock_net, logger):
        """--setup flag: wizard runs even with settings file."""
        defs = {
            "tunnels": {
                "openvpn": {"type": "openvpn", "order": 1, "config_file": "client.ovpn"},
            },
        }
        settings = {"openvpn": {"config_file": "client.ovpn"}}
        (tmp_dir / ".vpn-settings.json").write_text(json.dumps(settings))

        e = Engine(tmp_dir, defs, net=mock_net, log=logger)
        with patch("tv.ui.wizard_targets", return_value=[]) as mock_wiz:
            e.prepare(setup=True)

        mock_wiz.assert_called_once()

    def test_prepare_no_settings_triggers_wizard(self, tmp_dir, mock_net, logger):
        """No settings file + setup=False: wizard runs (first-time use)."""
        defs = {
            "tunnels": {
                "openvpn": {"type": "openvpn", "order": 1, "config_file": "client.ovpn"},
            },
        }
        e = Engine(tmp_dir, defs, net=mock_net, log=logger)
        with patch("tv.ui.wizard_targets", return_value=[]) as mock_wiz:
            e.prepare(setup=False)

        mock_wiz.assert_called_once()

    def test_prepare_auto_setup_on_missing_param(self, tmp_dir, mock_net, logger):
        """Settings file exists but missing required param -> auto-enter setup."""
        defs = {
            "tunnels": {
                "forti": {
                    "type": "fortivpn", "order": 1,
                    # No auth at all - login/pass/host missing
                },
            },
        }
        # Create settings file (triggers quiet mode) but with incomplete data
        (tmp_dir / ".vpn-settings.json").write_text(json.dumps({"forti": {}}))

        e = Engine(tmp_dir, defs, net=mock_net, log=logger)
        # Should auto-switch to wizard mode (setup=True) instead of crashing
        with patch("tv.config._resolve_param") as mock_resolve, \
             patch("tv.ui.wizard_targets", return_value=[]):
            # First call (quiet): raises SetupRequiredError
            # Second call (wizard): returns values
            from tv.config import SetupRequiredError
            mock_resolve.side_effect = [
                SetupRequiredError("missing"),  # quiet mode -> triggers auto-setup
                "vpn.com",   # host (wizard)
                "443",       # port (wizard)
                "user",      # login (wizard)
                "secret",    # pass (wizard)
                "auto",      # cert_mode (wizard)
            ]
            with patch("tv.config._handle_forti_cert"):
                e.prepare(setup=False)

        # Should have tunnels populated (auto-setup succeeded)
        assert len(e.tunnels) == 1


# =========================================================================
# Setup
# =========================================================================

class TestSetup:
    def test_no_disconnect_without_clear(self, engine):
        engine.tunnels = []
        with patch("tv.engine.disconnect.run") as mock_disc, \
             patch("tv.engine.time.sleep"):
            engine.setup()

        mock_disc.assert_not_called()
        engine.net.disable_ipv6.assert_called_once()

    def test_calls_disconnect_with_clear(self, engine):
        engine.tunnels = []
        with patch("tv.engine.disconnect.run") as mock_disc, \
             patch("tv.engine.time.sleep"):
            engine.setup(clear=True)

        mock_disc.assert_called_once_with(engine.net, engine.log, engine.defs)
        engine.net.disable_ipv6.assert_called_once()

    def test_adds_vpn_server_routes(self, engine, _skip_setup_io):
        engine.tunnels = []
        engine.setup()

        # Static host route (10.20.30.40 from defs)
        engine.net.add_host_route.assert_any_call("10.20.30.40", "192.168.1.1")
        # Resolved host route (1.2.3.4 from mock_net.resolve_host)
        engine.net.resolve_host.assert_called_with("vpn.test.com")
        engine.net.add_host_route.assert_any_call("1.2.3.4", "192.168.1.1")

    def test_prepares_log_files(self, engine, tmp_dir, _skip_setup_io):
        log_path = tmp_dir / "logs" / "test.log"
        engine.tunnels = [
            TunnelConfig(name="t", log=str(log_path)),
        ]
        engine.setup()
        assert log_path.exists()
        assert log_path.read_bytes() == b""
        # File should be readable (0o644)
        import stat
        mode = log_path.stat().st_mode & 0o777
        assert mode & 0o444 == 0o444  # readable by all

    def test_no_gateway_skips_routes(self, engine, _skip_setup_io):
        engine.tunnels = []
        engine.net.default_gateway.return_value = None
        engine.setup()

        engine.net.add_host_route.assert_not_called()


# =========================================================================
# Connect all
# =========================================================================

class TestConnectAll:
    def test_connects_tunnels(self, engine):
        engine.prepare()
        with patch("tv.vpn.openvpn.OpenVPNPlugin.connect", return_value=VPNResult(ok=True)), \
             patch("tv.vpn.singbox.SingBoxPlugin.connect", return_value=VPNResult(ok=True)):
            engine.connect_all()

        assert len(engine.results) == 2
        assert all(r.ok for r in engine.results)
        assert len(engine.plugins) == 2

    def test_connect_all_is_idempotent(self, engine):
        engine.prepare()
        with patch("tv.vpn.openvpn.OpenVPNPlugin.connect", return_value=VPNResult(ok=True)), \
             patch("tv.vpn.singbox.SingBoxPlugin.connect", return_value=VPNResult(ok=True)):
            engine.connect_all()
            engine.connect_all()

        # Second call replaces, not appends
        assert len(engine.plugins) == 2
        assert len(engine.results) == 2

    def test_fires_pre_and_post_connect_hooks(self, engine):
        engine.prepare()
        pre = MagicMock()
        post = MagicMock()
        engine.on("pre_connect", pre)
        engine.on("post_connect", post)

        with patch("tv.vpn.openvpn.OpenVPNPlugin.connect", return_value=VPNResult(ok=True)), \
             patch("tv.vpn.singbox.SingBoxPlugin.connect", return_value=VPNResult(ok=False)):
            engine.connect_all()

        assert pre.call_count == 2
        assert post.call_count == 2

        # Check hook kwargs
        first_post = post.call_args_list[0]
        assert first_post.kwargs["tunnel"].name == "openvpn"
        assert first_post.kwargs["result"].ok is True
        assert first_post.kwargs["index"] == 1
        assert first_post.kwargs["total"] == 2


# =========================================================================
# Check all
# =========================================================================

class TestCheckAll:
    def test_runs_checks_and_returns_results(self, engine):
        engine.tunnels = [TunnelConfig(name="t", type="openvpn")]
        engine.results = [VPNResult(ok=True)]

        fake_results = [CheckResult("test", "ok", "ok")]
        with patch("tv.engine.checks.run_all_from_tunnels", return_value=(fake_results, "1.2.3.4")):
            results, ext_ip = engine.check_all()

        assert len(results) == 1
        assert ext_ip == "1.2.3.4"

    def test_fires_on_all_checks_done(self, engine):
        engine.tunnels = [TunnelConfig(name="t", type="openvpn")]
        engine.results = [VPNResult(ok=True)]

        hook = MagicMock()
        engine.on("on_all_checks_done", hook)

        with patch("tv.engine.checks.run_all_from_tunnels", return_value=([], "")):
            engine.check_all()

        hook.assert_called_once()
        assert "results" in hook.call_args.kwargs
        assert "ext_ip" in hook.call_args.kwargs

    def test_fires_on_check_fail(self, engine):
        engine.tunnels = [TunnelConfig(name="t", type="openvpn")]
        engine.results = [VPNResult(ok=True)]

        hook = MagicMock()
        engine.on("on_check_fail", hook)

        failed = [CheckResult("test", "fail", "timeout")]
        with patch("tv.engine.checks.run_all_from_tunnels", return_value=(failed, "")):
            engine.check_all()

        hook.assert_called_once()
        assert hook.call_args.kwargs["failed"] == failed

    def test_no_fail_hook_when_all_pass(self, engine):
        engine.tunnels = [TunnelConfig(name="t", type="openvpn")]
        engine.results = [VPNResult(ok=True)]

        hook = MagicMock()
        engine.on("on_check_fail", hook)

        passed = [CheckResult("test", "ok", "ok")]
        with patch("tv.engine.checks.run_all_from_tunnels", return_value=(passed, "")):
            engine.check_all()

        hook.assert_not_called()


# =========================================================================
# Disconnect all
# =========================================================================

class TestDisconnectAll:
    def test_disconnects_in_reverse_order(self, engine):
        order = []
        plugin1 = MagicMock(spec=TunnelPlugin)
        plugin2 = MagicMock(spec=TunnelPlugin)
        plugin1.disconnect.side_effect = lambda: order.append("first")
        plugin2.disconnect.side_effect = lambda: order.append("second")
        tcfg1 = TunnelConfig(name="first")
        tcfg2 = TunnelConfig(name="second")

        engine.plugins = [plugin1, plugin2]
        engine.tunnels = [tcfg1, tcfg2]

        engine.disconnect_all()

        # plugin2 (second) disconnected BEFORE plugin1 (first)
        assert order == ["second", "first"]
        assert plugin1.delete_routes.call_count == 1
        assert plugin2.cleanup_dns.call_count == 1
        engine.net.restore_ipv6.assert_called_once()

    def test_exception_in_one_plugin_doesnt_stop_others(self, engine):
        plugin1 = MagicMock(spec=TunnelPlugin)
        plugin2 = MagicMock(spec=TunnelPlugin)
        plugin2.disconnect.side_effect = RuntimeError("connection reset")

        engine.plugins = [plugin1, plugin2]
        engine.tunnels = [TunnelConfig(name="first"), TunnelConfig(name="second")]

        engine.disconnect_all()  # should not raise

        # plugin2 threw, but plugin1 still disconnected
        plugin1.disconnect.assert_called_once()
        plugin2.disconnect.assert_called_once()
        engine.net.restore_ipv6.assert_called_once()

    def test_fires_pre_and_post_disconnect_hooks(self, engine):
        plugin = MagicMock(spec=TunnelPlugin)
        tcfg = TunnelConfig(name="test")
        engine.plugins = [plugin]
        engine.tunnels = [tcfg]

        pre = MagicMock()
        post = MagicMock()
        engine.on("pre_disconnect", pre)
        engine.on("post_disconnect", post)

        engine.disconnect_all()

        pre.assert_called_once()
        post.assert_called_once()
        assert pre.call_args.kwargs["tunnel"] is tcfg
        assert post.call_args.kwargs["plugin"] is plugin

    def test_empty_tunnels_only_restores_ipv6(self, engine):
        engine.plugins = []
        engine.tunnels = []

        engine.disconnect_all()

        engine.net.restore_ipv6.assert_called_once()


# =========================================================================
# VPN server routes
# =========================================================================

class TestVpnServerRoutes:
    def test_global_format(self, engine, _skip_setup_io):
        engine.defs = {
            "global": {
                "vpn_server_routes": {
                    "hosts": ["5.6.7.8"],
                    "resolve": [],
                },
            },
        }
        engine.tunnels = []
        engine.setup()

        engine.net.add_host_route.assert_called_with("5.6.7.8", "192.168.1.1")

    def test_routes_vpn_servers_format(self, engine, _skip_setup_io):
        engine.defs = {
            "routes": {
                "vpn_servers": {
                    "hosts": ["9.10.11.12"],
                    "resolve": [],
                },
            },
        }
        engine.tunnels = []
        engine.setup()

        engine.net.add_host_route.assert_called_with("9.10.11.12", "192.168.1.1")
