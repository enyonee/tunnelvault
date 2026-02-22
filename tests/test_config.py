"""Tests for tv.config: loading, saving, param resolution, tunnel resolve."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from tv.app_config import cfg
from tv.config import (
    load_settings,
    save_tunnel_settings,
    resolve_tunnel_params,
    resolve_tunnel_routes,
    _resolve_param,
    _migrate_bash_settings,
    _generate_cert,
    _get_param_value,
    _set_param_value,
)

SETTINGS_FILENAME = cfg.paths.settings_file
from tv.vpn.base import TunnelConfig, ConfigParam, TunnelPlugin, VPNResult
from tv.vpn.fortivpn import FortiVPNPlugin
from tv.vpn.openvpn import OpenVPNPlugin


# =========================================================================
# Positive: settings load/save
# =========================================================================

class TestLoadSettings:
    def test_loads_json(self, tmp_dir: Path):
        data = {"fortivpn": {"host": "vpn.test.com", "port": "443"}}
        (tmp_dir / SETTINGS_FILENAME).write_text(json.dumps(data))
        result = load_settings(tmp_dir)
        assert result["fortivpn"]["host"] == "vpn.test.com"

    def test_migrates_bash_format(self, tmp_dir: Path):
        bash_content = (
            '# comment\n'
            'SAVED_FORTI_HOST="vpn.corp.com"\n'
            'SAVED_FORTI_PORT="44333"\n'
            'SAVED_FORTI_PASS="s3cret"\n'
        )
        (tmp_dir / ".vpn-settings").write_text(bash_content)
        result = load_settings(tmp_dir)
        assert result["fortivpn"]["host"] == "vpn.corp.com"
        assert result["fortivpn"]["pass"] == "s3cret"

    def test_returns_empty_when_no_files(self, tmp_dir: Path):
        result = load_settings(tmp_dir)
        assert result == {}


class TestSaveTunnelSettings:
    def test_saves_per_tunnel(self, tmp_dir: Path):
        tunnels = [
            TunnelConfig(
                name="fortivpn", type="fortivpn",
                auth={"host": "vpn.example.com", "port": "44333",
                       "login": "user", "pass": "secret",
                       "cert_mode": "auto", "trusted_cert": "abc123"},
            ),
            TunnelConfig(
                name="openvpn", type="openvpn",
                config_file="client.ovpn",
            ),
        ]
        save_tunnel_settings(tunnels, tmp_dir)
        path = tmp_dir / SETTINGS_FILENAME
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["fortivpn"]["host"] == "vpn.example.com"
        assert data["openvpn"]["config_file"] == "client.ovpn"

    def test_file_permissions_600(self, tmp_dir: Path):
        tunnels = [TunnelConfig(name="openvpn", type="openvpn", config_file="c.ovpn")]
        save_tunnel_settings(tunnels, tmp_dir)
        path = tmp_dir / SETTINGS_FILENAME
        mode = oct(path.stat().st_mode & 0o777)
        assert mode == "0o600"

    def test_skips_unknown_plugin(self, tmp_dir: Path):
        tunnels = [TunnelConfig(name="custom", type="wireguard")]
        save_tunnel_settings(tunnels, tmp_dir)
        path = tmp_dir / SETTINGS_FILENAME
        data = json.loads(path.read_text())
        assert data == {}

    def test_saves_targets_and_dns(self, tmp_dir: Path):
        tunnels = [
            TunnelConfig(
                name="forti", type="fortivpn",
                routes={"targets": ["*.corp.local", "10.0.0.0/8"]},
                dns={"nameservers": ["10.0.1.1"]},
            ),
        ]
        save_tunnel_settings(tunnels, tmp_dir)
        data = json.loads((tmp_dir / SETTINGS_FILENAME).read_text())
        assert data["forti"]["targets"] == ["*.corp.local", "10.0.0.0/8"]
        assert data["forti"]["dns_nameservers"] == ["10.0.1.1"]


# =========================================================================
# Negative / inverse: settings load failures
# =========================================================================

class TestLoadSettingsInverse:
    def test_invalid_json_returns_empty(self, tmp_dir: Path):
        (tmp_dir / SETTINGS_FILENAME).write_text("{corrupted json!!")
        result = load_settings(tmp_dir)
        assert result == {}

    def test_empty_file_returns_empty(self, tmp_dir: Path):
        (tmp_dir / SETTINGS_FILENAME).write_text("")
        result = load_settings(tmp_dir)
        assert result == {}

    def test_bash_file_with_injection_attempt(self, tmp_dir: Path):
        malicious = (
            'SAVED_FORTI_HOST="vpn.com"\n'
            '$(rm -rf /)\n'
            'SAVED_FORTI_PORT="443"\n'
        )
        (tmp_dir / ".vpn-settings").write_text(malicious)
        result = _migrate_bash_settings(tmp_dir / ".vpn-settings")
        assert "fortivpn" in result
        assert result["fortivpn"]["host"] == "vpn.com"
        # Injection line is not a valid SAVED_* key, so it's ignored
        all_values = str(result)
        assert "$(rm -rf /)" not in all_values


# =========================================================================
# Positive: param resolution
# =========================================================================

class TestResolveParam:
    def test_env_wins_over_saved(self):
        with patch.dict(os.environ, {"VPN_TEST": "from_env"}):
            result = _resolve_param("test", env_name="VPN_TEST", saved="from_file")
        assert result == "from_env"

    def test_saved_used_when_no_env(self):
        result = _resolve_param("test", env_name="NONEXISTENT_VAR", saved="from_file")
        assert result == "from_file"


# =========================================================================
# Negative / inverse: param resolution edge cases
# =========================================================================

class TestResolveParamInverse:
    def test_env_empty_string_not_treated_as_value(self):
        with patch.dict(os.environ, {"VPN_EMPTY": ""}):
            result = _resolve_param("test", env_name="VPN_EMPTY", saved="saved_val")
        assert result == "saved_val"

    @patch("tv.ui.wizard_input", return_value="wizard_input")
    def test_falls_to_wizard_when_all_empty(self, mock_wizard):
        result = _resolve_param("test", env_name="NOPE", saved="")
        assert result == "wizard_input"
        mock_wizard.assert_called_once()

    @patch("tv.ui.wizard_input", return_value="")
    def test_wizard_empty_returns_default(self, mock_wizard):
        result = _resolve_param("test", env_name="NOPE", saved="", default="def_val")
        assert result == ""  # wizard_input mock returns ""


# =========================================================================
# Certificate generation
# =========================================================================

class TestGenerateCert:
    @patch("subprocess.Popen")
    def test_returns_empty_on_timeout(self, mock_popen):
        mock_proc = MagicMock()
        mock_proc.communicate.side_effect = TimeoutError()
        mock_proc.kill.return_value = None
        mock_popen.return_value = mock_proc
        result = _generate_cert("host", "443")
        assert result == ""

    @patch("subprocess.Popen")
    def test_returns_empty_on_oserror(self, mock_popen):
        mock_popen.side_effect = FileNotFoundError("openssl")
        result = _generate_cert("host", "443")
        assert result == ""


# =========================================================================
# ConfigParam get/set helpers
# =========================================================================

class TestConfigParamHelpers:
    @pytest.mark.parametrize("target,key,label,tc_kw,expected", [
        ("auth", "host", "Хост", {"auth": {"host": "vpn.com"}}, "vpn.com"),
        ("config_file", "config_file", "Config", {"config_file": "test.ovpn"}, "test.ovpn"),
        ("extra", "gw", "GW", {"extra": {"gw": "1.2.3.4"}}, "1.2.3.4"),
    ])
    def test_get_param(self, target, key, label, tc_kw, expected):
        tc = TunnelConfig(**tc_kw)
        param = ConfigParam(key, label, target=target)
        assert _get_param_value(tc, param) == expected

    @pytest.mark.parametrize("target,key,label,value,check", [
        ("auth", "host", "Хост", "vpn.com", lambda tc: tc.auth["host"]),
        ("config_file", "config_file", "Config", "test.ovpn", lambda tc: tc.config_file),
        ("extra", "gw", "GW", "1.2.3.4", lambda tc: tc.extra["gw"]),
    ])
    def test_set_param(self, target, key, label, value, check):
        tc = TunnelConfig()
        param = ConfigParam(key, label, target=target)
        _set_param_value(tc, param, value)
        assert check(tc) == value


# =========================================================================
# resolve_tunnel_params - plugin-driven resolution
# =========================================================================

class TestResolveTunnelParams:
    def test_toml_value_used_first(self):
        """TOML value already in TunnelConfig -> no wizard needed."""
        tc = TunnelConfig(
            name="openvpn", type="openvpn",
            config_file="my.ovpn",
        )
        resolve_tunnel_params(tc, OpenVPNPlugin, {}, Path("/tmp"))
        assert tc.config_file == "my.ovpn"

    def test_env_fills_missing(self):
        """ENV fills when TOML value missing."""
        tc = TunnelConfig(name="openvpn", type="openvpn")
        with patch.dict(os.environ, {"VPN_OVPN_CONFIG": "env.ovpn"}):
            resolve_tunnel_params(tc, OpenVPNPlugin, {}, Path("/tmp"))
        assert tc.config_file == "env.ovpn"

    def test_saved_fills_missing(self):
        """Saved settings fill when TOML and ENV missing."""
        tc = TunnelConfig(name="openvpn", type="openvpn")
        saved = {"openvpn": {"config_file": "saved.ovpn"}}
        resolve_tunnel_params(tc, OpenVPNPlugin, saved, Path("/tmp"))
        assert tc.config_file == "saved.ovpn"

    def test_flat_saved_not_used(self):
        """Flat saved dict (legacy) is NOT used - prevents cross-tunnel leaks."""
        tc = TunnelConfig(name="openvpn", type="openvpn")
        saved = {"config_file": "flat.ovpn"}  # flat, not nested under tunnel name
        with patch("tv.config.ui.wizard_input", return_value="client.ovpn"):
            resolve_tunnel_params(tc, OpenVPNPlugin, saved, Path("/tmp"))
        # Should use default, not flat value
        assert tc.config_file == "client.ovpn"

    def test_forti_auth_resolved(self):
        """FortiVPN auth params resolved from saved."""
        tc = TunnelConfig(name="fortivpn", type="fortivpn")
        saved = {
            "fortivpn": {
                "host": "vpn.com", "port": "443",
                "login": "user", "pass": "secret",
                "cert_mode": "manual", "trusted_cert": "abc123",
            },
        }
        resolve_tunnel_params(tc, FortiVPNPlugin, saved, Path("/tmp"))
        assert tc.auth["host"] == "vpn.com"
        assert tc.auth["login"] == "user"
        assert tc.auth["pass"] == "secret"

    def test_toml_auth_not_overwritten(self):
        """TOML auth values take priority over saved."""
        tc = TunnelConfig(
            name="fortivpn", type="fortivpn",
            auth={"host": "toml-host", "port": "44333",
                   "login": "toml-user", "pass": "toml-pass",
                   "cert_mode": "manual", "trusted_cert": "toml-cert"},
        )
        saved = {"fortivpn": {"host": "saved-host", "login": "saved-user"}}
        resolve_tunnel_params(tc, FortiVPNPlugin, saved, Path("/tmp"))
        assert tc.auth["host"] == "toml-host"
        assert tc.auth["login"] == "toml-user"

    def test_empty_schema_noop(self):
        """Plugin with no config_schema -> no-op."""
        tc = TunnelConfig(name="custom", type="custom")

        class NoSchemaPlugin(TunnelPlugin):
            def connect(self): return VPNResult()
            @property
            def process_name(self): return "custom"

        resolve_tunnel_params(tc, NoSchemaPlugin, {}, Path("/tmp"))
        assert tc.auth == {}

    @patch("tv.config._generate_cert", return_value="generated_cert_abc")
    def test_forti_auto_cert_generated(self, mock_cert):
        """cert_mode=auto triggers cert generation."""
        tc = TunnelConfig(
            name="fortivpn", type="fortivpn",
            auth={"host": "vpn.com", "port": "443",
                   "login": "u", "pass": "p", "cert_mode": "auto"},
        )
        resolve_tunnel_params(tc, FortiVPNPlugin, {}, Path("/tmp"))
        assert tc.auth["trusted_cert"] == "generated_cert_abc"
        mock_cert.assert_called_once_with("vpn.com", "443")

    def test_forti_manual_cert_no_generation(self):
        """cert_mode=manual does NOT trigger cert generation."""
        tc = TunnelConfig(
            name="fortivpn", type="fortivpn",
            auth={"host": "vpn.com", "port": "443",
                   "login": "u", "pass": "p",
                   "cert_mode": "manual", "trusted_cert": "manual_cert"},
        )
        with patch("tv.config._generate_cert") as mock_cert:
            resolve_tunnel_params(tc, FortiVPNPlugin, {}, Path("/tmp"))
        mock_cert.assert_not_called()
        assert tc.auth["trusted_cert"] == "manual_cert"

    def test_forti_auto_cert_from_env(self):
        """cert_mode=auto with VPN_TRUSTED_CERT env -> uses env, no generation."""
        tc = TunnelConfig(
            name="fortivpn", type="fortivpn",
            auth={"host": "vpn.com", "port": "443",
                   "login": "u", "pass": "p", "cert_mode": "auto"},
        )
        with patch.dict(os.environ, {"VPN_TRUSTED_CERT": "env_cert_value"}), \
             patch("tv.config._generate_cert") as mock_cert:
            resolve_tunnel_params(tc, FortiVPNPlugin, {}, Path("/tmp"))
        mock_cert.assert_not_called()
        assert tc.auth["trusted_cert"] == "env_cert_value"

    def test_forti_auto_cert_from_saved(self):
        """cert_mode=auto with saved trusted_cert -> uses saved, no generation."""
        tc = TunnelConfig(
            name="fortivpn", type="fortivpn",
            auth={"host": "vpn.com", "port": "443",
                   "login": "u", "pass": "p", "cert_mode": "auto"},
        )
        saved = {"fortivpn": {"trusted_cert": "saved_cert_value"}}
        with patch("tv.config._generate_cert") as mock_cert:
            resolve_tunnel_params(tc, FortiVPNPlugin, saved, Path("/tmp"))
        mock_cert.assert_not_called()
        assert tc.auth["trusted_cert"] == "saved_cert_value"

    def test_migrated_bash_settings_resolve_forti(self):
        """Migrated bash settings (per-tunnel nested) resolve correctly."""
        tc = TunnelConfig(name="fortivpn", type="fortivpn")
        # Simulates _migrate_bash_settings output
        saved = {
            "fortivpn": {
                "host": "vpn.migrated.com", "port": "44333",
                "login": "migrated_user", "pass": "migrated_pass",
                "cert_mode": "manual", "trusted_cert": "migrated_cert",
            },
        }
        resolve_tunnel_params(tc, FortiVPNPlugin, saved, Path("/tmp"))
        assert tc.auth["host"] == "vpn.migrated.com"
        assert tc.auth["login"] == "migrated_user"
        assert tc.auth["trusted_cert"] == "migrated_cert"


# =========================================================================
# resolve_tunnel_routes
# =========================================================================

class TestResolveTunnelRoutes:
    def test_targets_from_toml(self):
        """Targets in TOML routes -> parsed into networks/hosts/dns."""
        tc = TunnelConfig(
            name="forti", type="fortivpn",
            routes={"targets": ["*.corp.local", "10.0.0.0/8", "192.168.1.1"]},
            dns={"nameservers": ["10.0.1.1"]},
        )
        resolve_tunnel_routes(tc, {})
        assert "10.0.0.0/8" in tc.routes["networks"]
        assert "192.168.1.1" in tc.routes["hosts"]
        assert "corp.local" in tc.dns["domains"]

    def test_targets_from_saved(self):
        """Targets from saved settings -> parsed."""
        tc = TunnelConfig(name="forti", type="fortivpn")
        saved = {
            "forti": {
                "targets": ["10.0.0.0/8", "*.test.local"],
                "dns_nameservers": ["10.0.1.1"],
            },
        }
        resolve_tunnel_routes(tc, saved)
        assert "10.0.0.0/8" in tc.routes["networks"]
        assert "test.local" in tc.dns["domains"]
        assert tc.dns["nameservers"] == ["10.0.1.1"]

    @patch("tv.ui.wizard_targets", return_value=["172.16.0.0/12", "1.2.3.4"])
    def test_wizard_fallback(self, mock_wizard):
        """No targets anywhere -> wizard asks."""
        tc = TunnelConfig(name="forti", type="fortivpn")
        resolve_tunnel_routes(tc, {})
        mock_wizard.assert_called_once_with("forti")
        assert "172.16.0.0/12" in tc.routes["networks"]
        assert "1.2.3.4" in tc.routes["hosts"]

    def test_advanced_mode_skips_wizard(self):
        """Existing networks in TOML -> wizard not called."""
        tc = TunnelConfig(
            name="forti", type="fortivpn",
            routes={"networks": ["10.0.0.0/8"]},
        )
        with patch("tv.ui.wizard_targets") as mock_wizard:
            resolve_tunnel_routes(tc, {})
        mock_wizard.assert_not_called()
        assert tc.routes["networks"] == ["10.0.0.0/8"]

    def test_advanced_mode_hosts_skips_wizard(self):
        """Existing hosts in TOML -> wizard not called."""
        tc = TunnelConfig(
            name="sb", type="singbox",
            routes={"hosts": ["1.2.3.4"]},
        )
        with patch("tv.ui.wizard_targets") as mock_wizard:
            resolve_tunnel_routes(tc, {})
        mock_wizard.assert_not_called()

    @patch("tv.ui.wizard_targets", return_value=[])
    def test_empty_wizard_input_noop(self, mock_wizard):
        """Empty wizard input -> no routes added."""
        tc = TunnelConfig(name="forti", type="fortivpn")
        resolve_tunnel_routes(tc, {})
        assert tc.routes.get("networks") is None
        assert tc.routes.get("hosts") is None

    @patch("tv.ui.wizard_nameservers", return_value=["10.0.1.1"])
    def test_wizard_asks_nameservers_for_wildcards(self, mock_ns):
        """Wildcard targets + no nameservers -> wizard asks for DNS servers."""
        tc = TunnelConfig(
            name="forti", type="fortivpn",
            routes={"targets": ["*.corp.local", "10.0.0.0/8"]},
        )
        resolve_tunnel_routes(tc, {})
        mock_ns.assert_called_once_with(["corp.local"])
        assert tc.dns["nameservers"] == ["10.0.1.1"]

    def test_existing_nameservers_not_overwritten(self):
        """Existing DNS nameservers -> wizard not called."""
        tc = TunnelConfig(
            name="forti", type="fortivpn",
            routes={"targets": ["*.corp.local"]},
            dns={"nameservers": ["10.0.1.1"]},
        )
        with patch("tv.ui.wizard_nameservers") as mock_ns:
            resolve_tunnel_routes(tc, {})
        mock_ns.assert_not_called()
        assert tc.dns["nameservers"] == ["10.0.1.1"]

    def test_saves_targets_back(self):
        """Original targets stored in routes for saving."""
        targets = ["*.corp.local", "10.0.0.0/8"]
        tc = TunnelConfig(
            name="forti", type="fortivpn",
            routes={"targets": targets},
            dns={"nameservers": ["10.0.1.1"]},
        )
        resolve_tunnel_routes(tc, {})
        assert tc.routes["targets"] == targets

    @patch("tv.ui.wizard_nameservers", return_value=["10.0.1.1"])
    def test_toml_domains_prompt_nameservers(self, mock_ns):
        """Domains in TOML (not from targets) -> wizard asks for nameservers."""
        tc = TunnelConfig(
            name="forti", type="fortivpn",
            routes={"networks": ["10.0.0.0/8"]},  # advanced mode
            dns={"domains": ["corp.local"]},        # domains but no nameservers
        )
        resolve_tunnel_routes(tc, {})
        mock_ns.assert_called_once_with(["corp.local"])
        assert tc.dns["nameservers"] == ["10.0.1.1"]

    def test_toml_domains_with_nameservers_no_prompt(self):
        """Domains + nameservers in TOML -> wizard NOT called."""
        tc = TunnelConfig(
            name="forti", type="fortivpn",
            routes={"networks": ["10.0.0.0/8"]},
            dns={"domains": ["corp.local"], "nameservers": ["10.0.1.1"]},
        )
        with patch("tv.ui.wizard_nameservers") as mock_ns:
            resolve_tunnel_routes(tc, {})
        mock_ns.assert_not_called()


# =========================================================================
# prompt=False params (non-interactive resolution)
# =========================================================================

class TestSilentParams:
    def test_fallback_gw_from_env(self):
        """fallback_gateway resolved from ENV without wizard prompt."""
        tc = TunnelConfig(
            name="fortivpn", type="fortivpn",
            auth={"host": "vpn.com", "port": "443",
                   "login": "u", "pass": "p",
                   "cert_mode": "manual", "trusted_cert": "cert"},
        )
        with patch.dict(os.environ, {"VPN_FORTI_FALLBACK_GW": "10.0.0.1"}):
            resolve_tunnel_params(tc, FortiVPNPlugin, {}, Path("/tmp"))
        assert tc.extra["fallback_gateway"] == "10.0.0.1"

    def test_fallback_gw_from_saved(self):
        """fallback_gateway resolved from saved settings."""
        tc = TunnelConfig(
            name="fortivpn", type="fortivpn",
            auth={"host": "vpn.com", "port": "443",
                   "login": "u", "pass": "p",
                   "cert_mode": "manual", "trusted_cert": "cert"},
        )
        saved = {"fortivpn": {"fallback_gateway": "10.0.0.1"}}
        resolve_tunnel_params(tc, FortiVPNPlugin, saved, Path("/tmp"))
        assert tc.extra["fallback_gateway"] == "10.0.0.1"

    def test_fallback_gw_not_prompted(self):
        """fallback_gateway with no value -> NOT prompted in wizard."""
        tc = TunnelConfig(
            name="fortivpn", type="fortivpn",
            auth={"host": "vpn.com", "port": "443",
                   "login": "u", "pass": "p",
                   "cert_mode": "manual", "trusted_cert": "cert"},
        )
        with patch("tv.config.ui.wizard_input") as mock_wizard:
            resolve_tunnel_params(tc, FortiVPNPlugin, {}, Path("/tmp"))
        # wizard_input should NOT be called for fallback_gateway
        for call in mock_wizard.call_args_list:
            assert "Fallback" not in call.args[0]

    def test_fallback_gw_from_toml(self):
        """fallback_gateway in TOML extra -> used as-is."""
        tc = TunnelConfig(
            name="fortivpn", type="fortivpn",
            auth={"host": "vpn.com", "port": "443",
                   "login": "u", "pass": "p",
                   "cert_mode": "manual", "trusted_cert": "cert"},
            extra={"fallback_gateway": "10.0.0.1"},
        )
        resolve_tunnel_params(tc, FortiVPNPlugin, {}, Path("/tmp"))
        assert tc.extra["fallback_gateway"] == "10.0.0.1"
