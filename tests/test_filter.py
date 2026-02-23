"""Tests for defaults.filter_tunnels()."""

from __future__ import annotations

import pytest

from tv.defaults import filter_tunnels
from tv.vpn.base import TunnelConfig


@pytest.fixture
def tunnels():
    return [
        TunnelConfig(name="alpha", type="openvpn", order=1),
        TunnelConfig(name="bravo", type="fortivpn", order=2),
        TunnelConfig(name="charlie", type="singbox", order=3),
    ]


class TestFilterTunnels:
    def test_single_name(self, tunnels):
        result = filter_tunnels(tunnels, "bravo")
        assert len(result) == 1
        assert result[0].name == "bravo"

    def test_multiple_names(self, tunnels):
        result = filter_tunnels(tunnels, "alpha,charlie")
        assert len(result) == 2
        assert result[0].name == "alpha"
        assert result[1].name == "charlie"

    def test_preserves_order(self, tunnels):
        """Result order matches original list, not filter string."""
        result = filter_tunnels(tunnels, "charlie,alpha")
        assert result[0].name == "alpha"
        assert result[1].name == "charlie"

    def test_all_names(self, tunnels):
        result = filter_tunnels(tunnels, "alpha,bravo,charlie")
        assert len(result) == 3

    def test_empty_string_returns_all(self, tunnels):
        result = filter_tunnels(tunnels, "")
        assert result == tunnels

    def test_whitespace_handling(self, tunnels):
        result = filter_tunnels(tunnels, " alpha , bravo ")
        assert len(result) == 2
        assert result[0].name == "alpha"

    def test_unknown_name_raises(self, tunnels):
        with pytest.raises(ValueError, match="unknown"):
            filter_tunnels(tunnels, "unknown")

    def test_unknown_name_lists_available(self, tunnels):
        with pytest.raises(ValueError, match="alpha"):
            filter_tunnels(tunnels, "nope")

    def test_mixed_known_unknown_raises(self, tunnels):
        with pytest.raises(ValueError, match="nope"):
            filter_tunnels(tunnels, "alpha,nope")

    def test_empty_tunnels_with_name_raises(self):
        with pytest.raises(ValueError, match="no tunnels"):
            filter_tunnels([], "alpha")

    def test_empty_tunnels_empty_string(self):
        result = filter_tunnels([], "")
        assert result == []
