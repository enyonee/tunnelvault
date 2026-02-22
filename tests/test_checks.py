"""Tests for tv.checks: health check primitives and runner."""

from __future__ import annotations

import subprocess
from unittest.mock import patch, MagicMock

import pytest

from tv.checks import (
    _check_port,
    _check_ping,
    _check_dns,
    _check_http,
    _check_http_any,
    _get_external_ip,
    _run_one,
    CheckResult,
)


# =========================================================================
# Positive: primitives
# =========================================================================

class TestCheckPort:
    @patch("subprocess.run")
    def test_open_port(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        assert _check_port("127.0.0.1", 80) is True

    @patch("subprocess.run")
    def test_uses_nc(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        _check_port("host", 443, timeout=3)
        args = mock_run.call_args[0][0]
        assert "nc" in args
        assert "-w" in args
        assert "3" in args


class TestCheckPing:
    @pytest.mark.parametrize("platform,flag,absent_flag", [
        ("Darwin", "-t", "-W"),
        ("Linux", "-W", "-t"),
    ])
    @patch("subprocess.run")
    def test_platform_ping_flag(self, mock_run, platform, flag, absent_flag):
        """Platform-specific ping timeout flag."""
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        with patch("platform.system", return_value=platform):
            _check_ping("127.0.0.1", timeout=3)
        args = mock_run.call_args[0][0]
        assert flag in args
        assert absent_flag not in args


class TestCheckDns:
    @patch("subprocess.run")
    def test_resolves(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "...", "")
        assert _check_dns("test.local", "10.0.0.1") is True


class TestCheckHttp:
    @pytest.mark.parametrize("status_code", ["200", "301"])
    @patch("subprocess.run")
    def test_success_codes(self, mock_run, status_code):
        mock_run.return_value = subprocess.CompletedProcess([], 0, status_code, "")
        assert _check_http("https://example.com") is True


class TestGetExternalIp:
    @patch("subprocess.run")
    def test_returns_ip(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "1.2.3.4", "")
        assert _get_external_ip("https://ifconfig.me") == "1.2.3.4"


# =========================================================================
# Negative / inverse: check failures
# =========================================================================

class TestCheckPortInverse:
    @patch("subprocess.run")
    def test_closed_port(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 1, "", "")
        assert _check_port("127.0.0.1", 99999) is False


class TestCheckPingInverse:
    @patch("platform.system", return_value="Darwin")
    @patch("subprocess.run")
    def test_unreachable_host(self, mock_run, _):
        mock_run.return_value = subprocess.CompletedProcess([], 2, "", "")
        assert _check_ping("192.0.2.1") is False


class TestCheckDnsInverse:
    @patch("subprocess.run")
    def test_nxdomain(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 1, "", "NXDOMAIN")
        assert _check_dns("nonexistent.invalid", "8.8.8.8") is False


class TestCheckHttpInverse:
    @pytest.mark.parametrize("rc,stdout", [
        (0, "000"),   # curl timeout
        (7, ""),      # curl connection refused
        (0, "500"),   # server error (не начинается с 2 или 3)
    ])
    @patch("subprocess.run")
    def test_failure_codes(self, mock_run, rc, stdout):
        mock_run.return_value = subprocess.CompletedProcess([], rc, stdout, "")
        assert _check_http("https://unreachable.test") is False


class TestGetExternalIpInverse:
    @pytest.mark.parametrize("rc,stdout", [
        (28, ""),  # curl timeout
        (0, ""),   # empty response
    ])
    @patch("subprocess.run")
    def test_returns_none(self, mock_run, rc, stdout):
        mock_run.return_value = subprocess.CompletedProcess([], rc, stdout, "")
        assert _get_external_ip("https://ifconfig.me") is None


# =========================================================================
# Positive: run_one
# =========================================================================

class TestRunOne:
    def test_ok_result(self, capsys):
        r = _run_one(1, True, "test", lambda: True, "ok_msg", "fail_msg", None)
        assert r.status == "ok"
        assert r.detail == "ok_msg"

    def test_skip_when_guard_false(self, capsys):
        r = _run_one(1, False, "test", lambda: True, "ok", "fail", None)
        assert r.status == "skip"


# =========================================================================
# Negative / inverse: run_one failures
# =========================================================================

class TestRunOneInverse:
    def test_fail_result(self, capsys):
        r = _run_one(1, True, "test", lambda: False, "ok", "fail_msg", None)
        assert r.status == "fail"
        assert r.detail == "fail_msg"

    def test_exception_in_check_is_fail(self, capsys):
        """Исключение в check-функции = fail, не crash."""
        r = _run_one(1, True, "test", lambda: 1/0, "ok", "error", None)
        assert r.status == "fail"
