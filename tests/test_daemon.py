"""Tests for tv.daemon: launchd keepalive service management."""

from __future__ import annotations

import plistlib
import subprocess
from unittest.mock import patch

from tv import daemon


# =========================================================================
# _build_plist
# =========================================================================


class TestBuildPlist:
    def test_basic_plist(self, tmp_dir):
        plist = daemon._build_plist(tmp_dir)

        assert plist["Label"] == "com.tunnelvault.keepalive"
        assert plist["RunAtLoad"] is True
        assert plist["KeepAlive"] is True
        assert "--only" not in plist["ProgramArguments"]
        assert plist["WorkingDirectory"] == str(tmp_dir.resolve())

    def test_plist_with_only(self, tmp_dir):
        plist = daemon._build_plist(tmp_dir, only="fortivpn,singbox")

        args = plist["ProgramArguments"]
        assert "--only" in args
        idx = args.index("--only")
        assert args[idx + 1] == "fortivpn,singbox"

    def test_plist_uses_current_python(self, tmp_dir):
        import sys

        plist = daemon._build_plist(tmp_dir)

        assert plist["ProgramArguments"][0] == sys.executable

    def test_plist_log_paths(self, tmp_dir):
        plist = daemon._build_plist(tmp_dir)

        assert plist["StandardOutPath"].endswith("daemon.log")
        assert plist["StandardErrorPath"].endswith("daemon.log")

    def test_plist_creates_log_dir(self, tmp_dir):
        log_dir = tmp_dir / "logs"
        assert not log_dir.exists()

        daemon._build_plist(tmp_dir)

        assert log_dir.exists()


# =========================================================================
# status
# =========================================================================


class TestStatus:
    def test_not_installed(self, tmp_path):
        with patch.object(daemon, "PLIST_PATH", tmp_path / "nonexistent.plist"):
            result = daemon.status()

        assert result["installed"] is False
        assert result["running"] is False
        assert result["pid"] is None

    def test_installed_and_running(self, tmp_path):
        plist_path = tmp_path / "test.plist"
        plist_path.write_text("")

        launchctl_output = "PID\tStatus\tLabel\n12345\t0\tcom.tunnelvault.keepalive\n"
        mock_result = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=launchctl_output,
        )
        with (
            patch.object(daemon, "PLIST_PATH", plist_path),
            patch("tv.daemon.subprocess.run", return_value=mock_result),
        ):
            result = daemon.status()

        assert result["installed"] is True
        assert result["running"] is True
        assert result["pid"] == 12345

    def test_installed_but_stopped(self, tmp_path):
        plist_path = tmp_path / "test.plist"
        plist_path.write_text("")

        launchctl_output = "PID\tStatus\tLabel\n-\t0\tcom.tunnelvault.keepalive\n"
        mock_result = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=launchctl_output,
        )
        with (
            patch.object(daemon, "PLIST_PATH", plist_path),
            patch("tv.daemon.subprocess.run", return_value=mock_result),
        ):
            result = daemon.status()

        assert result["installed"] is True
        assert result["running"] is False
        assert result["pid"] is None

    def test_installed_not_in_launchctl_list(self, tmp_path):
        plist_path = tmp_path / "test.plist"
        plist_path.write_text("")

        # launchctl list succeeds but label not found
        mock_result = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="PID\tStatus\tLabel\n",
        )
        with (
            patch.object(daemon, "PLIST_PATH", plist_path),
            patch("tv.daemon.subprocess.run", return_value=mock_result),
        ):
            result = daemon.status()

        assert result["installed"] is True
        assert result["running"] is False


# =========================================================================
# run_install
# =========================================================================


class TestRunInstall:
    def test_writes_plist_and_loads(self, tmp_dir, tmp_path):
        plist_path = tmp_path / "test.plist"

        mock_load = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        with (
            patch.object(daemon, "PLIST_PATH", plist_path),
            patch("tv.daemon.subprocess.run", return_value=mock_load),
        ):
            daemon.run_install(tmp_dir)

        assert plist_path.exists()
        # Verify it's valid plist
        data = plistlib.loads(plist_path.read_bytes())
        assert data["Label"] == "com.tunnelvault.keepalive"
        assert data["Label"] == "com.tunnelvault.keepalive"

    def test_unloads_existing_before_install(self, tmp_dir, tmp_path):
        plist_path = tmp_path / "test.plist"
        plist_path.write_text("")  # already exists

        calls = []

        def track_calls(cmd, **kwargs):
            calls.append(cmd)
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="", stderr=""
            )

        with (
            patch.object(daemon, "PLIST_PATH", plist_path),
            patch("tv.daemon.subprocess.run", side_effect=track_calls),
        ):
            daemon.run_install(tmp_dir)

        # First call should be unload, second should be load
        assert "unload" in calls[0]
        assert "load" in calls[1]

    def test_passes_only_to_plist(self, tmp_dir, tmp_path):
        plist_path = tmp_path / "test.plist"

        mock_load = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        with (
            patch.object(daemon, "PLIST_PATH", plist_path),
            patch("tv.daemon.subprocess.run", return_value=mock_load),
        ):
            daemon.run_install(tmp_dir, only="fortivpn")

        data = plistlib.loads(plist_path.read_bytes())
        args = data["ProgramArguments"]
        assert "--only" in args
        assert "fortivpn" in args


# =========================================================================
# run_uninstall
# =========================================================================


class TestRunUninstall:
    def test_unloads_and_removes(self, tmp_path):
        plist_path = tmp_path / "test.plist"
        plist_path.write_text("")

        mock_result = subprocess.CompletedProcess(args=[], returncode=0)
        with (
            patch.object(daemon, "PLIST_PATH", plist_path),
            patch("tv.daemon.subprocess.run", return_value=mock_result),
        ):
            daemon.run_uninstall()

        assert not plist_path.exists()

    def test_not_installed_noop(self, tmp_path, capsys):
        plist_path = tmp_path / "nonexistent.plist"

        with (
            patch.object(daemon, "PLIST_PATH", plist_path),
            patch("tv.daemon.subprocess.run") as mock_run,
        ):
            daemon.run_uninstall()

        mock_run.assert_not_called()
        out = capsys.readouterr().out
        assert "not installed" in out.lower() or "не установлен" in out.lower()


# =========================================================================
# run_status
# =========================================================================


class TestRunStatus:
    def test_prints_not_installed(self, tmp_path, capsys):
        with patch.object(daemon, "PLIST_PATH", tmp_path / "nope.plist"):
            daemon.run_status()

        out = capsys.readouterr().out
        assert "com.tunnelvault.keepalive" in out

    def test_prints_running(self, tmp_path, capsys):
        plist_path = tmp_path / "test.plist"
        plist_path.write_text("")

        launchctl_output = "PID\tStatus\tLabel\n12345\t0\tcom.tunnelvault.keepalive\n"
        mock_result = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=launchctl_output
        )
        with (
            patch.object(daemon, "PLIST_PATH", plist_path),
            patch("tv.daemon.subprocess.run", return_value=mock_result),
        ):
            daemon.run_status()

        out = capsys.readouterr().out
        assert "12345" in out
