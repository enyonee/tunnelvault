"""Tests for tv.daemon: daemonize, PID file, autostart management."""

from __future__ import annotations

import os
import plistlib
import subprocess
from unittest.mock import patch, MagicMock

from tv import daemon


# =========================================================================
# PID file
# =========================================================================


class TestPidFile:
    def test_write_and_read(self, tmp_dir):
        daemon.write_pid(tmp_dir, pid=42)
        assert daemon.read_pid(tmp_dir) == 42

    def test_write_default_pid(self, tmp_dir):
        daemon.write_pid(tmp_dir)
        assert daemon.read_pid(tmp_dir) == os.getpid()

    def test_read_missing(self, tmp_dir):
        assert daemon.read_pid(tmp_dir) is None

    def test_remove(self, tmp_dir):
        daemon.write_pid(tmp_dir, pid=99)
        daemon.remove_pid(tmp_dir)
        assert daemon.read_pid(tmp_dir) is None

    def test_remove_missing_noop(self, tmp_dir):
        daemon.remove_pid(tmp_dir)  # should not raise

    def test_stale_pid(self, tmp_dir):
        daemon.write_pid(tmp_dir, pid=999999)
        assert not daemon.is_pid_alive(999999)

    def test_pid_file_path(self, tmp_dir):
        path = daemon.pid_file_path(tmp_dir)
        assert path.name == "tunnelvault.pid"
        assert str(tmp_dir) in str(path)


# =========================================================================
# daemonize
# =========================================================================


class TestDaemonize:
    def test_parent_gets_child_pid(self, tmp_dir):
        with patch("tv.daemon.os.fork", return_value=12345):
            result = daemon.daemonize(tmp_dir)
        assert result == 12345

    def test_child_calls_setsid(self, tmp_dir):
        with (
            patch("tv.daemon.os.fork", return_value=0),
            patch("tv.daemon.os.setsid") as mock_setsid,
            patch("tv.daemon.os.open", return_value=3),
            patch("tv.daemon.os.dup2"),
            patch("tv.daemon.os.close"),
            patch("tv.daemon.write_pid"),
        ):
            result = daemon.daemonize(tmp_dir)

        assert result == 0
        mock_setsid.assert_called_once()

    def test_child_writes_pid(self, tmp_dir):
        with (
            patch("tv.daemon.os.fork", return_value=0),
            patch("tv.daemon.os.setsid"),
            patch("tv.daemon.os.open", return_value=3),
            patch("tv.daemon.os.dup2"),
            patch("tv.daemon.os.close"),
            patch("tv.daemon.write_pid") as mock_write,
        ):
            daemon.daemonize(tmp_dir)

        mock_write.assert_called_once_with(tmp_dir)

    def test_child_redirects_stdio(self, tmp_dir):
        dup2_calls = []

        def track_dup2(fd, target):
            dup2_calls.append((fd, target))

        with (
            patch("tv.daemon.os.fork", return_value=0),
            patch("tv.daemon.os.setsid"),
            patch("tv.daemon.os.open", return_value=3),
            patch("tv.daemon.os.dup2", side_effect=track_dup2),
            patch("tv.daemon.os.close"),
            patch("tv.daemon.write_pid"),
        ):
            daemon.daemonize(tmp_dir)

        # Should redirect stdout(1), stderr(2), stdin(0)
        targets = [call[1] for call in dup2_calls]
        assert 0 in targets  # stdin
        assert 1 in targets  # stdout
        assert 2 in targets  # stderr


# =========================================================================
# _build_plist
# =========================================================================


class TestBuildPlist:
    def test_basic_plist(self, tmp_dir):
        plist = daemon._build_plist(tmp_dir)

        assert plist["Label"] == "com.tunnelvault.keepalive"
        assert plist["RunAtLoad"] is True
        assert plist["KeepAlive"] is True
        assert "--foreground" in plist["ProgramArguments"]
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

    def test_plist_includes_foreground_flag(self, tmp_dir):
        """Launchd plist must use --foreground so process doesn't fork."""
        plist = daemon._build_plist(tmp_dir)
        assert "--foreground" in plist["ProgramArguments"]


# =========================================================================
# _build_systemd_unit
# =========================================================================


class TestBuildSystemdUnit:
    def test_basic_unit(self, tmp_dir):
        import sys

        unit = daemon._build_systemd_unit(tmp_dir)

        assert "[Unit]" in unit
        assert "[Service]" in unit
        assert "[Install]" in unit
        assert "Type=simple" in unit
        assert "--foreground" in unit
        assert sys.executable in unit
        assert str(tmp_dir.resolve()) in unit

    def test_unit_with_only(self, tmp_dir):
        unit = daemon._build_systemd_unit(tmp_dir, only="openvpn")

        assert "--only openvpn" in unit

    def test_unit_restart_on_failure(self, tmp_dir):
        unit = daemon._build_systemd_unit(tmp_dir)

        assert "Restart=on-failure" in unit
        assert "RestartSec=10" in unit

    def test_unit_after_network(self, tmp_dir):
        unit = daemon._build_systemd_unit(tmp_dir)

        assert "After=network-online.target" in unit


# =========================================================================
# enable / disable
# =========================================================================


class TestEnable:
    def test_enable_macos(self, tmp_dir, tmp_path):
        plist_path = tmp_path / "test.plist"
        mock_load = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        with (
            patch("tv.daemon.platform.system", return_value="Darwin"),
            patch.object(daemon, "PLIST_PATH", plist_path),
            patch("tv.daemon.subprocess.run", return_value=mock_load),
        ):
            daemon.enable(tmp_dir)

        assert plist_path.exists()
        data = plistlib.loads(plist_path.read_bytes())
        assert data["Label"] == "com.tunnelvault.keepalive"

    def test_enable_linux(self, tmp_dir, tmp_path):
        unit_path = tmp_path / "test.service"
        mock_result = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        with (
            patch("tv.daemon.platform.system", return_value="Linux"),
            patch.object(daemon, "SYSTEMD_PATH", unit_path),
            patch("tv.daemon.subprocess.run", return_value=mock_result),
        ):
            daemon.enable(tmp_dir)

        assert unit_path.exists()
        content = unit_path.read_text()
        assert "--foreground" in content


class TestDisable:
    def test_disable_macos(self, tmp_path):
        plist_path = tmp_path / "test.plist"
        plist_path.write_text("")

        mock_result = subprocess.CompletedProcess(args=[], returncode=0)
        with (
            patch("tv.daemon.platform.system", return_value="Darwin"),
            patch.object(daemon, "PLIST_PATH", plist_path),
            patch("tv.daemon.subprocess.run", return_value=mock_result),
        ):
            daemon.disable()

        assert not plist_path.exists()

    def test_disable_linux(self, tmp_path):
        unit_path = tmp_path / "test.service"
        unit_path.write_text("")

        mock_result = subprocess.CompletedProcess(args=[], returncode=0)
        with (
            patch("tv.daemon.platform.system", return_value="Linux"),
            patch.object(daemon, "SYSTEMD_PATH", unit_path),
            patch("tv.daemon.subprocess.run", return_value=mock_result),
        ):
            daemon.disable()

        assert not unit_path.exists()

    def test_disable_not_configured(self, tmp_path, capsys):
        with (
            patch("tv.daemon.platform.system", return_value="Darwin"),
            patch.object(daemon, "PLIST_PATH", tmp_path / "nope.plist"),
            patch("tv.daemon.subprocess.run") as mock_run,
        ):
            daemon.disable()

        mock_run.assert_not_called()
        out = capsys.readouterr().out
        assert "not configured" in out.lower() or "не настроен" in out.lower()


