"""Tests for the cheat-driven initial port scan (recon_setup.utils.scan)."""

import subprocess

import pytest

from recon_setup.utils import scan


class TestCompletionSentinel:
    """The sentinel must survive command-echo: the pane echoes the command it
    is sent into the piped log, so the marker must NOT appear in the command
    text, only in the command's output."""

    def test_marker_absent_from_command_text(self):
        # If this fails, the watcher would match the echoed command and report
        # the scan complete before it even starts.
        assert scan.SCAN_COMPLETE not in scan.SCAN_COMPLETE_CMD

    def test_command_outputs_the_marker(self):
        out = subprocess.run(
            ["bash", "-c", scan.SCAN_COMPLETE_CMD],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        assert out == scan.SCAN_COMPLETE


class TestDetectLhost:
    def test_parses_inet_from_ip_output(self):
        sample = (
            "9: tun0    inet 10.10.15.203/23 brd 10.10.15.255 scope global tun0"
        )
        assert scan._INET_RE.search(sample).group(1) == "10.10.15.203"

    def test_detect_lhost_missing_iface_returns_none(self):
        # A name that won't exist; detect_lhost swallows the error and returns None.
        assert scan.detect_lhost("definitely-not-an-iface-xyz") is None


class TestBuildScanCommand:
    """Integration: the real aliasr assemble() turns the recon cheat into an
    arun chain. Skipped when aliasr isn't installed."""

    def setup_method(self):
        pytest.importorskip("aliasr")

    def test_builds_arun_chain_for_target(self):
        cmd = scan.build_scan_command("10.129.78.184", "10.10.15.203")
        assert "arun naabu -host 10.129.78.184" in cmd
        assert "-source-ip 10.10.15.203" in cmd
        assert "arun nmap -Pn -n -sU" in cmd
        assert "AR_SKEW" not in cmd  # recon cheat has no #faketime tag
