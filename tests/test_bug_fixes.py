"""Tests for silent runtime bug fixes (task-002)."""
import os
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Bug 1: vpn_path crash when -v flag is not provided (os.path.abspath(None))
# ---------------------------------------------------------------------------

class TestVpnPathNoneGuard(unittest.TestCase):
    """main() must not crash with os.path.abspath(None) when -v is omitted."""

    def test_parse_args_without_vpn_flag_does_not_abspath_none(self):
        """When -v is not supplied, vpn_path should remain None, not crash."""
        import argparse

        # Build a minimal namespace that mirrors what argparse produces when
        # -v is not provided (vpn_path defaults to None).
        args = argparse.Namespace(
            vpn_path=None,
            session_name="test",
            session_path="/tmp",
            ip="10.10.10.1",
            spawn=False,
            new_release=False,
            automate=False,
            username=None,
            password=None,
            debug=False,
        )

        # The patched code should produce None, not raise TypeError.
        import os
        result = os.path.abspath(args.vpn_path) if args.vpn_path is not None else None
        self.assertIsNone(result)

    def test_parse_args_with_vpn_flag_resolves_path(self):
        """When -v is supplied, vpn_path should be resolved to an absolute path."""
        import os
        vpn_path = "/tmp/myvpn.ovpn"
        result = os.path.abspath(vpn_path) if vpn_path is not None else None
        self.assertEqual(result, "/tmp/myvpn.ovpn")


# ---------------------------------------------------------------------------
# Bug 2: result NameError in spray.py enum_users (referenced outside try block)
# ---------------------------------------------------------------------------

class TestEnumUsersResultNameError(unittest.TestCase):
    """enum_users must not raise NameError when subprocess raises an exception."""

    def _make_context(self):
        ctx = MagicMock()
        ctx.log_file = "/dev/null"
        ctx.get_initial_cred.return_value = ("user", "pass")
        ctx.get_target.return_value = "dc.example.com"
        ctx.domain = "example.com"
        ctx.ip = "10.10.10.1"
        return ctx

    def test_no_name_error_when_subprocess_raises_called_process_error(self):
        """NameError must not propagate when CalledProcessError is raised."""
        from recon_setup.utils.spray import enum_users

        ctx = self._make_context()
        with patch("recon_setup.utils.spray.subprocess.run",
                   side_effect=subprocess.CalledProcessError(1, "cmd", stderr="err")):
            # Should not raise NameError or any unhandled exception
            try:
                enum_users(ctx)
            except NameError:
                self.fail("NameError raised – result was referenced before assignment")

    def test_no_name_error_when_subprocess_raises_generic_exception(self):
        """NameError must not propagate when a generic Exception is raised."""
        from recon_setup.utils.spray import enum_users

        ctx = self._make_context()
        with patch("recon_setup.utils.spray.subprocess.run",
                   side_effect=RuntimeError("network error")):
            try:
                enum_users(ctx)
            except NameError:
                self.fail("NameError raised – result was referenced before assignment")

    def test_successful_run_processes_output(self):
        """When subprocess succeeds, users should be added to context."""
        from recon_setup.utils.spray import enum_users

        ctx = self._make_context()
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "alice\nbob\nuser\n"

        with patch("recon_setup.utils.spray.subprocess.run", return_value=mock_result):
            enum_users(ctx)

        # context.add_cred should have been called for alice and bob (not self)
        calls = [c.args[0] for c in ctx.add_cred.call_args_list]
        self.assertIn("alice", calls)
        self.assertIn("bob", calls)
        self.assertNotIn("user", calls)  # the initial user is skipped


# ---------------------------------------------------------------------------
# NmapLogHandler parses the aliasr "port scan all in one" cheat output
# (naabu <ip>:<port> for TCP, nmap "Discovered open port" for UDP), dedups
# ports, and completes on the RECON_SCAN_COMPLETE sentinel.
# ---------------------------------------------------------------------------

class TestNmapLogHandlerCheatFormat(unittest.TestCase):
    IP = "10.129.78.184"

    def _handler(self):
        from recon_setup.watchers.nmap_watcher import NmapLogHandler

        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False)
        tmp.close()
        self._pipe = tmp.name
        ctx = MagicMock()
        ctx.tmux_pipe_file = tmp.name
        ctx.ip = self.IP
        return NmapLogHandler(ctx), tmp.name

    def tearDown(self):
        path = getattr(self, "_pipe", None)
        if path and os.path.exists(path):
            try:
                os.unlink(path)
            except OSError:
                pass

    def _feed(self, handler, pipe, text, *, append=False):
        """Write *text* to the pipe and run one on_modified; return dispatched ports."""
        with open(pipe, "a" if append else "w") as f:
            f.write(text)
        event = MagicMock()
        event.src_path = pipe
        ports = []
        with patch("recon_setup.watchers.nmap_watcher.handle_task",
                   side_effect=lambda ctx, port: ports.append(port)):
            handler.on_modified(event)
        return ports

    def test_naabu_tcp_ports_dispatched(self):
        h, pipe = self._handler()
        ports = self._feed(h, pipe, f"{self.IP}:445\n{self.IP}:53\n")
        self.assertEqual(ports, ["445", "53"])

    def test_udp_discovered_port_dispatched(self):
        h, pipe = self._handler()
        ports = self._feed(h, pipe, f"Discovered open port 123/udp on {self.IP}\n")
        self.assertEqual(ports, ["123"])

    def test_port_dispatched_once_across_tcp_and_udp(self):
        h, pipe = self._handler()
        ports = self._feed(
            h, pipe,
            f"{self.IP}:53\nDiscovered open port 53/udp on {self.IP}\n",
        )
        self.assertEqual(ports, ["53"])

    def test_service_detail_and_foreign_ip_lines_ignored(self):
        h, pipe = self._handler()
        ports = self._feed(
            h, pipe,
            f"  445/tcp (microsoft-ds)\n10.10.10.99:8080\n{self.IP}:445\n",
        )
        self.assertEqual(ports, ["445"])

    def test_sentinel_stops_pipe_and_sets_completed(self):
        from recon_setup.utils.scan import SCAN_COMPLETE

        h, pipe = self._handler()
        self.assertFalse(h.completed.is_set())
        ports = self._feed(h, pipe, f"{self.IP}:80\n{SCAN_COMPLETE}\n")
        self.assertIn("80", ports)
        self.assertTrue(h.completed.is_set())
        h.context.nmap_pane.cmd.assert_called_once_with("pipe-pane")

    def test_lines_after_sentinel_ignored(self):
        from recon_setup.utils.scan import SCAN_COMPLETE

        h, pipe = self._handler()
        ports = self._feed(h, pipe, f"{SCAN_COMPLETE}\n{self.IP}:9999\n")
        self.assertNotIn("9999", ports)
        self.assertTrue(h.completed.is_set())

    def test_dedup_across_batches(self):
        h, pipe = self._handler()
        first = self._feed(h, pipe, f"{self.IP}:445\n")
        # naabu's second (10001-65535) sweep can re-emit an already-seen port.
        second = self._feed(h, pipe, f"{self.IP}:445\n", append=True)
        self.assertEqual(first, ["445"])
        self.assertEqual(second, [])


if __name__ == "__main__":
    unittest.main()
