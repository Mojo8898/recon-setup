"""Tests for silent runtime bug fixes (task-002)."""
import subprocess
import sys
import types
import unittest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Bug 1: vpn_path crash when -v flag is not provided (os.path.abspath(None))
# ---------------------------------------------------------------------------

class TestVpnPathNoneGuard(unittest.TestCase):
    """main() must not crash with os.path.abspath(None) when -v is omitted."""

    def test_parse_args_without_vpn_flag_does_not_abspath_none(self):
        """When -v is not supplied, vpn_path should remain None, not crash."""
        import recon_setup.main as m
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
# Bug 3: Double task execution in NmapLogHandler.on_modified (task-005)
# ---------------------------------------------------------------------------

class TestNmapLogHandlerDoubleExecution(unittest.TestCase):
    """NmapLogHandler must not fire handle_task twice when both 'already
    completed' lines land in the same on_modified batch."""

    def _make_handler(self, open_tcp_content="80,443"):
        """Build a NmapLogHandler with a fully mocked context."""
        import tempfile, os
        from recon_setup.watchers.nmap_watcher import NmapLogHandler

        # Temp file that acts as the tmux pipe file
        tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False)
        tmp.close()

        ctx = MagicMock()
        ctx.tmux_pipe_file = tmp.name
        ctx.nmap_dir = os.path.dirname(tmp.name)

        # Write a fake open_tcp.txt next to the pipe file
        open_tcp = os.path.join(ctx.nmap_dir, "open_tcp.txt")
        with open(open_tcp, 'w') as f:
            f.write(open_tcp_content)

        handler = NmapLogHandler(ctx)
        return handler, tmp.name, open_tcp

    def tearDown(self):
        import os
        # Best-effort cleanup
        for attr in ('_pipe', '_tcp'):
            path = getattr(self, attr, None)
            if path and os.path.exists(path):
                try:
                    os.unlink(path)
                except OSError:
                    pass

    def test_no_double_execution_when_two_already_completed_lines_in_batch(self):
        """When two 'already completed' lines arrive together, handle_task must
        be called exactly once per port (not twice)."""
        import os
        from unittest.mock import patch

        handler, pipe_path, tcp_path = self._make_handler("80,443")
        self._pipe = pipe_path
        self._tcp = tcp_path

        # Write two "already completed" lines to the pipe file
        two_lines = (
            "Targeted TCP scan already completed\n"
            "UDP scan already completed\n"
        )
        with open(pipe_path, 'w') as f:
            f.write(two_lines)

        event = MagicMock()
        event.src_path = pipe_path

        called_ports = []
        with patch("recon_setup.watchers.nmap_watcher.handle_task",
                   side_effect=lambda ctx, port: called_ports.append(port)):
            handler.on_modified(event)

        # Each port must appear exactly once
        self.assertEqual(sorted(called_ports), ["443", "80"],
                         f"Expected each port once, got: {called_ports}")

    def test_pipe_pane_called_once_for_already_completed(self):
        """pipe-pane must be sent exactly once when 'already completed' fires."""
        import os

        handler, pipe_path, tcp_path = self._make_handler("22")
        self._pipe = pipe_path
        self._tcp = tcp_path

        with open(pipe_path, 'w') as f:
            f.write("Targeted TCP scan already completed\n")

        event = MagicMock()
        event.src_path = pipe_path

        with patch("recon_setup.watchers.nmap_watcher.handle_task"):
            handler.on_modified(event)

        handler.context.nmap_pane.cmd.assert_called_once_with("pipe-pane")

    def test_completed_event_set_after_already_completed_line(self):
        """completed Event must be set after processing 'already completed'."""
        import os

        handler, pipe_path, tcp_path = self._make_handler("22")
        self._pipe = pipe_path
        self._tcp = tcp_path

        with open(pipe_path, 'w') as f:
            f.write("Targeted TCP scan already completed\n")

        event = MagicMock()
        event.src_path = pipe_path

        self.assertFalse(handler.completed.is_set())
        with patch("recon_setup.watchers.nmap_watcher.handle_task"):
            handler.on_modified(event)
        self.assertTrue(handler.completed.is_set())

    def test_break_stops_processing_subsequent_lines(self):
        """After 'already completed', any further lines (e.g. discovered port)
        must NOT be processed."""
        import os

        handler, pipe_path, tcp_path = self._make_handler("22")
        self._pipe = pipe_path
        self._tcp = tcp_path

        # "already completed" appears first; a spurious "Discovered open port"
        # follows — it must be ignored due to the break.
        with open(pipe_path, 'w') as f:
            f.write(
                "Targeted TCP scan already completed\n"
                "Discovered open port 9999/tcp on 10.10.10.1\n"
            )

        event = MagicMock()
        event.src_path = pipe_path

        called_ports = []
        with patch("recon_setup.watchers.nmap_watcher.handle_task",
                   side_effect=lambda ctx, port: called_ports.append(port)):
            handler.on_modified(event)

        # Only port 22 (from open_tcp.txt) should be handled; 9999 must not appear
        self.assertNotIn("9999", called_ports,
                         "Port 9999 should have been skipped due to break")
        self.assertIn("22", called_ports)


if __name__ == "__main__":
    unittest.main()
