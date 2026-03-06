"""Command dataclass and faketime helper for recon_setup task builders.

Each Command represents one run_task call (one tmux pane).  args is a list of
individual shell-command strings; to_shell() joins them with '; ' to produce
the full pane command sent via send_keys.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Command:
    """A single tmux-pane command ready for run_task().

    Attributes:
        args:        List of shell command strings for this pane.  Each element
                     is one complete tool invocation (may include pipes/redirects
                     within a single tool chain).  to_shell() joins them with
                     '; ' so the pane runs them sequentially.
        description: Human-readable label shown in logs / tests.
        delay:       Seconds to sleep before executing (replaces the old inline
                     nxc/kerbrute heuristics in run_task).
    """

    args: list[str] = field(default_factory=list)
    description: str = ""
    delay: int = 2

    def to_shell(self) -> str:
        """Return the full shell string for tmux send_keys."""
        return "; ".join(self.args)


def faketime_prefix(ip: str) -> str:
    """Return the faketime/rdate shell prefix string for *ip*.

    The returned string ends with a trailing space so it can be directly
    prepended to a command string.

    Example::

        ft = faketime_prefix("10.10.10.1")
        shell_cmd = ft + "getTGT.py dom/user:pass"
    """
    awk = "{print $2, $3, $4}"
    return (
        f"faketime \"$(rdate -n {ip} -p"
        f" | awk '{awk}'"
        f" | date -f - \"+%Y-%m-%d %H:%M:%S\")\" "
    )


def with_faketime(ip: str, cmd: Command) -> Command:
    """Wrap every arg in *cmd* with the faketime/rdate prefix for *ip*.

    Intended for single-invocation Commands (e.g. getTGT.py) where the
    entire pane needs Kerberos time-sync.  For complex multi-tool panes
    (e.g. LDAP) apply faketime_prefix() to individual args in the builder.

    Returns a new Command; the original is not modified.
    """
    ft = faketime_prefix(ip)
    return Command(
        args=[f"{ft}{arg}" for arg in cmd.args],
        description=cmd.description,
        delay=cmd.delay,
    )
