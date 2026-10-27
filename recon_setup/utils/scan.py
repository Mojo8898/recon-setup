"""Build the initial port scan from the aliasr ``port scan all in one`` cheat.

recon-setup used to shell out to a personal ``/opt/scripts/scan_machine.py``.
That script is gone: the scan command is now the aliasr reconnaissance cheat,
rendered through :mod:`recon_setup.utils.cheat_adapter` and sent straight to the
nmap pane.  The watcher (:mod:`recon_setup.watchers.nmap_watcher`) then parses
the pane output — naabu's ``<ip>:<port>`` lines for TCP and nmap's
``Discovered open port`` lines for UDP — and dispatches per-port tasks.
"""

from __future__ import annotations

import re
import subprocess

from recon_setup.utils.cheat_adapter import render_cheat

# Marker the watcher greps for to know the scan finished (naabu ``-silent``
# prints no "done" line of its own).
SCAN_COMPLETE = "RECON_SCAN_COMPLETE"

# The command that emits it.  The pane echoes the command it's sent into the
# piped log, so a plain ``echo RECON_SCAN_COMPLETE`` would make the watcher
# match the marker in the *echoed command* before the scan even runs.  The
# split-quote keeps the marker out of the command text while the shell still
# prints it (``'RECON_SCAN' '_COMPLETE'`` concatenate to the full marker).
SCAN_COMPLETE_CMD = "echo 'RECON_SCAN''_COMPLETE'"

_SCAN_CHEAT = {
    "file": "misc/reconnaissance.md",
    "section": "port scan all in one",
}

_INET_RE = re.compile(r"\binet\s+(\d{1,3}(?:\.\d{1,3}){3})")


def detect_lhost(interface: str = "tun0") -> str | None:
    """Return *interface*'s IPv4 address, or ``None`` if it can't be read.

    Used to fill the cheat's ``-source-ip`` — on an HTB/VPN box that's the
    ``tun0`` address (e.g. ``10.10.15.203``).
    """
    try:
        out = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", interface],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    m = _INET_RE.search(out or "")
    return m.group(1) if m else None


def build_scan_command(
    ip: str,
    lhost: str,
    *,
    interface: str = "tun0",
    rate_limit: int | None = None,
    retries: int | None = None,
) -> str:
    """Render the port-scan cheat into one assembled ``arun`` chain command.

    *lhost* is required (the cheat bakes in ``-source-ip``); callers resolve it
    via :func:`detect_lhost` or a CLI override before calling.  The returned
    command is the multi-line ``arun ... ; \\``-continued chain from the cheat
    adapter; callers append the completion sentinel (see
    :data:`SCAN_COMPLETE_CMD`).
    """
    params: dict[str, object] = {"ip": ip, "lhost": lhost, "interface": interface}
    if rate_limit is not None:
        params["rate_limit"] = rate_limit
    if retries is not None:
        params["retries"] = retries
    return render_cheat(_SCAN_CHEAT, params)
