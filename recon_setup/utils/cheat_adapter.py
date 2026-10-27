"""Resolve aliasr cheats into recon-setup command strings.

recon-setup and the aliasr TUI share one source of truth for command text (the
markdown cheats) *and* one builder.  A ``cheat:`` pane names a cheat section by
``(file, ## heading)``; recon-setup looks it up and hands it to aliasr's own
:func:`aliasr.core.build.render` — the same non-interactive pipeline the TUI
uses (variation expansion, placeholder fill, the ``arun`` / ``AR_SKEW`` chain).

recon-setup supplies only what the TUI would get from a human:

* the runtime **values** (``ip``, ``user``, ``password`` …), and
* the variation **selections** — a Kerberos-first policy (DC clock skew is the
  cheat's own concern via its ``#faketime`` / ``AR_SKEW`` overlay), overridable
  per pane.

Needs ``aliasr>=1.1.5`` (for ``aliasr.core.build``).
"""

from __future__ import annotations

from typing import Any

from recon_setup.utils.task_spec import TaskSpecError

# Variation keys recon-setup picks by default (a pane may override via ``select``).
# aliasr renders one key per command head, so "Kerberos" becomes ``--use-kcache``
# for nxc, ``-k`` for bloodyAD, ``--ccache-file`` for smbclientng, and so on.
_SELECTION_POLICY: dict[str, str] = {
    "auth": "Kerberos",
    "impacket_auth": "Kerberos",
}


def _load_aliasr():
    """Import aliasr's cheat loader + command builder, or raise TaskSpecError."""
    try:
        from aliasr.core import build, cheats
    except ModuleNotFoundError as exc:  # pragma: no cover - env-dependent
        raise TaskSpecError(
            "aliasr is required to resolve cheat-backed tasks but is not "
            "installed (pip install 'aliasr>=1.1.5'), or pin the pane to a "
            "literal `run:` block instead of `cheat:`."
        ) from exc
    return cheats, build


def _find_cheat(file: str, section: str):
    """Return the one cheat whose path ends with *file* and title == *section*."""
    cheats_mod, _ = _load_aliasr()
    cheats_mod.load_cheats()
    want = file.replace("\\", "/")
    matches = [
        c
        for c in cheats_mod.get_loaded_cheats()
        if c.path.replace("\\", "/").endswith(want) and c.title == section
    ]
    if not matches:
        raise TaskSpecError(f"aliasr cheat not found: {file} :: '{section}'")
    # The same file can appear under several CHEAT_PATHS (package + user
    # override); identical bodies are fine, genuinely different ones are not.
    if len({c.cmd for c in matches}) > 1:
        raise TaskSpecError(
            f"aliasr cheat is ambiguous across cheat paths: {file} :: '{section}'"
        )
    return matches[0]


def render_cheat(ref: dict[str, Any], params: dict[str, Any]) -> str:
    """Render a cheat *ref* into one assembled command via aliasr.

    *ref* keys:
      * ``file``    — path suffix, e.g. ``protocols/smb.md``
      * ``section`` — the ``## heading`` text, e.g. ``smb all in one``
      * ``select``  — optional ``{param: key}`` variation overrides
      * ``set``     — optional ``{placeholder: value}`` overrides/extras

    *params* supplies the runtime placeholder values.  skew/encode/local are
    decided inside aliasr from the cheat's tags; recon-setup only chooses the
    variation keys and fills the values.
    """
    _, build = _load_aliasr()
    cheat = _find_cheat(ref["file"], ref["section"])
    return build.render(
        cheat.cmd,
        {**params, **(ref.get("set") or {})},
        selections={**_SELECTION_POLICY, **(ref.get("select") or {})},
        build_tags=cheat.build_tags,
        cheat_tags=cheat.cheat_tags,
        strict=True,
    )
