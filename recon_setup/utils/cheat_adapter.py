"""Resolve aliasr cheats into recon-setup command lines.

recon-setup and the aliasr TUI share one source of truth for command text: the
markdown cheats under aliasr's ``CHEAT_PATHS``.  A ``tasks.yaml`` pane can point
at a cheat section (by file + ``## heading``) instead of embedding a literal
``run:`` block; this module reads that section from the *installed* aliasr at
runtime and renders it, so editing a cheat no longer forces a recon-setup
release.

Only aliasr's lightweight ``core`` layer is used (markdown parsing +
``variations.toml`` resolution) — never the textual TUI.  Three jobs:

1. **Find** the cheat by ``(file, section)``.
2. **Resolve variations** (``<auth>``, ``<smb_modules>``, ``<impacket_auth>`` …):
   aliasr prompts for these interactively; recon-setup is non-interactive, so it
   fixes the choice from a per-param policy (overridable per pane).
3. **Bridge placeholders** (``<ip>``, ``<user>``, ``<password>`` …) to
   recon-setup's runtime values, and apply recon-setup's own faketime overlay to
   the Kerberos lines (aliasr cheats don't carry that wrapper).
"""

from __future__ import annotations

import re
from typing import Any

from recon_setup.utils.task_spec import TaskSpecError

# aliasr placeholder syntax: ``<name>`` or ``<name|default>``.  Same shape as
# aliasr's own ``_PH_RE``; kept local so recon-setup doesn't reach into private
# aliasr internals for it.
_PH_RE = re.compile(r"<([^>\s]+)>")

# Lines that need the DC clock-skew shim: an inline ``-k``, a kcache, or an
# impacket TGT request.  recon-setup wraps these with its faketime prefix
# because the cheats themselves don't (aliasr relies on an external ``skewrun``
# shell instead).
_KRB_HINT = re.compile(r"(?<=\s)-k(?=\s|$)|--use-kcache|\bgetTGT\.py\b|KRB5CCNAME")

# Default variation choice when a pane doesn't override it.  Auth key sets
# differ *per command* (``[nxc.auth]`` has "Password + Kerberos", but
# ``[smbclientng.auth]`` does not — its Kerberos is ccache-based), so the policy
# is keyed ``"<head>.<param>"`` and falls back to a bare ``"<param>"``.  A param
# with variations but no matching entry has "no safe default": the pane must
# choose, else rendering fails loudly rather than guessing.
_VARIATION_POLICY: dict[str, str] = {
    # nxc: Password + Kerberos == recon-setup's existing ``-p '<pw>' -k`` form.
    "nxc.auth": "Password + Kerberos",
    # smbclientng has no inline ``-k``; its Kerberos path reuses the ccache that
    # the "SMB all in one" getTGT step exports.
    "smbclientng.auth": "Kerberos",
    "impacket_auth": "Kerberos",
}


def _load_aliasr():
    """Import aliasr's core modules, or raise a clear TaskSpecError."""
    try:
        from aliasr.core import assemble, cheats, variations
    except ModuleNotFoundError as exc:  # pragma: no cover - env-dependent
        raise TaskSpecError(
            "aliasr is required to resolve cheat-backed tasks but is not "
            "installed (pip install aliasr), or pin the pane to a literal "
            "`run:` block instead of `cheat:`."
        ) from exc
    return cheats, variations, assemble


def _find_cheat(file: str, section: str):
    """Return the one cheat whose path ends with *file* and title == *section*."""
    cheats_mod, _, _ = _load_aliasr()
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


def _ordered_params(cmd: str) -> list[str]:
    """Placeholder names in *cmd*, first-seen order, defaults stripped."""
    seen: list[str] = []
    for tok in _PH_RE.findall(cmd):
        name = tok.split("|", 1)[0]
        if name not in seen:
            seen.append(name)
    return seen


def _resolve_variations(cmd: str, overrides: dict[str, str], variations_mod) -> str:
    """Replace every variation placeholder with a concrete fragment.

    A pane may override any choice; otherwise :data:`_VARIATION_POLICY` decides.
    An override value that isn't a known variation key is taken as a literal
    substitution (so a pane can inject a custom ``<smb_modules>`` string that
    isn't in ``variations.toml``).
    """
    var_map = variations_mod.get_all_variations(cmd, _ordered_params(cmd))
    out = cmd
    for param, variations in var_map.items():
        head = variations[0].command_prefix  # "nxc", "smbclientng", or "_"
        by_key = {v.key: v.value for v in variations}
        choice = (
            overrides.get(param)
            or _VARIATION_POLICY.get(f"{head}.{param}")
            or _VARIATION_POLICY.get(param)
        )
        if choice is None:
            raise TaskSpecError(
                f"cheat variation <{param}> ({head}) needs a choice "
                f"(options: {sorted(by_key)})"
            )
        value = by_key.get(choice, choice)  # known key -> its value, else literal
        out = variations_mod.apply_variation(out, param, value)
    # Pane overrides for params with no variations.toml table (e.g. a custom
    # <smb_modules> string): inject them literally.
    for param, value in overrides.items():
        if param not in var_map:
            out = variations_mod.apply_variation(out, param, value)
    return out


def _substitute(cmd: str, params: dict[str, Any]) -> str:
    """Fill recon-setup runtime placeholders; honor ``<name|default>``."""

    def repl(match: re.Match[str]) -> str:
        name, _, default = match.group(1).partition("|")
        if name in params and params[name] is not None:
            return str(params[name])
        if default:
            return default
        raise TaskSpecError(f"cheat placeholder <{match.group(1)}> is unbound")

    return _PH_RE.sub(repl, cmd)


def _faketime(line: str, ft: str, rule: Any) -> str:
    """Prefix *line* with the faketime shim per *rule*.

    ``rule`` is ``"kerberos"`` (default — only lines that look Kerberos-bound),
    ``True`` (every line) or ``False`` (never).
    """
    if not ft or rule is False:
        return line
    stripped = line.strip()
    # A bare assignment (``export VAR=…`` or ``VAR=…``) has nothing to time.
    if stripped.startswith("export ") or re.match(r"^\w+=", stripped):
        return line
    if rule is True or _KRB_HINT.search(line):
        return ft + line
    return line


def render_cheat(ref: dict[str, Any], params: dict[str, Any]) -> list[str]:
    """Render a cheat *ref* into resolved shell lines.

    *ref* keys:
      * ``file``     — path suffix, e.g. ``protocols/smb.md``
      * ``section``  — the ``## heading`` text, e.g. ``nxc smb modules``
      * ``variations`` — optional ``{param: choice}`` overrides
      * ``faketime`` — ``"kerberos"`` (default) | ``True`` | ``False``

    *params* carries recon-setup's runtime values (``ip``, ``user`` …) plus the
    faketime prefix under ``ft`` (same convention as literal ``run:`` panes).
    """
    _, variations_mod, assemble_mod = _load_aliasr()
    cheat = _find_cheat(ref["file"], ref["section"])
    cmd = _resolve_variations(cheat.cmd, ref.get("variations", {}) or {}, variations_mod)
    cmd = _substitute(cmd, params)
    rule = ref.get("faketime", "kerberos")
    ft = str(params.get("ft", "") or "")
    return [_faketime(c, ft, rule) for c in assemble_mod.split_commands(cmd)]
