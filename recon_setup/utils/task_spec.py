"""Loader for the declarative task definitions in ``tasks.yaml``.

This is the bridge between the *data* (tasks.yaml) and the *logic* (builders).
It loads the YAML once, substitutes ``{{placeholder}}`` tokens, and renders
pane dicts into :class:`~recon_setup.utils.commands.Command` objects.

Design note: substitution is deliberately dumb.  It only fills placeholders —
it has no conditionals or loops.  Any branching ("auth vs anon") or iteration
("one spider per share") stays in the Python builders, which pick the right
slice of the spec and call :func:`render_panes`.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from recon_setup.utils.commands import Command

_SPEC_PATH = Path(__file__).with_name("tasks.yaml")
_PLACEHOLDER = re.compile(r"\{\{(\w+)\}\}")

_cache: dict[str, Any] | None = None


class TaskSpecError(Exception):
    """Raised when the task spec is malformed or a placeholder is unbound."""


def load_spec(reload: bool = False) -> dict[str, Any]:
    """Return the parsed tasks.yaml, caching the result.

    Pass ``reload=True`` to force a re-read (useful in tests).
    """
    global _cache
    if _cache is None or reload:
        with _SPEC_PATH.open(encoding="utf-8") as fh:
            _cache = yaml.safe_load(fh) or {}
    return _cache


def spec_get(*keys: str) -> Any:
    """Return the task-spec node at the nested *keys*.

    Raises :class:`TaskSpecError` (not a bare ``KeyError``) when a key along the
    path is missing, so a renamed or dropped ``tasks.yaml`` section fails with a
    message that names the missing section instead of surfacing deep inside a
    builder.
    """
    node: Any = load_spec()
    walked: list[str] = []
    for key in keys:
        walked.append(str(key))
        if not isinstance(node, dict) or key not in node:
            raise TaskSpecError(f"tasks.yaml: missing section '{'.'.join(walked)}'")
        node = node[key]
    return node


def _render(template: str, params: dict[str, Any]) -> str:
    """Substitute every ``{{name}}`` in *template* from *params*.

    Raises :class:`TaskSpecError` naming the offending placeholder when it is
    not bound — so a typo surfaces at build time with a clear message rather
    than silently producing a broken shell command.
    """

    def repl(match: re.Match[str]) -> str:
        key = match.group(1)
        if key not in params:
            raise TaskSpecError(
                f"unbound placeholder {{{{{key}}}}} while rendering: {template!r}"
            )
        return str(params[key])

    return _PLACEHOLDER.sub(repl, template)


def render_panes(
    panes: list[dict[str, Any]],
    params: dict[str, Any],
    *,
    has_cred: bool = False,
) -> list[Command]:
    """Render a list of pane dicts into Command objects.

    *panes* is a list of ``{description, delay, run, run_if_cred}`` dicts from
    the spec.  *params* supplies the placeholder values.  When *has_cred* is
    True, each pane's ``run_if_cred`` lines are appended after its ``run``
    lines (used by the FTP anon-then-auth pattern).
    """
    commands: list[Command] = []
    for pane in panes:
        args = [_render(line, params) for line in pane.get("run", [])]
        if has_cred:
            args += [_render(line, params) for line in pane.get("run_if_cred", [])]
        commands.append(
            Command(
                args=args,
                description=_render(pane.get("description", ""), params),
                delay=pane.get("delay", 2),
            )
        )
    return commands
