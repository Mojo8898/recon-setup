"""Unit tests for the aliasr cheat adapter.

These exercise the adapter's own logic (placeholder bridging, variation policy,
faketime overlay) with *fake* aliasr modules, so the suite never depends on the
installed aliasr's cheat corpus or on textual being importable.
"""

import re

import pytest

from recon_setup.utils import cheat_adapter as ca
from recon_setup.utils.task_spec import TaskSpecError


# ---------- fakes mimicking aliasr.core.variations / .assemble ----------


class _Var:
    """Duck-typed stand-in for aliasr.core.variations.Variation."""

    def __init__(self, key, value, param, command_prefix):
        self.key = key
        self.value = value
        self.param = param
        self.command_prefix = command_prefix


class _FakeVariations:
    """A minimal variations module keyed like the real variations.toml."""

    _TABLE = {
        ("nxc", "auth"): {
            "Password": "-p '<password>'",
            "Password + Kerberos": "-p '<password>' -k",
            "Kerberos": "--use-kcache",
        },
        ("smbclientng", "auth"): {
            "Password": "-p '<password>'",
            "Kerberos": "--ccache-file $KRB5CCNAME",
        },
    }

    def get_all_variations(self, cmd, params):
        head = cmd.split()[0] if cmd.split() else ""
        out = {}
        for p in params:
            choices = self._TABLE.get((head, p))
            if choices:
                out[p] = [_Var(k, v, p, head) for k, v in choices.items()]
        return out

    def apply_variation(self, cmd, param, value):
        return re.sub(rf"<{re.escape(param)}(?:\|[^>]*)?>", value, cmd)


class _FakeAssemble:
    @staticmethod
    def split_commands(cmd):
        return [ln for ln in cmd.split("\n") if ln.strip()]


# ---------- _ordered_params ----------


class TestOrderedParams:
    def test_order_dedupe_and_strip_defaults(self):
        cmd = "x <a> <b|def> <a> <c>"
        assert ca._ordered_params(cmd) == ["a", "b", "c"]


# ---------- _substitute ----------


class TestSubstitute:
    def test_fills_known_and_default(self):
        out = ca._substitute("u <user> n <name|test>", {"user": "bob"})
        assert out == "u bob n test"

    def test_unbound_raises(self):
        with pytest.raises(TaskSpecError, match="unbound"):
            ca._substitute("x <missing>", {})

    def test_none_value_falls_through_to_default(self):
        assert ca._substitute("<pw|fallback>", {"pw": None}) == "fallback"


# ---------- _faketime ----------


class TestFaketime:
    FT = "FT "

    def test_wraps_kerberos_line(self):
        assert ca._faketime("nxc smb x -k", self.FT, "kerberos") == "FT nxc smb x -k"

    def test_skips_non_kerberos_line(self):
        assert ca._faketime("nxc smb x -p y", self.FT, "kerberos") == "nxc smb x -p y"

    def test_skips_export_assignment(self):
        line = "export KRB5CCNAME=$(pwd)/x.ccache"
        assert ca._faketime(line, self.FT, "kerberos") == line

    def test_rule_true_wraps_everything_but_assignments(self):
        assert ca._faketime("echo hi", self.FT, True) == "FT echo hi"
        assert ca._faketime("A=1", self.FT, True) == "A=1"

    def test_rule_false_never_wraps(self):
        assert ca._faketime("nxc -k", self.FT, False) == "nxc -k"

    def test_no_ft_is_noop(self):
        assert ca._faketime("nxc -k", "", "kerberos") == "nxc -k"


# ---------- _resolve_variations (per-head policy + overrides) ----------


class TestResolveVariations:
    def test_nxc_auth_policy_default(self):
        out = ca._resolve_variations("nxc smb <ip> <auth>", {}, _FakeVariations())
        assert out == "nxc smb <ip> -p '<password>' -k"

    def test_smbclientng_auth_policy_default_is_ccache(self):
        out = ca._resolve_variations("smbclientng <auth>", {}, _FakeVariations())
        assert out == "smbclientng --ccache-file $KRB5CCNAME"

    def test_pane_override_wins(self):
        out = ca._resolve_variations(
            "nxc smb <auth>", {"auth": "Password"}, _FakeVariations()
        )
        assert out == "nxc smb -p '<password>'"

    def test_literal_override_for_param_without_table_entry(self):
        # smb_modules has no variations table here -> left untouched by resolve
        out = ca._resolve_variations("nxc <smb_modules>", {}, _FakeVariations())
        assert out == "nxc <smb_modules>"

    def test_missing_default_raises(self):
        fake = _FakeVariations()
        fake._TABLE = {("tool", "auth"): {"Password": "-p x"}}
        with pytest.raises(TaskSpecError, match="needs a choice"):
            ca._resolve_variations("tool <auth>", {}, fake)


# ---------- render_cheat end-to-end (fakes) ----------


class _FakeCheat:
    def __init__(self, cmd):
        self.cmd = cmd
        self.title = "t"
        self.path = "protocols/smb.md"


class TestRenderCheat:
    def _patch(self, monkeypatch, cmd):
        monkeypatch.setattr(
            ca, "_load_aliasr", lambda: (None, _FakeVariations(), _FakeAssemble())
        )
        monkeypatch.setattr(ca, "_find_cheat", lambda f, s: _FakeCheat(cmd))

    def test_nxc_section_matches_recon_form(self, monkeypatch):
        self._patch(monkeypatch, "nxc smb <ip> -u '<user>' <auth> <smb_modules>")
        lines = ca.render_cheat(
            {"file": "protocols/smb.md", "section": "nxc smb modules",
             "variations": {"smb_modules": "-M timeroast"}},
            {"ip": "10.0.0.1", "user": "bob", "password": "pw", "ft": "FT "},
        )
        assert lines == ["FT nxc smb 10.0.0.1 -u 'bob' -p 'pw' -k -M timeroast"]

    def test_multiline_export_not_wrapped(self, monkeypatch):
        self._patch(
            monkeypatch,
            "getTGT.py <domain>/'<user>' -k -no-pass\n"
            "export KRB5CCNAME=$(pwd)/x.ccache\n"
            "nxc smb <ip> -u '<user>' --use-kcache --shares",
        )
        lines = ca.render_cheat(
            {"file": "protocols/smb.md", "section": "x"},
            {"ip": "10.0.0.1", "user": "bob", "domain": "d.htb", "ft": "FT "},
        )
        assert lines[0].startswith("FT getTGT.py")
        assert lines[1] == "export KRB5CCNAME=$(pwd)/x.ccache"
        assert lines[2].startswith("FT nxc smb")

    def test_faketime_false_disables_overlay(self, monkeypatch):
        self._patch(monkeypatch, "nxc smb <ip> <auth>")
        lines = ca.render_cheat(
            {"file": "f", "section": "s", "faketime": False},
            {"ip": "1.2.3.4", "password": "pw", "ft": "FT "},
        )
        assert lines == ["nxc smb 1.2.3.4 -p 'pw' -k"]
