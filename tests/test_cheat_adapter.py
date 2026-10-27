"""Tests for the aliasr cheat adapter.

render_cheat delegates all construction to aliasr.core.build.render, so these
exercise it against the real aliasr (a hard dependency): the adapter's own job
is only addressing (_find_cheat), the Kerberos-first selection policy, and
value/selection overrides.  _find_cheat is patched so tests don't depend on the
installed cheat corpus.
"""

import pytest

from recon_setup.utils import cheat_adapter as ca
from recon_setup.utils.task_spec import TaskSpecError

pytest.importorskip("aliasr")


class _FakeCheat:
    def __init__(self, cmd, build_tags=(), cheat_tags=("target/remote",)):
        self.cmd = cmd
        self.title = "t"
        self.path = "x.md"
        self.build_tags = tuple(build_tags)
        self.cheat_tags = tuple(cheat_tags)


def _patch(monkeypatch, cheat):
    monkeypatch.setattr(ca, "_find_cheat", lambda f, s: cheat)


class TestRenderCheat:
    def test_multi_command_plain_arun_chain(self, monkeypatch):
        _patch(monkeypatch, _FakeCheat("mkdir -p nmap\nnaabu -host <ip>"))
        out = ca.render_cheat({"file": "f", "section": "s"}, {"ip": "10.1.2.3"})
        assert out.startswith("arun mkdir -p nmap ; \\\n")
        assert "arun naabu -host 10.1.2.3" in out
        assert "AR_SKEW" not in out

    def test_faketime_exports_skew_and_resolves_impacket_auth(self, monkeypatch):
        _patch(
            monkeypatch,
            _FakeCheat(
                "getTGT.py <domain>/'<user>'<impacket_auth>\nnxc ldap <ip> --use-kcache",
                build_tags=("faketime",),
            ),
        )
        out = ca.render_cheat(
            {"file": "f", "section": "s"},
            {"ip": "10.1.2.3", "user": "bob", "domain": "d.htb"},
        )
        assert out.startswith("export AR_SKEW=10.1.2.3 ; \\\n")
        # Kerberos policy expands <impacket_auth> to its value, not the key.
        assert "arun getTGT.py d.htb/'bob' -k -no-pass" in out
        assert "Kerberos" not in out

    def test_auth_selection_renders_per_head(self, monkeypatch):
        _patch(
            monkeypatch,
            _FakeCheat("nxc smb <ip> <auth>\nsmbclientng --host <fqdn> <auth>"),
        )
        out = ca.render_cheat(
            {"file": "f", "section": "s"}, {"ip": "10.1.2.3", "fqdn": "dc.d"}
        )
        assert "arun nxc smb 10.1.2.3 --use-kcache" in out
        assert "arun smbclientng --host dc.d --ccache-file $KRB5CCNAME" in out

    def test_select_override_changes_key(self, monkeypatch):
        _patch(monkeypatch, _FakeCheat("nxc smb <ip> <auth>"))
        out = ca.render_cheat(
            {"file": "f", "section": "s", "select": {"auth": "Password"}},
            {"ip": "10.1.2.3", "password": "pw"},
        )
        assert out == "nxc smb 10.1.2.3 -p 'pw'"

    def test_set_override_injects_value(self, monkeypatch):
        # A custom <smb_modules> injected as a value (no variation key for it).
        _patch(monkeypatch, _FakeCheat("nxc smb <ip> <smb_modules>"))
        out = ca.render_cheat(
            {"file": "f", "section": "s", "set": {"smb_modules": "-M timeroast"}},
            {"ip": "10.1.2.3"},
        )
        assert out == "nxc smb 10.1.2.3 -M timeroast"

    def test_no_faketime_tag_means_no_skew(self, monkeypatch):
        _patch(monkeypatch, _FakeCheat("nxc smb <ip> --shares\nnxc ldap <ip>"))
        out = ca.render_cheat({"file": "f", "section": "s"}, {"ip": "10.1.2.3"})
        assert "AR_SKEW" not in out

    def test_target_local_emits_bare(self, monkeypatch):
        _patch(monkeypatch, _FakeCheat("whoami\nhostname", cheat_tags=("target/local",)))
        out = ca.render_cheat({"file": "f", "section": "s"}, {"ip": "10.1.2.3"})
        assert "arun" not in out
        assert out == "whoami ; \\\nhostname"

    def test_strict_raises_on_unbound_placeholder(self, monkeypatch):
        _patch(monkeypatch, _FakeCheat("nxc <ip> <mystery>"))
        with pytest.raises(Exception):  # aliasr BuildError surfaces the typo
            ca.render_cheat({"file": "f", "section": "s"}, {"ip": "10.1.2.3"})


class TestFindCheatErrors:
    def test_missing_section_raises_taskspecerror(self, monkeypatch):
        # Real _find_cheat against the corpus: a nonexistent section must raise.
        with pytest.raises(TaskSpecError, match="not found"):
            ca._find_cheat("protocols/smb.md", "no such section here")
