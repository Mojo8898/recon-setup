"""Tests for the tasks.yaml-driven dispatch in tasks.py and a smoke test that
every builder renders with no leftover placeholders.
"""

import recon_setup.utils.tasks as T
from recon_setup.utils import builders as B


class Ctx:
    """Minimal Context stand-in for dispatch tests."""

    def __init__(self, creds=True):
        self._creds = creds
        self.ip = "1.1.1.1"
        self.domain = "d.local"
        self.vhost = None
        self.sprayable_ports = {}

    def get_target(self):
        return "dc.d.local"

    def creds_exist(self):
        return self._creds

    def get_initial_cred(self):
        return ("u", "p")


# ===========================================================================
# Dispatch
# ===========================================================================


class TestHandleTask:
    def test_generic_handler_runs_builder(self, monkeypatch):
        seen = []
        monkeypatch.setattr(T, "_run_commands", lambda ctx, cmds: seen.append(cmds))
        T.handle_task(Ctx(), 53)
        assert seen and any("DNS" in c.description for c in seen[0])

    def test_custom_handler_routed(self, monkeypatch):
        called = []
        monkeypatch.setitem(T._CUSTOM_HANDLERS, "ldap", lambda c: called.append("ldap"))
        monkeypatch.setitem(T._CUSTOM_HANDLERS, "smb", lambda c: called.append("smb"))
        T.handle_task(Ctx(), 389)
        T.handle_task(Ctx(), 445)
        assert called == ["ldap", "smb"]

    def test_require_cred_runs_with_creds(self, monkeypatch):
        seen = []
        monkeypatch.setattr(T, "_run_commands", lambda ctx, cmds: seen.append(cmds))
        T.handle_task(Ctx(creds=True), 1433)
        assert seen and any("MSSQL" in c.description for c in seen[0])

    def test_require_cred_skips_without_creds(self, monkeypatch):
        seen = []
        monkeypatch.setattr(T, "_run_commands", lambda ctx, cmds: seen.append(cmds))
        T.handle_task(Ctx(creds=False), 1433)
        assert seen == []

    def test_kerberos_cred_vs_no_cred(self, monkeypatch):
        seen = []
        monkeypatch.setattr(T, "_run_commands", lambda ctx, cmds: seen.extend(cmds))
        T.handle_task(Ctx(creds=True), 88)
        with_cred = len(seen)
        seen.clear()
        T.handle_task(Ctx(creds=False), 88)
        assert with_cred == 2 and len(seen) == 1

    def test_string_port_accepted(self, monkeypatch):
        seen = []
        monkeypatch.setattr(T, "_run_commands", lambda ctx, cmds: seen.append(cmds))
        T.handle_task(Ctx(), "53")
        assert seen

    def test_sprayable_only_port_populates_without_handler(self, monkeypatch):
        seen = []
        monkeypatch.setattr(T, "_run_commands", lambda ctx, cmds: seen.append(cmds))
        ctx = Ctx()
        T.handle_task(ctx, 22)
        assert ctx.sprayable_ports.get(22) == "ssh"
        assert seen == []

    def test_sprayable_port_with_handler(self, monkeypatch):
        monkeypatch.setattr(T, "_run_commands", lambda ctx, cmds: None)
        ctx = Ctx()
        T.handle_task(ctx, 135)
        assert ctx.sprayable_ports.get(135) == "wmi"  # spray label != handler

    def test_unknown_port_is_noop(self, monkeypatch):
        seen = []
        monkeypatch.setattr(T, "_run_commands", lambda ctx, cmds: seen.append(cmds))
        ctx = Ctx()
        T.handle_task(ctx, 9999)
        assert seen == [] and ctx.sprayable_ports == {}


# ===========================================================================
# Smoke: every builder renders with no leftover {{placeholder}}
# ===========================================================================


def _strings(cmds):
    for c in cmds:
        yield c.description
        yield from c.args


def test_no_unrendered_placeholders():
    batches = [
        B.build_ftp_commands("1.1.1.1", ("u", "p")),
        B.build_ftp_commands("1.1.1.1"),
        B.build_dns_commands("1.1.1.1", "d.local"),
        B.build_http_commands("1.1.1.1", "dc.d.local"),
        B.build_https_commands("dc.d.local"),
        B.build_kerberos_commands("1.1.1.1", "d.local", ("u", "p")),
        B.build_kerberos_commands("1.1.1.1", "d.local"),
        B.build_rpc_commands("1.1.1.1"),
        B.build_ldap_commands("1.1.1.1", "d.local", "dc.d.local", cred=("u", "p")),
        B.build_ldap_commands("1.1.1.1", "d.local", "dc.d.local", anon_bind=True),
        B.build_mssql_commands("1.1.1.1", "d.local", ("u", "p")),
        B.build_nfs_commands("1.1.1.1"),
        B.build_smb_commands(
            "1.1.1.1", "dc.d.local", "d.local", cred=("u", "p"),
            shares=[{"name": "X", "access": ["READ"], "remark": ""}],
            share_method="user/pass",
        ),
    ]
    for cmds in batches:
        for s in _strings(cmds):
            assert "{{" not in s and "}}" not in s, f"unrendered placeholder in: {s!r}"
