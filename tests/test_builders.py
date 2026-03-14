"""Tests for commands.py (Command / with_faketime) and all builder functions.

Tests inspect cmd.args lists directly — not shell strings — so they are
decoupled from quoting/joining implementation details.
"""

import pytest

from recon_setup.utils.commands import Command, faketime_prefix, with_faketime
from recon_setup.utils.builders import (
    build_dns_commands,
    build_ftp_commands,
    build_http_commands,
    build_https_commands,
    build_kerberos_commands,
    build_ldap_commands,
    build_mssql_commands,
    build_nfs_commands,
    build_rpc_commands,
    build_smb_commands,
)


# ===========================================================================
# Command.to_shell()
# ===========================================================================


class TestCommandToShell:
    def test_single_arg(self):
        cmd = Command(args=["nxc smb 10.0.0.1"], description="x", delay=7)
        assert cmd.to_shell() == "nxc smb 10.0.0.1"

    def test_multiple_args_joined_by_semicolon(self):
        cmd = Command(args=["cmd1", "cmd2", "cmd3"])
        assert cmd.to_shell() == "cmd1; cmd2; cmd3"

    def test_empty_args_returns_empty_string(self):
        cmd = Command(args=[])
        assert cmd.to_shell() == ""

    def test_default_delay_is_2(self):
        cmd = Command(args=["x"])
        assert cmd.delay == 2

    def test_custom_delay(self):
        cmd = Command(args=["x"], delay=20)
        assert cmd.delay == 20


# ===========================================================================
# with_faketime()
# ===========================================================================


class TestWithFaketime:
    def test_wraps_each_arg_with_faketime_prefix(self):
        cmd = Command(args=["getTGT.py dom/user:pass"], description="TGT", delay=2)
        wrapped = with_faketime("10.0.0.1", cmd)
        assert len(wrapped.args) == 1
        assert wrapped.args[0].startswith("faketime ")
        assert "getTGT.py" in wrapped.args[0]

    def test_ip_appears_in_faketime_prefix(self):
        cmd = Command(args=["some-tool --arg"])
        wrapped = with_faketime("192.168.1.5", cmd)
        assert "192.168.1.5" in wrapped.args[0]

    def test_rdate_in_faketime_prefix(self):
        cmd = Command(args=["tool"])
        wrapped = with_faketime("10.0.0.1", cmd)
        assert "rdate" in wrapped.args[0]

    def test_preserves_delay_and_description(self):
        cmd = Command(args=["tool"], description="my desc", delay=15)
        wrapped = with_faketime("10.0.0.1", cmd)
        assert wrapped.delay == 15
        assert wrapped.description == "my desc"

    def test_original_command_unchanged(self):
        cmd = Command(args=["original-tool"])
        _ = with_faketime("10.0.0.1", cmd)
        assert cmd.args == ["original-tool"]

    def test_wraps_multiple_args(self):
        cmd = Command(args=["tool1 a", "tool2 b"])
        wrapped = with_faketime("10.0.0.1", cmd)
        assert len(wrapped.args) == 2
        assert all("faketime " in a for a in wrapped.args)
        assert "tool1 a" in wrapped.args[0]
        assert "tool2 b" in wrapped.args[1]

    def test_faketime_prefix_standalone(self):
        prefix = faketime_prefix("10.0.0.2")
        assert "faketime" in prefix
        assert "10.0.0.2" in prefix
        assert "rdate" in prefix
        assert prefix.endswith(" ")


# ===========================================================================
# build_ftp_commands
# ===========================================================================


class TestBuildFtpCommands:
    def test_unauthenticated_returns_one_command(self):
        cmds = build_ftp_commands(ip="10.0.0.1")
        assert len(cmds) == 1

    def test_unauthenticated_anon_login(self):
        cmds = build_ftp_commands(ip="10.0.0.1")
        assert len(cmds[0].args) == 1
        assert "nxc ftp" in cmds[0].args[0]
        assert "-u ''" in cmds[0].args[0]

    def test_unauthenticated_ip_present(self):
        cmds = build_ftp_commands(ip="10.0.0.1")
        assert "10.0.0.1" in cmds[0].args[0]

    def test_authenticated_returns_one_command_two_args(self):
        cmds = build_ftp_commands(ip="10.0.0.1", cred=("admin", "s3cr3t"))
        assert len(cmds) == 1
        assert len(cmds[0].args) == 2

    def test_authenticated_anon_first(self):
        cmds = build_ftp_commands(ip="10.0.0.1", cred=("admin", "s3cr3t"))
        assert "-u ''" in cmds[0].args[0]

    def test_authenticated_cred_in_second_arg(self):
        cmds = build_ftp_commands(ip="10.0.0.1", cred=("admin", "s3cr3t"))
        assert "admin" in cmds[0].args[1]
        assert "s3cr3t" in cmds[0].args[1]

    def test_delay_is_7_for_nxc(self):
        cmds = build_ftp_commands(ip="10.0.0.1")
        assert cmds[0].delay == 7


# ===========================================================================
# build_dns_commands
# ===========================================================================


class TestBuildDnsCommands:
    def test_returns_one_command(self):
        cmds = build_dns_commands(ip="10.0.0.1", domain="example.com")
        assert len(cmds) == 1

    def test_reverse_lookup_present(self):
        cmds = build_dns_commands(ip="10.0.0.1", domain="example.com")
        assert any("dig" in a and "-x" in a for a in cmds[0].args)

    def test_zone_transfer_present(self):
        cmds = build_dns_commands(ip="10.0.0.1", domain="example.com")
        assert any("axfr" in a and "example.com" in a for a in cmds[0].args)

    def test_ip_in_both_args(self):
        cmds = build_dns_commands(ip="10.0.0.1", domain="example.com")
        assert all("10.0.0.1" in a for a in cmds[0].args)


# ===========================================================================
# build_http_commands
# ===========================================================================


class TestBuildHttpCommands:
    def test_returns_three_panes(self):
        cmds = build_http_commands(ip="10.0.0.1", fqdn="dc.example.com")
        assert len(cmds) == 3

    def test_pane1_contains_firefox(self):
        cmds = build_http_commands(ip="10.0.0.1", fqdn="dc.example.com")
        assert any("firefox" in a for a in cmds[0].args)

    def test_pane1_contains_vhost_ffuf(self):
        cmds = build_http_commands(ip="10.0.0.1", fqdn="dc.example.com")
        assert any("ffuf" in a and "FUZZ.dc.example.com" in a for a in cmds[0].args)

    def test_pane1_contains_feroxbuster(self):
        cmds = build_http_commands(ip="10.0.0.1", fqdn="dc.example.com")
        assert any("feroxbuster" in a for a in cmds[0].args)

    def test_pane2_contains_wpscan(self):
        cmds = build_http_commands(ip="10.0.0.1", fqdn="dc.example.com")
        assert any("wpscan" in a for a in cmds[1].args)

    def test_pane2_contains_wpscan_aggressive(self):
        cmds = build_http_commands(ip="10.0.0.1", fqdn="dc.example.com")
        assert any("plugins-detection aggressive" in a for a in cmds[1].args)

    def test_pane3_contains_nuclei(self):
        cmds = build_http_commands(ip="10.0.0.1", fqdn="dc.example.com")
        assert any("nuclei" in a for a in cmds[2].args)

    def test_pane3_nuclei_command_exact(self):
        cmds = build_http_commands(ip="10.0.0.1", fqdn="dc.example.com")
        assert any(
            a == "nuclei -u 10.0.0.1 -severity critical,high,medium -c 10"
            for a in cmds[2].args
        )

    def test_ip_only_target_still_has_three_panes(self):
        cmds = build_http_commands(ip="10.0.0.1", fqdn="10.0.0.1")
        assert len(cmds) == 3

    def test_target_in_all_pane1_args(self):
        cmds = build_http_commands(ip="10.0.0.1", fqdn="dc.example.com")
        # burpsuite guard is index 0, so skip it when checking fqdn presence
        assert all("dc.example.com" in a for a in cmds[0].args[1:])

    def test_pane1_first_arg_is_burpsuite_guard(self):
        cmds = build_http_commands(ip="10.0.0.1", fqdn="dc.example.com")
        assert cmds[0].args[0] == (
            'pgrep -fi "burpsuite" > /dev/null 2>&1'
            ' || { BurpSuitePro &>/dev/null & } 2>/dev/null'
            ' || { BurpSuiteCommunity &>/dev/null & } 2>/dev/null'
            ' || { burpsuite &>/dev/null & } 2>/dev/null'
        )

    def test_pane1_burpsuite_guard_before_firefox(self):
        cmds = build_http_commands(ip="10.0.0.1", fqdn="dc.example.com")
        args = cmds[0].args
        idx_guard = next(i for i, a in enumerate(args) if "burpsuite" in a and "pgrep" in a)
        idx_firefox = next(i for i, a in enumerate(args) if "firefox" in a)
        assert idx_guard == 0
        assert idx_guard < idx_firefox


# ===========================================================================
# build_kerberos_commands
# ===========================================================================


class TestBuildKerberosCommands:
    def test_no_domain_returns_empty(self):
        assert build_kerberos_commands(ip="10.0.0.1", domain="") == []

    def test_domain_only_returns_one_command(self):
        cmds = build_kerberos_commands(ip="10.0.0.1", domain="dom.local")
        assert len(cmds) == 1

    def test_kerbrute_present(self):
        cmds = build_kerberos_commands(ip="10.0.0.1", domain="dom.local")
        assert any("kerbrute" in a for a in cmds[0].args)

    def test_kerbrute_delay_is_20(self):
        cmds = build_kerberos_commands(ip="10.0.0.1", domain="dom.local")
        kerbrute_cmd = next(c for c in cmds if any("kerbrute" in a for a in c.args))
        assert kerbrute_cmd.delay == 20

    def test_with_cred_returns_two_commands(self):
        cmds = build_kerberos_commands(
            ip="10.0.0.1", domain="dom.local", cred=("user", "pass")
        )
        assert len(cmds) == 2

    def test_tgt_command_has_faketime(self):
        cmds = build_kerberos_commands(
            ip="10.0.0.1", domain="dom.local", cred=("user", "pass")
        )
        tgt_cmd = cmds[0]
        assert any("faketime" in a for a in tgt_cmd.args)
        assert any("getTGT.py" in a for a in tgt_cmd.args)

    def test_tgt_contains_domain_and_cred(self):
        cmds = build_kerberos_commands(
            ip="10.0.0.1", domain="dom.local", cred=("myuser", "mypass")
        )
        assert any("dom.local" in a and "myuser" in a for a in cmds[0].args)

    def test_second_command_is_kerbrute(self):
        cmds = build_kerberos_commands(
            ip="10.0.0.1", domain="dom.local", cred=("user", "pass")
        )
        assert any("kerbrute" in a for a in cmds[1].args)


# ===========================================================================
# build_rpc_commands
# ===========================================================================


class TestBuildRpcCommands:
    def test_returns_one_command(self):
        cmds = build_rpc_commands(ip="10.0.0.1")
        assert len(cmds) == 1

    def test_authenticated_rpcclient_present(self):
        cmds = build_rpc_commands(ip="10.0.0.1")
        assert any("rpcclient" in a and "10.0.0.1" in a for a in cmds[0].args)

    def test_null_session_rpcclient_present(self):
        cmds = build_rpc_commands(ip="10.0.0.1")
        assert any("-U ''" in a for a in cmds[0].args)

    def test_querydominfo_in_both(self):
        cmds = build_rpc_commands(ip="10.0.0.1")
        assert all("querydominfo" in a for a in cmds[0].args)


# ===========================================================================
# build_ldap_commands
# ===========================================================================


class TestBuildLdapCommands:
    def test_no_creds_no_anon_returns_empty(self):
        cmds = build_ldap_commands(
            ip="10.0.0.1", domain="dom.local", dc_fqdn="dc.dom.local"
        )
        assert cmds == []

    def test_authenticated_returns_three_panes(self):
        cmds = build_ldap_commands(
            ip="10.0.0.1",
            domain="dom.local",
            dc_fqdn="dc.dom.local",
            cred=("user", "pass"),
        )
        assert len(cmds) == 3

    def test_pane1_has_bloodyad(self):
        cmds = build_ldap_commands(
            ip="10.0.0.1", domain="dom.local", dc_fqdn="dc.dom.local", cred=("u", "p")
        )
        assert any("bloodyAD" in a for a in cmds[0].args)

    def test_pane1_has_nxc_ldap_asreproast(self):
        cmds = build_ldap_commands(
            ip="10.0.0.1", domain="dom.local", dc_fqdn="dc.dom.local", cred=("u", "p")
        )
        assert any("nxc ldap" in a and "--asreproast" in a for a in cmds[0].args)

    def test_pane1_nxc_ldap_modules_include_new_modules(self):
        cmds = build_ldap_commands(
            ip="10.0.0.1", domain="dom.local", dc_fqdn="dc.dom.local", cred=("u", "p")
        )
        module_arg = next(
            a for a in cmds[0].args if "nxc ldap" in a and "-M maq" in a
        )
        for module in [
            "-M badsuccessor",
            "-M dns-nonsecure",
            "-M dump-computers",
            "-M get-network",
            "-M obsolete",
        ]:
            assert module in module_arg

    def test_pane1_has_hashcat(self):
        cmds = build_ldap_commands(
            ip="10.0.0.1", domain="dom.local", dc_fqdn="dc.dom.local", cred=("u", "p")
        )
        assert any("hashcat" in a and "18200" in a for a in cmds[0].args)
        assert any("hashcat" in a and "13100" in a for a in cmds[0].args)
        assert any("hashcat" in a and "19700" in a for a in cmds[0].args)

    def test_pane1_hashcat_19700_after_13100(self):
        cmds = build_ldap_commands(
            ip="10.0.0.1", domain="dom.local", dc_fqdn="dc.dom.local", cred=("u", "p")
        )
        args = cmds[0].args
        idx_13100 = next(i for i, a in enumerate(args) if "hashcat" in a and "13100" in a)
        idx_19700 = next(i for i, a in enumerate(args) if "hashcat" in a and "19700" in a)
        assert idx_19700 == idx_13100 + 1

    def test_pane3_has_bloodhound(self):
        cmds = build_ldap_commands(
            ip="10.0.0.1", domain="dom.local", dc_fqdn="dc.dom.local", cred=("u", "p")
        )
        assert any("bloodhound-ce-python" in a for a in cmds[2].args)

    def test_pane3_bloodhound_after_cli_up(self):
        cmds = build_ldap_commands(
            ip="10.0.0.1", domain="dom.local", dc_fqdn="dc.dom.local", cred=("u", "p")
        )
        args = cmds[2].args
        idx_cli_up = next(i for i, a in enumerate(args) if a == "bloodhound-cli up")
        idx_echo = next(i for i, a in enumerate(args) if a == "echo")
        idx_bloodhound = next(i for i, a in enumerate(args) if "bloodhound-ce-python" in a)
        # bloodhound-cli up (0) → sleep 1 (1) → echo (2) → bloodhound-ce-python (3)
        assert idx_cli_up == 0
        assert idx_echo == 2
        assert idx_bloodhound == 3
        assert idx_bloodhound > idx_cli_up

    def test_pane1_faketime_on_bloodyad(self):
        cmds = build_ldap_commands(
            ip="10.0.0.1", domain="dom.local", dc_fqdn="dc.dom.local", cred=("u", "p")
        )
        assert any("faketime" in a and "bloodyAD" in a for a in cmds[0].args)

    def test_pane2_has_certipy(self):
        cmds = build_ldap_commands(
            ip="10.0.0.1", domain="dom.local", dc_fqdn="dc.dom.local", cred=("u", "p")
        )
        assert any("certipy" in a for a in cmds[1].args)

    def test_pane2_has_powerview(self):
        cmds = build_ldap_commands(
            ip="10.0.0.1", domain="dom.local", dc_fqdn="dc.dom.local", cred=("u", "p")
        )
        assert any("powerview" in a for a in cmds[1].args)

    def test_pane3_has_bloodhound_up(self):
        cmds = build_ldap_commands(
            ip="10.0.0.1", domain="dom.local", dc_fqdn="dc.dom.local", cred=("u", "p")
        )
        assert any("bloodhound-cli" in a for a in cmds[2].args)

    def test_anon_bind_returns_two_panes(self):
        cmds = build_ldap_commands(
            ip="10.0.0.1",
            domain="dom.local",
            dc_fqdn="dc.dom.local",
            anon_bind=True,
        )
        assert len(cmds) == 2

    def test_anon_pane1_has_nxc_ldap(self):
        cmds = build_ldap_commands(
            ip="10.0.0.1", domain="dom.local", dc_fqdn="dc.dom.local", anon_bind=True
        )
        assert any("nxc ldap" in a for a in cmds[0].args)

    def test_anon_pane1_has_hashcat(self):
        cmds = build_ldap_commands(
            ip="10.0.0.1", domain="dom.local", dc_fqdn="dc.dom.local", anon_bind=True
        )
        assert any("hashcat" in a and "13100" in a for a in cmds[0].args)
        assert any("hashcat" in a and "19700" in a for a in cmds[0].args)

    def test_anon_pane1_hashcat_19700_after_13100(self):
        cmds = build_ldap_commands(
            ip="10.0.0.1", domain="dom.local", dc_fqdn="dc.dom.local", anon_bind=True
        )
        args = cmds[0].args
        idx_13100 = next(i for i, a in enumerate(args) if "hashcat" in a and "13100" in a)
        idx_19700 = next(i for i, a in enumerate(args) if "hashcat" in a and "19700" in a)
        assert idx_19700 == idx_13100 + 1

    def test_anon_pane2_has_powerview(self):
        cmds = build_ldap_commands(
            ip="10.0.0.1", domain="dom.local", dc_fqdn="dc.dom.local", anon_bind=True
        )
        assert any("powerview" in a for a in cmds[1].args)

    def test_cred_takes_precedence_over_anon_bind(self):
        # When both cred and anon_bind are provided, cred path wins (3 panes).
        cmds = build_ldap_commands(
            ip="10.0.0.1",
            domain="dom.local",
            dc_fqdn="dc.dom.local",
            cred=("u", "p"),
            anon_bind=True,
        )
        assert len(cmds) == 3


# ===========================================================================
# build_https_commands
# ===========================================================================


class TestBuildHttpsCommands:
    def test_returns_one_command(self):
        cmds = build_https_commands(fqdn="dc.dom.local")
        assert len(cmds) == 1

    def test_firefox_present(self):
        cmds = build_https_commands(fqdn="dc.dom.local")
        assert any("firefox" in a and "https" in a for a in cmds[0].args)

    def test_curl_present(self):
        cmds = build_https_commands(fqdn="dc.dom.local")
        assert any("curl" in a and "https" in a for a in cmds[0].args)

    def test_fqdn_in_all_args(self):
        cmds = build_https_commands(fqdn="dc.dom.local")
        # burpsuite guard is index 0 and does not contain fqdn; skip it
        assert all("dc.dom.local" in a for a in cmds[0].args[1:])

    def test_ip_fallback_fqdn(self):
        cmds = build_https_commands(fqdn="10.0.0.1")
        assert any("10.0.0.1" in a for a in cmds[0].args)

    def test_first_arg_is_burpsuite_guard(self):
        cmds = build_https_commands(fqdn="dc.dom.local")
        assert cmds[0].args[0] == (
            'pgrep -fi "burpsuite" > /dev/null 2>&1'
            ' || { BurpSuitePro &>/dev/null & } 2>/dev/null'
            ' || { BurpSuiteCommunity &>/dev/null & } 2>/dev/null'
            ' || { burpsuite &>/dev/null & } 2>/dev/null'
        )

    def test_burpsuite_guard_before_firefox(self):
        cmds = build_https_commands(fqdn="dc.dom.local")
        args = cmds[0].args
        idx_guard = next(i for i, a in enumerate(args) if "burpsuite" in a and "pgrep" in a)
        idx_firefox = next(i for i, a in enumerate(args) if "firefox" in a)
        assert idx_guard == 0
        assert idx_guard < idx_firefox


# ===========================================================================
# build_smb_commands
# ===========================================================================


class TestBuildSmbCommands:
    # --- unauthenticated ---

    def test_unauth_no_shares_returns_two_panes(self):
        cmds = build_smb_commands(
            ip="10.0.0.1", dc_fqdn="dc.dom.local", domain="dom.local"
        )
        assert len(cmds) == 2

    def test_unauth_pane1_is_aliasr(self):
        cmds = build_smb_commands(
            ip="10.0.0.1", dc_fqdn="dc.dom.local", domain="dom.local"
        )
        assert any("aliasr" in a for a in cmds[0].args)
        # no credentials in aliasr call
        assert not any("-u" in a for a in cmds[0].args)

    def test_unauth_pane1_args0_is_aliasr_clear_all(self):
        cmds = build_smb_commands(
            ip="10.0.0.1", dc_fqdn="dc.dom.local", domain="dom.local"
        )
        assert cmds[0].args[0] == "aliasr clear all"

    def test_unauth_pane1_args2_is_aliasr_scan(self):
        cmds = build_smb_commands(
            ip="10.0.0.1", dc_fqdn="dc.dom.local", domain="dom.local"
        )
        assert cmds[0].args[2].startswith("aliasr scan")

    def test_unauth_pane2_has_rid_brute(self):
        cmds = build_smb_commands(
            ip="10.0.0.1", dc_fqdn="dc.dom.local", domain="dom.local"
        )
        assert any("rid-brute" in a for a in cmds[1].args)

    def test_unauth_pane2_has_null_and_guest(self):
        cmds = build_smb_commands(
            ip="10.0.0.1", dc_fqdn="dc.dom.local", domain="dom.local"
        )
        assert any("-u '' -p ''" in a for a in cmds[1].args)
        assert any("-u 'a' -p ''" in a for a in cmds[1].args)

    def test_unauth_pane2_has_spray(self):
        cmds = build_smb_commands(
            ip="10.0.0.1", dc_fqdn="dc.dom.local", domain="dom.local"
        )
        assert any("users.txt" in a for a in cmds[1].args)

    # --- authenticated ---

    def test_auth_no_shares_returns_three_panes(self):
        cmds = build_smb_commands(
            ip="10.0.0.1",
            dc_fqdn="dc.dom.local",
            domain="dom.local",
            cred=("user", "pass"),
        )
        assert len(cmds) == 3

    def test_auth_pane1_is_aliasr_with_creds(self):
        cmds = build_smb_commands(
            ip="10.0.0.1",
            dc_fqdn="dc.dom.local",
            domain="dom.local",
            cred=("user", "pass"),
        )
        assert any("aliasr" in a and "-u" in a for a in cmds[0].args)

    def test_auth_pane1_args0_is_aliasr_clear_all(self):
        cmds = build_smb_commands(
            ip="10.0.0.1",
            dc_fqdn="dc.dom.local",
            domain="dom.local",
            cred=("user", "pass"),
        )
        assert cmds[0].args[0] == "aliasr clear all"

    def test_auth_pane1_args2_is_aliasr_scan_with_creds(self):
        cmds = build_smb_commands(
            ip="10.0.0.1",
            dc_fqdn="dc.dom.local",
            domain="dom.local",
            cred=("user", "pass"),
        )
        assert cmds[0].args[2].startswith("aliasr scan")
        assert "-u" in cmds[0].args[2]

    def test_auth_pane2_has_module_scan(self):
        cmds = build_smb_commands(
            ip="10.0.0.1",
            dc_fqdn="dc.dom.local",
            domain="dom.local",
            cred=("user", "pass"),
        )
        assert any("--pass-pol" in a for a in cmds[1].args)
        assert any("timeroast" in a for a in cmds[1].args)
        assert any("printnightmare" in a for a in cmds[1].args)
        assert any("ntlm_reflection" in a for a in cmds[1].args)
        assert any("sccm-recon6" in a for a in cmds[1].args)

    def test_auth_pane2_has_exactly_3_args_no_standalone_printnightmare(self):
        cmds = build_smb_commands(
            ip="10.0.0.1",
            dc_fqdn="dc.dom.local",
            domain="dom.local",
            cred=("user", "pass"),
        )
        pane2_args = cmds[1].args
        assert len(pane2_args) == 3
        # printnightmare must be in the consolidated module arg (not its own arg)
        module_arg = next(a for a in pane2_args if "printnightmare" in a)
        assert "ntlm_reflection" in module_arg  # consolidated together

    def test_auth_pane2_has_faketime(self):
        cmds = build_smb_commands(
            ip="10.0.0.1",
            dc_fqdn="dc.dom.local",
            domain="dom.local",
            cred=("user", "pass"),
        )
        assert any("faketime" in a for a in cmds[1].args)

    def test_auth_pane3_has_rid_brute(self):
        cmds = build_smb_commands(
            ip="10.0.0.1",
            dc_fqdn="dc.dom.local",
            domain="dom.local",
            cred=("user", "pass"),
        )
        assert any("rid-brute" in a for a in cmds[2].args)

    # --- shares: non-default share spider ---

    def test_auth_with_one_non_default_share_adds_spider_and_spider_plus(self):
        shares = [
            {"name": "ADMIN$", "access": ["READ"], "remark": ""},
            {"name": "Backup", "access": ["READ", "WRITE"], "remark": "custom"},
        ]
        cmds = build_smb_commands(
            ip="10.0.0.1",
            dc_fqdn="dc.dom.local",
            domain="dom.local",
            cred=("user", "pass"),
            shares=shares,
            share_method="user/pass",
        )
        # 3 base + 1 spider per non-default + 1 spider_plus
        assert len(cmds) == 5

    def test_auth_spider_arg_contains_share_name(self):
        shares = [{"name": "Reports", "access": ["READ"], "remark": ""}]
        cmds = build_smb_commands(
            ip="10.0.0.1",
            dc_fqdn="dc.dom.local",
            domain="dom.local",
            cred=("user", "pass"),
            shares=shares,
            share_method="user/pass",
        )
        spider_cmd = cmds[3]
        assert any("Reports" in a for a in spider_cmd.args)
        assert any("spider" in a for a in spider_cmd.args)

    def test_default_shares_filtered_out(self):
        default_shares = [
            {"name": n, "access": ["READ"], "remark": ""}
            for n in ["ADMIN$", "C$", "Users", "IPC$", "NETLOGON", "SYSVOL"]
        ]
        cmds = build_smb_commands(
            ip="10.0.0.1",
            dc_fqdn="dc.dom.local",
            domain="dom.local",
            cred=("user", "pass"),
            shares=default_shares,
            share_method="user/pass",
        )
        # 3 base + 0 spider + 1 spider_plus (shares list present, method set)
        assert len(cmds) == 4

    def test_null_spider_uses_empty_creds(self):
        shares = [{"name": "Data", "access": ["READ"], "remark": ""}]
        cmds = build_smb_commands(
            ip="10.0.0.1",
            dc_fqdn="10.0.0.1",
            domain="",
            shares=shares,
            share_method="null",
        )
        spider_cmd = cmds[2]
        assert any("-u '' -p ''" in a for a in spider_cmd.args)
        assert any("Data" in a for a in spider_cmd.args)

    def test_guest_spider_uses_guest_creds(self):
        shares = [{"name": "Public", "access": ["READ"], "remark": ""}]
        cmds = build_smb_commands(
            ip="10.0.0.1",
            dc_fqdn="10.0.0.1",
            domain="",
            shares=shares,
            share_method="guest",
        )
        spider_cmd = cmds[2]
        assert any("-u 'a' -p ''" in a for a in spider_cmd.args)

    def test_null_spider_plus_uses_empty_creds(self):
        shares = [{"name": "Shared", "access": ["READ"], "remark": ""}]
        cmds = build_smb_commands(
            ip="10.0.0.1",
            dc_fqdn="10.0.0.1",
            domain="workgroup",
            shares=shares,
            share_method="null",
        )
        spider_plus = cmds[-1]
        assert any("spider_plus" in a for a in spider_plus.args)
        assert any("-u '' -p ''" in a for a in spider_plus.args)

    def test_no_shares_no_spider_commands(self):
        cmds = build_smb_commands(
            ip="10.0.0.1",
            dc_fqdn="dc.dom.local",
            domain="dom.local",
            cred=("user", "pass"),
            shares=None,
            share_method=None,
        )
        assert len(cmds) == 3


# ===========================================================================
# build_mssql_commands
# ===========================================================================


class TestBuildMssqlCommands:
    def test_returns_three_panes(self):
        cmds = build_mssql_commands(
            ip="10.0.0.1", domain="dom.local", cred=("sa", "password1")
        )
        assert len(cmds) == 3

    def test_pane1_has_nxc_mssql(self):
        cmds = build_mssql_commands(
            ip="10.0.0.1", domain="dom.local", cred=("sa", "password1")
        )
        assert any("nxc mssql" in a for a in cmds[0].args)

    def test_pane1_has_kerberos_local_and_domain_variants(self):
        cmds = build_mssql_commands(
            ip="10.0.0.1", domain="dom.local", cred=("sa", "p")
        )
        assert any("-k" in a for a in cmds[0].args)
        assert any("--local-auth" in a for a in cmds[0].args)
        assert any("-d ." in a for a in cmds[0].args)

    def test_pane1_has_faketime_on_kerberos_variant(self):
        cmds = build_mssql_commands(
            ip="10.0.0.1", domain="dom.local", cred=("sa", "p")
        )
        assert any("faketime" in a and "nxc mssql" in a for a in cmds[0].args)

    def test_pane2_is_mssqlclient(self):
        cmds = build_mssql_commands(
            ip="10.0.0.1", domain="dom.local", cred=("sa", "p")
        )
        assert any("mssqlclient.py" in a for a in cmds[1].args)
        assert not any("-windows-auth" in a for a in cmds[1].args)

    def test_pane3_is_mssqlclient_windows_auth(self):
        cmds = build_mssql_commands(
            ip="10.0.0.1", domain="dom.local", cred=("sa", "p")
        )
        assert any("mssqlclient.py" in a and "-windows-auth" in a for a in cmds[2].args)

    def test_creds_in_mssqlclient_args(self):
        cmds = build_mssql_commands(
            ip="10.0.0.1", domain="dom.local", cred=("sa", "hunter2")
        )
        assert any("sa" in a and "hunter2" in a for a in cmds[1].args)


# ===========================================================================
# build_nfs_commands
# ===========================================================================


class TestBuildNfsCommands:
    def test_returns_one_command(self):
        cmds = build_nfs_commands(ip="10.0.0.1")
        assert len(cmds) == 1

    def test_showmount_present(self):
        cmds = build_nfs_commands(ip="10.0.0.1")
        assert any("showmount" in a for a in cmds[0].args)

    def test_nxc_nfs_present(self):
        cmds = build_nfs_commands(ip="10.0.0.1")
        assert any("nxc nfs" in a for a in cmds[0].args)

    def test_ip_in_all_args(self):
        cmds = build_nfs_commands(ip="10.0.0.1")
        assert all("10.0.0.1" in a for a in cmds[0].args)
