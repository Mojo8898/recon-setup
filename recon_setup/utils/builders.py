"""Pure builder functions that return list[Command] for each protocol handler.

All functions take only primitive arguments — no Context dependency — so they
can be tested without tmux, libtmux, or live machines.

Cred convention: cred is a (username, password) tuple or None.
Shares convention: shares is the list[dict] returned by enum_smb_shares, or
None when share enumeration was skipped / failed.
"""

from __future__ import annotations

from recon_setup.utils.commands import Command, faketime_prefix
from recon_setup.utils.task_spec import render_panes, spec_get

# Shares that are always present on Windows and uninteresting to spider.
_NON_DEFAULT_SHARES: frozenset[str] = frozenset(
    {"ADMIN$", "C$", "Users", "IPC$", "NETLOGON", "SYSVOL"}
)


# ---------------------------------------------------------------------------
# FTP (port 21)
# ---------------------------------------------------------------------------


def build_ftp_commands(
    ip: str,
    cred: tuple[str, str] | None = None,
) -> list[Command]:
    """Build FTP enumeration commands.

    Unauthenticated: anonymous login only.
    Authenticated: anonymous first, then credentialled.

    Command text lives in tasks.yaml (``ftp``); this function only supplies the
    placeholder values and signals whether a cred is present.
    """
    params: dict = {"ip": ip}
    if cred:
        params["user"], params["password"] = cred
    return render_panes(spec_get("ftp", "panes"), params, has_cred=bool(cred))


# ---------------------------------------------------------------------------
# DNS (port 53)
# ---------------------------------------------------------------------------


def build_dns_commands(ip: str, domain: str) -> list[Command]:
    """Reverse-lookup and zone-transfer enumeration (see tasks.yaml ``dns``)."""
    return render_panes(spec_get("dns", "panes"), {"ip": ip, "domain": domain})


# ---------------------------------------------------------------------------
# HTTP (port 80)
# ---------------------------------------------------------------------------


def build_http_commands(ip: str, fqdn: str) -> list[Command]:
    """HTTP enumeration: vhost fuzzing, content discovery, WordPress scan.

    *fqdn* is the resolved target string from context.get_target() — may be
    ``hostname.domain``, ``domain``, or ``ip`` when no hostname/domain is
    known.  Vhost fuzzing headers use *fqdn* in all cases (preserving the
    original handler behaviour).  Command text lives in tasks.yaml (``http``).
    """
    return render_panes(spec_get("http", "panes"), {"ip": ip, "fqdn": fqdn})


# ---------------------------------------------------------------------------
# Kerberos (port 88)
# ---------------------------------------------------------------------------


def build_kerberos_commands(
    ip: str,
    domain: str,
    cred: tuple[str, str] | None = None,
) -> list[Command]:
    """Kerberos enumeration: TGT retrieval (if creds) and user enumeration.

    Returns an empty list when *domain* is falsy (mirrors the original
    ``if context.domain:`` guard in the handler).
    """
    if not domain:
        return []

    params: dict = {"ip": ip, "domain": domain, "ft": faketime_prefix(ip)}

    cmds: list[Command] = []
    if cred:
        params["user"], params["password"] = cred
        cmds += render_panes([spec_get("kerberos", "tgt")], params)
    cmds += render_panes([spec_get("kerberos", "userenum")], params)
    return cmds


# ---------------------------------------------------------------------------
# RPC (port 135)
# ---------------------------------------------------------------------------


def build_rpc_commands(ip: str) -> list[Command]:
    """RPC domain info queries (see tasks.yaml ``rpc``)."""
    return render_panes(spec_get("rpc", "panes"), {"ip": ip})


# ---------------------------------------------------------------------------
# LDAP / Active Directory (port 389)
# ---------------------------------------------------------------------------


def build_ldap_commands(
    ip: str,
    domain: str,
    dc_fqdn: str,
    cred: tuple[str, str] | None = None,
    anon_bind: bool = False,
) -> list[Command]:
    """LDAP / AD enumeration.

    Authenticated path: bloodyAD + nxc ldap + hashcat + BloodHound (pane 1),
    Certipy + PowerView (pane 2), bloodhound-cli up (pane 3).

    Anonymous-bind path: nxc ldap anon + hashcat (pane 1),
    PowerView anon (pane 2).

    Returns an empty list when neither creds nor anon_bind are available.

    Command text lives in tasks.yaml (``ldap``).  This function keeps the
    logic: cred takes precedence over anon_bind, and the faketime prefix is
    supplied as the {{ft}} placeholder.
    """
    params: dict = {
        "ip": ip,
        "domain": domain,
        "dc_fqdn": dc_fqdn,
        "ft": faketime_prefix(ip),
    }

    if cred:
        params["user"], params["password"] = cred
        return render_panes(spec_get("ldap", "variants", "auth"), params)

    if anon_bind:
        return render_panes(spec_get("ldap", "variants", "anon"), params)

    return []


# ---------------------------------------------------------------------------
# HTTPS (port 443)
# ---------------------------------------------------------------------------


def build_https_commands(fqdn: str) -> list[Command]:
    """Open browser and inspect HTTPS cert/headers (see tasks.yaml ``https``)."""
    return render_panes(spec_get("https", "panes"), {"fqdn": fqdn})


# ---------------------------------------------------------------------------
# SMB (port 445)
# ---------------------------------------------------------------------------


def build_smb_commands(
    ip: str,
    dc_fqdn: str,
    domain: str,
    cred: tuple[str, str] | None = None,
    shares: list[dict] | None = None,
    share_method: str | None = None,
) -> list[Command]:
    """SMB enumeration, share spidering, and spider_plus download.

    *shares* and *share_method* come from enum_smb_shares().  Logging of
    found non-default shares is left to the handler (orchestration concern).

    Command text lives in tasks.yaml (``smb``).  This function keeps the
    *logic*: choosing the auth/anon variant, looping once per non-default
    share, and the share_method guards.  It never hardcodes a command.
    """
    params: dict = {"ip": ip, "dc_fqdn": dc_fqdn, "domain": domain, "ft": faketime_prefix(ip)}
    if cred:
        params["user"], params["password"] = cred

    # Base panes: credentialled path differs from the null/guest sweep.
    variant = "auth" if cred else "anon"
    cmds = render_panes(spec_get("smb", "base", variant), params)

    # Per-share spider + one-shot spider_plus (only when shares were enumerated).
    if shares and share_method:
        # user/pass templates require a cred; the other methods never do.
        usable = share_method != "user/pass" or bool(cred)
        if usable:
            spider_tpl = spec_get("smb", "spider").get(share_method)
            for share in shares:
                if share["name"] in _NON_DEFAULT_SHARES:
                    continue
                if spider_tpl:
                    cmds += render_panes([spider_tpl], {**params, "share": share["name"]})

            spider_plus_tpl = spec_get("smb", "spider_plus").get(share_method)
            if spider_plus_tpl:
                cmds += render_panes([spider_plus_tpl], params)

    return cmds


# ---------------------------------------------------------------------------
# MSSQL (port 1433)
# ---------------------------------------------------------------------------


def build_mssql_commands(
    ip: str,
    domain: str,
    cred: tuple[str, str],
) -> list[Command]:
    """MSSQL enumeration and interactive client.

    Requires credentials; returns three pane Commands (see tasks.yaml ``mssql``).
    """
    user, password = cred
    params = {
        "ip": ip,
        "domain": domain,
        "user": user,
        "password": password,
        "ft": faketime_prefix(ip),
    }
    return render_panes(spec_get("mssql", "panes"), params)


# ---------------------------------------------------------------------------
# NFS (port 2049)
# ---------------------------------------------------------------------------


def build_nfs_commands(ip: str) -> list[Command]:
    """NFS share enumeration (see tasks.yaml ``nfs``)."""
    return render_panes(spec_get("nfs", "panes"), {"ip": ip})
