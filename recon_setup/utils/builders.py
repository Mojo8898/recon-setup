"""Pure builder functions that return list[Command] for each protocol handler.

All functions take only primitive arguments — no Context dependency — so they
can be tested without tmux, libtmux, or live machines.

Cred convention: cred is a (username, password) tuple or None.
Shares convention: shares is the list[dict] returned by enum_smb_shares, or
None when share enumeration was skipped / failed.
"""

from __future__ import annotations

from recon_setup.utils.commands import Command, faketime_prefix, with_faketime
from recon_setup.utils.task_spec import load_spec, render_panes

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
    return render_panes(load_spec()["ftp"]["panes"], params, has_cred=bool(cred))


# ---------------------------------------------------------------------------
# DNS (port 53)
# ---------------------------------------------------------------------------


def build_dns_commands(ip: str, domain: str) -> list[Command]:
    """Reverse-lookup and zone-transfer enumeration (see tasks.yaml ``dns``)."""
    return render_panes(load_spec()["dns"]["panes"], {"ip": ip, "domain": domain})


# ---------------------------------------------------------------------------
# HTTP (port 80)
# ---------------------------------------------------------------------------


def build_http_commands(ip: str, fqdn: str) -> list[Command]:
    """HTTP enumeration: vhost fuzzing, content discovery, WordPress scan.

    *fqdn* is the resolved target string from context.get_target() — may be
    ``hostname.domain``, ``domain``, or ``ip`` when no hostname/domain is
    known.  Vhost fuzzing headers use *fqdn* in all cases (preserving the
    original handler behaviour).
    """
    pane1 = Command(
        args=[
            (
                'pgrep -fi "burpsuite" > /dev/null 2>&1'
                ' || { BurpSuitePro &>/dev/null & } 2>/dev/null'
                ' || { BurpSuiteCommunity &>/dev/null & } 2>/dev/null'
                ' || { burpsuite &>/dev/null & } 2>/dev/null'
            ),
            f"firefox 'http://{fqdn}' &> /dev/null & disown",
            (
                f"ffuf -w /usr/share/seclists/Discovery/DNS/services-names.txt"
                f" -u http://{fqdn} -H 'Host: FUZZ.{fqdn}' -ac -c"
            ),
            (
                f"ffuf -w /usr/share/seclists/Discovery/DNS/"
                f"subdomains-top1million-5000.txt"
                f" -u http://{fqdn} -H 'Host: FUZZ.{fqdn}' -ac -c"
            ),
            (
                f"ffuf -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt"
                f" -u http://{fqdn}/FUZZ -ac -c"
            ),
            (
                f"ffuf -w /usr/share/seclists/Discovery/Web-Content/"
                f"raft-small-words.txt"
                f" -u http://{fqdn}/FUZZ -ac -c"
            ),
            f"feroxbuster -u http://{fqdn}",
        ],
        description="HTTP enumeration",
        delay=2,
    )
    pane2 = Command(
        args=[
            (
                f"wpscan --no-update --url http://{fqdn}"
                f" --detection-mode aggressive -e ap,u"
            ),
            (
                f"wpscan --no-update --url http://{fqdn}"
                f" --detection-mode aggressive -e ap,u"
                f" --plugins-detection aggressive -o wpscan_long.out"
            ),
        ],
        description="WordPress scan",
        delay=2,
    )
    pane3 = Command(
        args=[
            f"sleep 30",
            f"nuclei -u {ip} -severity critical,high,medium -c 10",
        ],
        description="Nuclei scan",
        delay=2,
    )
    return [pane1, pane2, pane3]


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

    cmds: list[Command] = []

    if cred:
        user, password = cred
        tgt = Command(
            args=[f"getTGT.py {domain}/'{user}':'{password}'"],
            description="Get TGT",
            delay=2,
        )
        cmds.append(with_faketime(ip, tgt))

    cmds.append(
        Command(
            args=[
                f"kerbrute userenum -d {domain} --dc {ip}"
                f" /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt"
            ],
            description="Kerbrute user enumeration",
            delay=20,
        )
    )
    return cmds


# ---------------------------------------------------------------------------
# RPC (port 135)
# ---------------------------------------------------------------------------


def build_rpc_commands(ip: str) -> list[Command]:
    """RPC domain info queries — authenticated and null-session."""
    return [
        Command(
            args=[
                f"echo querydominfo | rpcclient {ip}",
                f"echo querydominfo | rpcclient -U '' -N {ip}",
            ],
            description="RPC query",
            delay=2,
        )
    ]


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
    """
    ft = faketime_prefix(ip)

    if cred:
        user, password = cred

        pane1 = Command(
            args=[
                f"{ft}bloodyAD --host {dc_fqdn} -d {domain}"
                f" -u '{user}' -p '{password}' -k get writable",
                "echo",
                "rm -f $(pwd)/hashes.kerberoast",
                (
                    f"{ft}nxc ldap {ip} -u '{user}' -p '{password}' -k"
                    f" --pass-pol --pso"
                    f" --asreproast hashes.asreproast"
                    f" --kerberoasting hashes.kerberoast"
                    f" --find-delegation --trusted-for-delegation"
                    f" --password-not-required --users --groups --dc-list --gmsa"
                ),
                (
                    f"{ft}nxc ldap {ip} -u '{user}' -p '{password}' -k"
                    f" -M maq -M sccm -M laps -M adcs -M pre2k"
                    f" -M badsuccessor -M dns-nonsecure -M dump-computers"
                    f" -M get-network -M obsolete"
                ),
                "echo",
                (
                    "hashcat -m 18200 hashes.asreproast"
                    " /usr/share/wordlists/rockyou.txt --force --quiet"
                ),
                (
                    "hashcat -m 13100 hashes.kerberoast"
                    " /usr/share/wordlists/rockyou.txt --force --quiet"
                ),
                (
                    "hashcat -m 19700 hashes.kerberoast"
                    " /usr/share/wordlists/rockyou.txt --force --quiet"
                ),
            ],
            description="LDAP AD enumeration (auth)",
            delay=7,
        )

        pane2 = Command(
            args=[
                "rm -f $(pwd)/initial_enabled_Certipy.json",
                (
                    f"{ft}certipy find -u '{user}'@{domain} -p '{password}' -k"
                    f" -target {dc_fqdn} -dc-ip {ip}"
                    f" -stdout -json -output initial_enabled -timeout 2 -enabled"
                ),
                r"echo -e '\n<--- Find Vulnerable: --->\n'",
                (
                    f"{ft}certipy find -u '{user}'@{domain} -p '{password}' -k"
                    f" -target {dc_fqdn} -dc-ip {ip}"
                    f" -stdout -timeout 2 -vulnerable"
                ),
                "echo",
                "parse_certipy.py initial_enabled_Certipy.json",
                "echo",
                (
                    f"{ft}powerview {domain}/'{user}':'{password}'"
                    f"@{dc_fqdn} -k --web --no-cache"
                ),
            ],
            description="Certificate enumeration (auth)",
            delay=7,
        )

        pane3 = Command(
            args=[
                "bloodhound-cli up",
                "sleep 1",
                "echo",
                (
                    f"{ft}bloodhound-ce-python --zip -c All -d {domain}"
                    f" -dc {dc_fqdn} -ns {ip} -u '{user}' -p '{password}' -op ia"
                    f" && bloodhound-ce-ctl -u http://127.0.0.1:8081"
                    f" -c -p -z $(ls -t ia_*_bloodhound.zip | head -n1)"
                ),
            ],
            description="Start BloodHound",
            delay=2,
        )

        return [pane1, pane2, pane3]

    if anon_bind:
        pane1 = Command(
            args=[
                "rm -f $(pwd)/hashes.kerberoast",
                (
                    f"nxc ldap {dc_fqdn} -u '' -p ''"
                    f" --asreproast hashes.asreproast"
                    f" --kerberoasting hashes.kerberoast"
                    f" --find-delegation --trusted-for-delegation"
                    f" --password-not-required --users --groups --dc-list --gmsa"
                ),
                "echo",
                (
                    "hashcat -m 18200 hashes.asreproast"
                    " /usr/share/wordlists/rockyou.txt --force --quiet"
                ),
                (
                    "hashcat -m 13100 hashes.kerberoast"
                    " /usr/share/wordlists/rockyou.txt --force --quiet"
                ),
                (
                    "hashcat -m 19700 hashes.kerberoast"
                    " /usr/share/wordlists/rockyou.txt --force --quiet"
                ),
            ],
            description="LDAP anonymous enumeration",
            delay=7,
        )
        pane2 = Command(
            args=[f"powerview {dc_fqdn} --no-cache"],
            description="PowerView anonymous",
            delay=2,
        )
        return [pane1, pane2]

    return []


# ---------------------------------------------------------------------------
# HTTPS (port 443)
# ---------------------------------------------------------------------------


def build_https_commands(fqdn: str) -> list[Command]:
    """Open browser and inspect HTTPS certificate/headers."""
    return [
        Command(
            args=[
                (
                    'pgrep -fi "burpsuite" > /dev/null 2>&1'
                    ' || { BurpSuitePro &>/dev/null & } 2>/dev/null'
                    ' || { BurpSuiteCommunity &>/dev/null & } 2>/dev/null'
                    ' || { burpsuite &>/dev/null & } 2>/dev/null'
                ),
                f"firefox 'https://{fqdn}' &> /dev/null & disown",
                f"curl -Ik https://{fqdn}",
            ],
            description="HTTPS inspection",
            delay=2,
        )
    ]


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
    spec = load_spec()["smb"]
    params: dict = {"ip": ip, "dc_fqdn": dc_fqdn, "domain": domain, "ft": faketime_prefix(ip)}
    if cred:
        params["user"], params["password"] = cred

    # Base panes: credentialled path differs from the null/guest sweep.
    variant = "auth" if cred else "anon"
    cmds = render_panes(spec["base"][variant], params)

    # Per-share spider + one-shot spider_plus (only when shares were enumerated).
    if shares and share_method:
        # user/pass templates require a cred; the other methods never do.
        usable = share_method != "user/pass" or bool(cred)
        if usable:
            spider_tpl = spec["spider"].get(share_method)
            for share in shares:
                if share["name"] in _NON_DEFAULT_SHARES:
                    continue
                if spider_tpl:
                    cmds += render_panes([spider_tpl], {**params, "share": share["name"]})

            spider_plus_tpl = spec["spider_plus"].get(share_method)
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

    Requires credentials; returns three pane Commands.
    """
    ft = faketime_prefix(ip)
    user, password = cred

    pane1 = Command(
        args=[
            (
                f"{ft}nxc mssql {ip} -u '{user}' -p '{password}' -k"
                f" -M enum_impersonate -M enum_links -M enum_logins"
            ),
            (
                f"nxc mssql {ip} -u '{user}' -p '{password}' --local-auth"
                f" -M enum_impersonate -M enum_links -M enum_logins"
            ),
            (
                f"nxc mssql {ip} -u '{user}' -p '{password}' -d ."
                f" -M enum_impersonate -M enum_links -M enum_logins"
            ),
        ],
        description="MSSQL enumeration",
        delay=7,
    )
    pane2 = Command(
        args=[f"mssqlclient.py {domain}/'{user}':'{password}'@{ip}"],
        description="mssqlclient",
        delay=2,
    )
    pane3 = Command(
        args=[f"mssqlclient.py {domain}/'{user}':'{password}'@{ip} -windows-auth"],
        description="mssqlclient (Windows auth)",
        delay=2,
    )
    return [pane1, pane2, pane3]


# ---------------------------------------------------------------------------
# NFS (port 2049)
# ---------------------------------------------------------------------------


def build_nfs_commands(ip: str) -> list[Command]:
    """NFS share enumeration."""
    return [
        Command(
            args=[
                f"showmount -e {ip}",
                f"nxc nfs {ip} --enum-shares",
            ],
            description="NFS enumeration",
            delay=2,
        )
    ]
