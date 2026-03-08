"""Pure builder functions that return list[Command] for each protocol handler.

All functions take only primitive arguments — no Context dependency — so they
can be tested without tmux, libtmux, or live machines.

Cred convention: cred is a (username, password) tuple or None.
Shares convention: shares is the list[dict] returned by enum_smb_shares, or
None when share enumeration was skipped / failed.
"""

from __future__ import annotations

from recon_setup.utils.commands import Command, faketime_prefix, with_faketime

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
    """
    anon = f"nxc ftp {ip} -u '' -p '' --ls"
    if cred:
        user, password = cred
        auth = f"nxc ftp {ip} -u '{user}' -p '{password}' --ls"
        args = [anon, auth]
    else:
        args = [anon]
    return [Command(args=args, description="FTP enumeration", delay=7)]


# ---------------------------------------------------------------------------
# DNS (port 53)
# ---------------------------------------------------------------------------


def build_dns_commands(ip: str, domain: str) -> list[Command]:
    """Reverse-lookup and zone-transfer enumeration."""
    return [
        Command(
            args=[
                f"dig @{ip} -x {ip} +short",
                f"dig axfr @{ip} {domain}",
            ],
            description="DNS enumeration",
            delay=2,
        )
    ]


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
                (
                    f"{ft}bloodhound-ce-python --zip -c All -d {domain}"
                    f" -dc {dc_fqdn} -ns {ip} -u '{user}' -p '{password}'"
                ),
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
            args=["bloodhound-cli up"],
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
    """
    ft = faketime_prefix(ip)
    cmds: list[Command] = []

    if cred:
        user, password = cred

        # pane 1 — aliasr
        cmds.append(
            Command(
                args=[
                    "aliasr clear all",
                    "echo",
                    f"aliasr scan {ip} -u '{user}' -p '{password}'",
                ],
                description="aliasr SMB scan (auth)",
                delay=2,
            )
        )

        # pane 2 — nxc module scans
        cmds.append(
            Command(
                args=[
                    (
                        f"{ft}nxc smb {ip} -u '{user}' -p '{password}' -k"
                        f" --pass-pol --shares"
                    ),
                    (
                        f"{ft}nxc smb {ip} -u '{user}' -p '{password}' -k"
                        f" -M timeroast"
                    ),
                    (
                        f"{ft}nxc smb {ip} -u '{user}' -p '{password}' -k"
                        f" -M ntlm_reflection -M sccm-recon6 -M printnightmare"
                        f" -M webdav -M spooler -M ioxidresolver"
                        f" -M gpp_autologin -M gpp_password -M ms17-010"
                        f" -M nopac -M remove-mic -M smbghost -M enum_ca"
                        f" -M aws-credentials"
                    ),
                ],
                description="SMB module scan (auth)",
                delay=7,
            )
        )

        # pane 3 — RID brute + user extraction
        cmds.append(
            Command(
                args=[
                    "rm -f $(pwd)/smb.out",
                    (
                        f"{ft}nxc smb {ip} -u '{user}' -p '{password}' -k"
                        f" --shares --users --pass-pol"
                        f" --rid-brute 10000 --log $(pwd)/smb.out"
                    ),
                    "cat smb.out | grep TypeUser | cut -d '\\' -f 2"
                    " | cut -d ' ' -f 1 > users.txt",
                    "echo",
                    "cat users.txt",
                ],
                description="SMB RID brute (auth)",
                delay=7,
            )
        )

    else:
        # pane 1 — aliasr (anon)
        cmds.append(
            Command(
                args=[
                    "aliasr clear all",
                    "echo",
                    f"aliasr scan {ip}",
                ],
                description="aliasr SMB scan (anon)",
                delay=2,
            )
        )

        # pane 2 — null + guest RID brute + spray
        cmds.append(
            Command(
                args=[
                    "rm -f $(pwd)/smb.out",
                    (
                        f"nxc smb {ip} -u '' -p '' --shares --users --pass-pol"
                        f" --rid-brute 10000 --log $(pwd)/smb.out"
                    ),
                    (
                        f"nxc smb {ip} -u 'a' -p ''"
                        f" --rid-brute 10000 --log $(pwd)/smb.out"
                    ),
                    "cat smb.out | grep TypeUser | cut -d '\\' -f 2"
                    " | cut -d ' ' -f 1 > users.txt",
                    "echo",
                    "cat users.txt",
                    "echo",
                    (
                        f"{ft}nxc smb {ip} -u users.txt -p users.txt -k"
                        f" --no-bruteforce --continue-on-success"
                    ),
                    f"nxc smb {ip} -u users.txt -p '' --continue-on-success",
                ],
                description="SMB RID brute (anon)",
                delay=7,
            )
        )

    # per-share spider (only when shares were enumerated)
    if shares and share_method:
        non_default = [s for s in shares if s["name"] not in _NON_DEFAULT_SHARES]

        for share in non_default:
            name = share["name"]
            if share_method == "user/pass" and cred:
                user, password = cred
                cmds.append(
                    Command(
                        args=[
                            f"{ft}nxc smb {ip} -u '{user}' -p '{password}' -k"
                            f" --spider '{name}' --regex . --depth 2"
                        ],
                        description=f"SMB spider: {name} (auth)",
                        delay=7,
                    )
                )
            elif share_method == "null":
                cmds.append(
                    Command(
                        args=[
                            f"nxc smb {ip} -u '' -p ''"
                            f" --spider '{name}' --regex . --depth 2"
                        ],
                        description=f"SMB spider: {name} (null)",
                        delay=7,
                    )
                )
            elif share_method == "guest":
                cmds.append(
                    Command(
                        args=[
                            f"nxc smb {ip} -u 'a' -p ''"
                            f" --spider '{name}' --regex . --depth 2"
                        ],
                        description=f"SMB spider: {name} (guest)",
                        delay=7,
                    )
                )

        # spider_plus + smbclientng
        _exclude = (
            "DOWNLOAD_FLAG=True"
            " EXCLUDE_EXTS=ico,lnk,svg,js,css,scss,map,png,jpg,html,npmignore"
            " EXCLUDE_FILTER=ADMIN$,C$,Users,IPC$,NETLOGON,SYSVOL,bootstrap,lang"
            " OUTPUT_FOLDER=."
        )
        if share_method == "user/pass" and cred:
            user, password = cred
            cmds.append(
                Command(
                    args=[
                        (
                            f"{ft}nxc smb {ip} -u '{user}' -p '{password}' -k"
                            f" -M spider_plus -o {_exclude}"
                        ),
                        f"cat {ip}.json | jq '. | map_values(keys)'",
                        "echo",
                        (
                            f"{ft}smbclientng --host {dc_fqdn} -d {domain}"
                            f" -u '{user}' -p '{password}' -k -S <(echo 'shares')"
                        ),
                    ],
                    description="SMB spider_plus (auth)",
                    delay=7,
                )
            )
        elif share_method == "null":
            cmds.append(
                Command(
                    args=[
                        (
                            f"nxc smb {ip} -u '' -p ''"
                            f" -M spider_plus -o {_exclude}"
                        ),
                        f"cat {ip}.json | jq '. | map_values(keys)'",
                        "echo",
                        (
                            f"smbclientng --host {ip} -d {domain}"
                            f" -u '' -p '' -S <(echo 'shares')"
                        ),
                    ],
                    description="SMB spider_plus (null)",
                    delay=7,
                )
            )
        elif share_method == "guest":
            cmds.append(
                Command(
                    args=[
                        (
                            f"nxc smb {ip} -u 'a' -p ''"
                            f" -M spider_plus -o {_exclude}"
                        ),
                        f"cat {ip}.json | jq '. | map_values(keys)'",
                        "echo",
                        (
                            f"smbclientng --host {ip} -d {domain}"
                            f" -u a -p '' -S <(echo 'shares')"
                        ),
                    ],
                    description="SMB spider_plus (guest)",
                    delay=7,
                )
            )

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
