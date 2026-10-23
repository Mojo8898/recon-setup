import re
import subprocess

from recon_setup.utils.logger import write_log
from recon_setup.utils.commands import faketime_prefix

_NEGATIVE = re.compile(r"\[\-\]")

# The LDAP anonymous bind can take >10s against a DC over VPN (measured ~14s on
# a live box), so the old 8s cap timed out and reported no bind.  SMB auth is
# fast, so it keeps a tighter cap: enum_smb_shares runs up to four probes
# back-to-back (NTLM + Kerberos fallback + null + guest) synchronously in the
# 445 handler, so an oversized cap there triples worst-case blocking.
_LDAP_TIMEOUT = 20
_SMB_TIMEOUT = 10


def anonymous_bind(context):
    cmd = ["nxc", "ldap", context.ip, "-u", "", "-p", ""]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=_LDAP_TIMEOUT, check=False)
    except Exception as e:
        write_log(context.log_file, f"NetExec ldap subprocess error: {e}", "ERROR")
        return False
    out = p.stdout or ""
    # A "[-]" marks either a failed bind or an anonymous bind whose *search* is
    # denied ("successful bind must be completed") — in both cases anonymous
    # enumeration is not useful, so treat either as no anonymous bind.
    return not _NEGATIVE.search(out)


def enum_smb_shares(context):
    def run_nxc(user, password, kerberos=False):
        # NTLM by default; Kerberos (-k) only on request, wrapped in faketime so
        # DC clock skew (KRB_AP_ERR_SKEW) doesn't sink the probe the way it did
        # before — the actual task commands already use this same faketime trick.
        prefix = faketime_prefix(context.ip) if kerberos else ""
        cmd = f"{prefix}nxc smb {context.ip} -u {user} "
        if password:
            cmd += f"-p '{password}' "
            if kerberos:
                cmd += "-k "
        else:
            cmd += "-p '' "
        cmd += "--shares"
        # write_log(context.log_file, f"Running: {cmd}", "INFO")
        try:
            p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=_SMB_TIMEOUT, check=False)
            return p.stdout or ""
        except Exception as e:
            write_log(context.log_file, f"Subprocess exception: {e}", "ERROR")
            return ""

    def parse_shares(raw):
        lines = [ln.rstrip("\n") for ln in raw.splitlines()]
        hdr_idx = None
        for i, ln in enumerate(lines):
            if "Share" in ln and "Permissions" in ln and "Remark" in ln:
                hdr_idx = i
                break
        if hdr_idx is None or hdr_idx + 2 >= len(lines):
            return []

        header = lines[hdr_idx]
        try:
            c_share = header.index("Share")
            c_perm = header.index("Permissions")
            c_remark = header.index("Remark")
        except ValueError:
            return []

        shares = []
        for ln in lines[hdr_idx + 2 :]:
            if "SMB" not in ln or not ln.strip() or ln.strip().startswith("-----"):
                continue
            pad = ln + " " * max(0, c_remark + 1 - len(ln))
            name = pad[c_share:c_perm].strip()
            perms = pad[c_perm:c_remark].strip()
            remark = pad[c_remark:].strip()
            if not name or name.startswith("-----"):
                continue
            access = [p.strip() for p in perms.split(",") if p.strip()] if perms else []
            shares.append({"name": name, "remark": remark, "access": access})

        return shares

    # 1) user/pass — NTLM first (robust to clock skew, matches a plain
    #    `nxc smb -u x -p y`), then fall back to Kerberos+faketime for
    #    NTLM-disabled DCs.  Either way the method is "user/pass"; the task
    #    commands for that method already use -k + faketime.
    if context.creds_exist():
        user, password = context.get_initial_cred()
        if user is not None:
            shares = parse_shares(run_nxc(user, password))
            if not shares:
                shares = parse_shares(run_nxc(user, password, kerberos=True))
            if shares:
                return shares, "user/pass"
            write_log(context.log_file, "Share enum with provided credentials failed; trying null session", "INFO")

    # 2) null
    out = run_nxc("''", "")
    shares = parse_shares(out)
    if shares:
        write_log(context.log_file, "Null authentication is enabled for reading shares", "SUCCESS")
        return shares, "null"

    # 3) guest
    out = run_nxc("a", "")
    shares = parse_shares(out)
    if shares:
        write_log(context.log_file, "Guest authentication is enabled for reading shares", "SUCCESS")
        return shares, "guest"

    return None, None
