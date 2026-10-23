from time import sleep

import libtmux

from recon_setup.utils.logger import write_log
from recon_setup.utils.active_directory import enum_smb_shares, anonymous_bind
from recon_setup.utils.task_spec import load_spec
from recon_setup.utils.builders import (
    build_ftp_commands,
    build_dns_commands,
    build_http_commands,
    build_kerberos_commands,
    build_rpc_commands,
    build_ldap_commands,
    build_https_commands,
    build_smb_commands,
    build_mssql_commands,
    build_nfs_commands,
    _NON_DEFAULT_SHARES,
)


# ---------------------------------------------------------------------------
# Task execution mechanics (tmux panes)
# ---------------------------------------------------------------------------


def run_task(context, command: str, delay: int = 2):
    """Send *command* to the next available task pane after sleeping *delay* s.

    The *delay* is supplied by the caller via ``cmd.delay`` on the Command
    object returned by the builder functions.
    """
    target_pane = prepare_task_pane(context)
    if target_pane:
        target_pane.send_keys(f"sleep {delay}; {command}")
    else:
        write_log(context.log_file, f"Failed to create pane for task: {command}")


def stage_task(context, command):
    target_pane = prepare_task_pane(context)
    if target_pane:
        target_pane.send_keys(command, enter=False)


def prepare_task_pane(context):
    if (context.current_task_window is None or context.current_task_pane > 5):
        # Create a new task window
        window_name = f"tasks{context.task_window_count}"
        new_window = context.session.new_window(
            window_name=window_name,
            attach=False
        )
        # Split into 6 panes (5 splits)
        pane = new_window.active_pane
        for _ in range(2):
            pane = pane.split()
            pane = pane.split(direction=libtmux.pane.PaneDirection.Right)
        pane = pane.split()
        new_window.select_layout('tiled')
        # Update session tracking
        context.current_task_window = new_window
        context.task_window_count += 1
        context.current_task_pane = 0
        sleep(1) # Give panes time to initialize
    # Get the next available pane
    panes = context.current_task_window.panes
    if context.current_task_pane < len(panes):
        target_pane = panes[context.current_task_pane]
        context.current_task_pane += 1
        return target_pane
    return None


def _run_commands(context, commands):
    """Helper: run every Command from a builder through run_task."""
    for cmd in commands:
        run_task(context, cmd.to_shell(), delay=cmd.delay)


# ---------------------------------------------------------------------------
# Dispatch: port -> handler, driven by tasks.yaml
# ---------------------------------------------------------------------------

# Named resolvers that source a builder argument from the Context.  The YAML
# ``args`` lists reference these by name, so the mapping of port -> builder ->
# arguments is data while the (logic of) sourcing each argument lives here.
_RESOLVERS = {
    "ip": lambda c: c.ip,
    "domain": lambda c: c.domain,
    "fqdn": lambda c: c.get_target(),
    "https_fqdn": lambda c: c.vhost or c.domain or c.ip,
    "cred": lambda c: c.get_initial_cred() if c.creds_exist() else None,
}

_BUILDERS = {
    "ftp": build_ftp_commands,
    "dns": build_dns_commands,
    "http": build_http_commands,
    "kerberos": build_kerberos_commands,
    "rpc": build_rpc_commands,
    "https": build_https_commands,
    "mssql": build_mssql_commands,
    "nfs": build_nfs_commands,
}


def _generic_handler(context, cfg):
    """Run a builder whose args are resolved from the context per *cfg*."""
    if cfg.get("require_cred") and not context.creds_exist():
        return
    builder = _BUILDERS[cfg["builder"]]
    args = [_RESOLVERS[name](context) for name in cfg.get("args", [])]
    _run_commands(context, builder(*args))


# --- bespoke handlers (probe + orchestration logic that is not data) --------


def ldap_tasks(context):
    context.is_ad = True
    dc_fqdn = context.get_target()
    cred = context.get_initial_cred() if context.creds_exist() else None
    anon = False
    if not cred:
        anon = anonymous_bind(context)
        if anon:
            write_log(context.log_file, "LDAP anonymous bind is enabled", "SUCCESS")
    _run_commands(
        context,
        build_ldap_commands(
            ip=context.ip,
            domain=context.domain,
            dc_fqdn=dc_fqdn,
            cred=cred,
            anon_bind=anon,
        ),
    )


def smb_tasks(context):
    dc_fqdn = context.get_target()
    shares, method = enum_smb_shares(context)
    cred = context.get_initial_cred() if context.creds_exist() else None

    # Log found non-default shares (orchestration concern — stays in handler)
    if shares:
        for share in shares:
            if share["name"] not in _NON_DEFAULT_SHARES:
                write_log(
                    context.log_file,
                    f"Found non-default share: {share['name']}"
                    f" ({', '.join(share['access'])} privileges)",
                    "SUCCESS",
                )

    _run_commands(
        context,
        build_smb_commands(
            ip=context.ip,
            dc_fqdn=dc_fqdn,
            domain=context.domain,
            cred=cred,
            shares=shares,
            share_method=method,
        ),
    )


_CUSTOM_HANDLERS = {
    "ldap": ldap_tasks,
    "smb": smb_tasks,
}


def handle_task(context, port):
    """Main entry point for port handling — dispatch is driven by tasks.yaml."""
    port = int(port)
    spec = load_spec()

    spray = spec.get("sprayable_ports", {})
    if port in spray:
        context.sprayable_ports[port] = spray[port]

    cfg = spec.get("handlers", {}).get(port)
    if not cfg:
        return
    if "custom" in cfg:
        _CUSTOM_HANDLERS[cfg["custom"]](context)
    else:
        _generic_handler(context, cfg)
