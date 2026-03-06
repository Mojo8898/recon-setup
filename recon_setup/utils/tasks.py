from time import sleep

import libtmux

from recon_setup.utils.logger import write_log
from recon_setup.utils.active_directory import enum_smb_shares, anonymous_bind
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


SPRAYABLE_PORTS = {21: "ftp", 22: "ssh", 135: "wmi", 389: "ldap", 445: "smb", 1433: "mssql", 3389: "rdp", 5900: "vnc", 5985: "winrm"}


class PortHandlerRegistry:
    def __init__(self):
        self.port_handlers = {}

    def register_port_handler(self, *ports):
        def decorator(func):
            for port in ports:
                self.port_handlers.setdefault(port, []).append(func)
            return func
        return decorator


port_registry = PortHandlerRegistry()


def handle_task(context, port):
    """Main entry point for port handling"""
    port = int(port)
    if port in SPRAYABLE_PORTS:
        context.sprayable_ports[port] = SPRAYABLE_PORTS[port]
    if port in port_registry.port_handlers:
        for task_handler in port_registry.port_handlers[port]:
            task_handler(context)


def run_task(context, command: str, delay: int = 2):
    """Send *command* to the next available task pane after sleeping *delay* s.

    The *delay* is supplied by the caller via ``cmd.delay`` on the Command
    object returned by the builder functions, replacing the old inline
    'nxc'/'kerbrute' string-based heuristics.
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


@port_registry.register_port_handler(21)
def ftp_tasks(context):
    cred = context.get_initial_cred() if context.creds_exist() else None
    _run_commands(context, build_ftp_commands(ip=context.ip, cred=cred))


@port_registry.register_port_handler(53)
def dns_tasks(context):
    _run_commands(context, build_dns_commands(ip=context.ip, domain=context.domain))


@port_registry.register_port_handler(80)
def http_tasks(context):
    fqdn = context.get_target()
    _run_commands(context, build_http_commands(ip=context.ip, fqdn=fqdn))


@port_registry.register_port_handler(88)
def kerberos_tasks(context):
    cred = context.get_initial_cred() if context.creds_exist() else None
    _run_commands(
        context,
        build_kerberos_commands(ip=context.ip, domain=context.domain, cred=cred),
    )


@port_registry.register_port_handler(135)
def rpc_tasks(context):
    _run_commands(context, build_rpc_commands(ip=context.ip))


@port_registry.register_port_handler(389)
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


@port_registry.register_port_handler(443)
def https_tasks(context):
    fqdn = context.vhost or context.domain or context.ip
    _run_commands(context, build_https_commands(fqdn=fqdn))


@port_registry.register_port_handler(445)
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


@port_registry.register_port_handler(1433)
def mssql_tasks(context):
    if context.creds_exist():
        cred = context.get_initial_cred()
        _run_commands(
            context,
            build_mssql_commands(ip=context.ip, domain=context.domain, cred=cred),
        )


@port_registry.register_port_handler(2049)
def nfs_tasks(context):
    _run_commands(context, build_nfs_commands(ip=context.ip))
