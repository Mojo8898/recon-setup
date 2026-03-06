# recon-setup

![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-blue)

**recon-setup** is a CLI tool that automates tmux session creation, nmap scanning, and port-driven enumeration for offensive security labs.

## Features

- [x] Structured tmux session with dedicated panes for OpenVPN, Ligolo, file serving, nmap, and task logging.
- [x] Port-driven automation: watches nmap output in real time and dispatches enumeration tasks as ports are discovered.
- [x] Credential-aware handlers: pass initial credentials to pre-populate authenticated scans across SMB, LDAP, Kerberos, MSSQL, and more.
- [x] Credential watcher: monitors `creds.txt` for new entries and re-runs relevant handlers automatically.
- [x] HTB CLI integration: spawn machines directly by name without manually retrieving an IP.

## Requirements

- tmux
- `/opt/scripts/scan_machine.py` — nmap wrapper script that drives the scan and emits port results to stdout
- Tools used by enumeration handlers: `nxc`, `bloodhound-ce-python`, `bloodhound-cli`, `bloodyAD`, `certipy`, `aliasr`, `kerbrute`, `hashcat`, `ffuf`, `feroxbuster`, `nuclei`, `wpscan`, `powerview`, `impacket`

## Install

```bash
# Latest commit (GitHub)
uv tool install git+https://github.com/Mojo8898/recon-setup
pipx install git+https://github.com/Mojo8898/recon-setup

# Local development
git clone https://github.com/Mojo8898/recon-setup
cd recon-setup
uv sync
```

## Usage

```
usage: recon-setup [-h] [-v VPN_PATH] [-s SESSION_PATH] [-i IP]
                   [--spawn SPAWN] [-n] [-a] [-u USERNAME] [-p PASSWORD] [-d]
                   session_name

Automate the setup and enumeration process for offensive security labs.

options:
  -h, --help            show this help message and exit

Session Arguments:
  Arguments related to session configuration

  session_name          Name of the tmux session to be created
  -v VPN_PATH, --vpn_path VPN_PATH
                        Path of your VPN file
  -s SESSION_PATH, --session_path SESSION_PATH
                        Path to where the session will be created (default:
                        /workspace/machines)
  -i IP, --ip IP        IP address of the target machine

HTB CLI Arguments:
  Arguments related to HTB CLI functionality

  --spawn SPAWN         Spawn the target machine using the HTB CLI instead of
                        providing an IP (requires htb-cli)
  -n, --new_release     Wait for the scheduled release time (7pm UTC) and
                        spawn automatically

Automation Arguments:
  Arguments related to automated tasking

  -a, --automate        Optional flag to enable automated tasks on the fly
                        from nmap scan results
  -u USERNAME, --username USERNAME
                        Username to supply automated tasks (AD only)
  -p PASSWORD, --password PASSWORD
                        Password to supply automated tasks (AD only)
  -d, --debug           Enable debug mode for automation
```

Standard session without automation:

```bash
recon-setup pirate -v ~/vpn/lab.ovpn -i 10.10.11.40
```

Session with full automation and initial credentials:

```bash
recon-setup pirate -v ~/vpn/lab.ovpn -i 10.10.11.40 -a -u pentest -p 'Password123!'
```

Spawn an HTB machine by name and automate:

```bash
recon-setup pirate -v ~/vpn/lab.ovpn --spawn pirate -a
```

## Contributing

Contributions are welcome. Feel free to open an issue for bugs or feature requests.

## Acknowledgments

- Built on top of [libtmux](https://github.com/tmux-python/libtmux)
- Enumeration handlers integrate [aliasr](https://github.com/Mojo8898/aliasr), [NetExec](https://github.com/Pennyw0rth/NetExec), and the [Impacket](https://github.com/fortra/impacket) suite
