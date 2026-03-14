#!/usr/bin/python3

import os
import time
import requests
from datetime import datetime, timezone
from rich.console import Console

BASE_URL = "https://labs.hackthebox.com"

# Rate-limit-aware timing constants
SPAWN_INTERVAL = 4.4    # 60s / 15 spawn-limit * 1.1 buffer
IP_POLL_INTERVAL = 0.73  # 10s / 15 IP-poll-limit * 1.1 buffer (/api/v4/machine/active)
SPAWN_WINDOW = 60       # seconds for the new-release retry window
RATELIMIT_SLEEP = 60    # back-off when x-ratelimit-remaining <= 1


def get_current_time():
    """Return current UTC time via NTP (pool.ntp.org), falling back to local clock on errors."""
    import socket
    import struct

    NTP_DELTA = 2208988800  # seconds between 1900-01-01 and 1970-01-01
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(3)
        client.sendto(b"\x1b" + 47 * b"\0", ("pool.ntp.org", 123))
        data, _ = client.recvfrom(1024)
        t = struct.unpack("!12I", data)[10] - NTP_DELTA
        return datetime.fromtimestamp(t, tz=timezone.utc)
    except Exception as e:
        print(f"Error fetching time from NTP, falling back to local time: {e}")
        return datetime.now(timezone.utc)
    finally:
        client.close()


def _check_ratelimit(response):
    """Sleep RATELIMIT_SLEEP seconds if x-ratelimit-remaining is <= 1."""
    remaining = response.headers.get("x-ratelimit-remaining")
    if remaining is not None:
        try:
            if int(remaining) <= 1:
                time.sleep(RATELIMIT_SLEEP)
        except ValueError:
            pass


def _auth_headers(token):
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    }


def get_machine_id(name, token):
    """Look up machine ID by name.

    Queries /api/v5/machines?state=unreleased first, then state=active.
    Follows pagination via links.next until all pages are exhausted.
    Match is case-insensitive.  Raises ValueError if not found in either.
    """
    headers = _auth_headers(token)
    for state in ("unreleased", "active"):
        url = f"{BASE_URL}/api/v5/machines?state={state}"
        while url:
            response = requests.get(url, headers=headers)
            _check_ratelimit(response)
            if response.status_code != 200:
                break
            data = response.json()
            if isinstance(data, dict):
                machine_list = data.get("data", [])
                next_url = data.get("links", {}).get("next")
            elif isinstance(data, list):
                machine_list = data
                next_url = None
            else:
                break
            for machine in machine_list:
                if machine.get("name", "").lower() == name.lower():
                    return machine["id"]
            url = next_url
    raise ValueError(f"Machine '{name}' not found in unreleased or active listings")


def spawn_machine_api(machine_id, token):
    """POST to /api/v4/vm/spawn with {machine_id: N}.

    Returns True on HTTP 200, False on any error.
    """
    headers = _auth_headers(token)
    url = f"{BASE_URL}/api/v4/vm/spawn"
    response = requests.post(url, json={"machine_id": machine_id}, headers=headers)
    _check_ratelimit(response)
    return response.status_code == 200


def get_active_ip(token):
    """GET /api/v4/machine/active and return info.ip, or None."""
    headers = _auth_headers(token)
    url = f"{BASE_URL}/api/v4/machine/active"
    response = requests.get(url, headers=headers)
    _check_ratelimit(response)
    if response.status_code != 200:
        return None
    data = response.json()
    if isinstance(data, dict):
        info = data.get("info")
        if isinstance(info, dict):
            ip = info.get("ip")
            return ip if ip else None
    return None


def spawn_machine(name, new_release):
    """Spawn a machine by name and return its IP address.

    Reads HTB_TOKEN from the environment; raises EnvironmentError if missing.
    Preserves the original (name, new_release) signature for main.py compatibility.
    """
    token = os.environ.get("HTB_TOKEN")
    if not token:
        raise EnvironmentError(
            "HTB_TOKEN environment variable is not set. "
            "Export your HTB API token before running recon-setup."
        )

    console = Console()
    machine_id = get_machine_id(name, token)

    if new_release:
        # Sync time and wait until T-60s before the scheduled 19:00 UTC release
        now = get_current_time()
        release_time = now.replace(hour=19, minute=0, second=0, microsecond=0)
        if now < release_time:
            wait_seconds = (release_time - now).total_seconds() - 60
            if wait_seconds > 0:
                try:
                    with console.status(
                        f"Waiting {wait_seconds:.0f}s until T-60s before release...",
                        spinner="dots",
                    ):
                        time.sleep(wait_seconds)
                except KeyboardInterrupt:
                    print("Ctrl+C detected. Attempting spawn now...")

        # Retry spawn every SPAWN_INTERVAL for a SPAWN_WINDOW-second window
        spawned = False
        window_end = time.monotonic() + SPAWN_WINDOW
        with console.status("Attempting to spawn machine (new release)...", spinner="dots"):
            while time.monotonic() < window_end:
                if spawn_machine_api(machine_id, token):
                    spawned = True
                    break
                time.sleep(SPAWN_INTERVAL)

        if not spawned:
            return None

    else:
        # Standard (non-release) spawn — single attempt
        with console.status("Spawning machine...", spinner="dots"):
            if not spawn_machine_api(machine_id, token):
                return None

    # Poll for IP at IP_POLL_INTERVAL until assigned
    ip = None
    with console.status("Waiting for IP assignment...", spinner="dots"):
        while ip is None:
            ip = get_active_ip(token)
            if ip is None:
                time.sleep(IP_POLL_INTERVAL)

    return ip
