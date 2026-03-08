"""Unit tests for recon_setup.utils.htb_cli (direct HTB API integration)."""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

import recon_setup.utils.htb_cli as htb_mod
from recon_setup.utils.htb_cli import RATELIMIT_SLEEP


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_response(status_code=200, json_data=None, headers=None):
    """Build a minimal mock requests.Response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data if json_data is not None else {}
    resp.headers = headers or {}
    return resp


def _spawn_ctx():
    """
    Return a reusable context-manager stack that suppresses Rich Console I/O
    and no-ops time.sleep / time.monotonic for the duration of a test.
    The monotonic side-effect (0, 1, 2) keeps the new-release window loop
    alive for exactly two iterations before breaking on success.
    """
    return (
        patch("recon_setup.utils.htb_cli.Console"),
        patch("recon_setup.utils.htb_cli.time"),
    )


# ---------------------------------------------------------------------------
# AC #1 — Missing HTB_TOKEN raises EnvironmentError
# ---------------------------------------------------------------------------

class TestMissingToken:
    def test_spawn_machine_raises_environment_error(self, monkeypatch):
        monkeypatch.delenv("HTB_TOKEN", raising=False)
        with pytest.raises(EnvironmentError, match="HTB_TOKEN"):
            htb_mod.spawn_machine("TestMachine", False)

    def test_error_message_is_descriptive(self, monkeypatch):
        monkeypatch.delenv("HTB_TOKEN", raising=False)
        with pytest.raises(EnvironmentError, match="Export your HTB API token"):
            htb_mod.spawn_machine("TestMachine", False)


# ---------------------------------------------------------------------------
# AC #2 — get_machine_id: unreleased-first, active fallback, case-insensitive
# ---------------------------------------------------------------------------

class TestGetMachineId:
    def test_machine_not_found_raises_value_error(self):
        empty = make_response(json_data=[])
        with patch("recon_setup.utils.htb_cli.requests") as mock_req:
            mock_req.get.return_value = empty
            with pytest.raises(ValueError, match="TestMachine"):
                htb_mod.get_machine_id("TestMachine", "tok")

    def test_machine_found_in_unreleased_on_first_call(self):
        machines = [{"id": 42, "name": "TestMachine"}]
        resp = make_response(json_data=machines)
        with patch("recon_setup.utils.htb_cli.requests") as mock_req:
            mock_req.get.return_value = resp
            machine_id = htb_mod.get_machine_id("TestMachine", "tok")
        assert machine_id == 42

    def test_machine_found_in_active_after_unreleased_miss(self):
        empty = make_response(json_data=[])
        active = make_response(json_data=[{"id": 99, "name": "TargetBox"}])
        with patch("recon_setup.utils.htb_cli.requests") as mock_req:
            mock_req.get.side_effect = [empty, active]
            machine_id = htb_mod.get_machine_id("TargetBox", "tok")
        assert machine_id == 99

    def test_name_match_is_case_insensitive(self):
        machines = [{"id": 7, "name": "UPPERBOX"}]
        resp = make_response(json_data=machines)
        with patch("recon_setup.utils.htb_cli.requests") as mock_req:
            mock_req.get.return_value = resp
            machine_id = htb_mod.get_machine_id("upperbox", "tok")
        assert machine_id == 7

    def test_response_with_data_wrapper_is_handled(self):
        wrapped = {"data": [{"id": 55, "name": "Wrapped"}]}
        resp = make_response(json_data=wrapped)
        with patch("recon_setup.utils.htb_cli.requests") as mock_req:
            mock_req.get.return_value = resp
            machine_id = htb_mod.get_machine_id("Wrapped", "tok")
        assert machine_id == 55

    def test_auth_header_contains_bearer_token(self):
        machines = [{"id": 1, "name": "X"}]
        resp = make_response(json_data=machines)
        with patch("recon_setup.utils.htb_cli.requests") as mock_req:
            mock_req.get.return_value = resp
            htb_mod.get_machine_id("X", "mytoken123")
        call_kwargs = mock_req.get.call_args
        assert "Authorization" in call_kwargs.kwargs["headers"]
        assert call_kwargs.kwargs["headers"]["Authorization"] == "Bearer mytoken123"


# ---------------------------------------------------------------------------
# AC #3 — spawn_machine_api: POST body and return value
# ---------------------------------------------------------------------------

class TestSpawnMachineApi:
    def test_returns_true_on_200(self):
        ok = make_response(status_code=200)
        with patch("recon_setup.utils.htb_cli.requests") as mock_req:
            with patch("recon_setup.utils.htb_cli.time"):
                mock_req.post.return_value = ok
                result = htb_mod.spawn_machine_api(42, "tok")
        assert result is True

    def test_returns_false_on_non_200(self):
        err = make_response(status_code=500)
        with patch("recon_setup.utils.htb_cli.requests") as mock_req:
            with patch("recon_setup.utils.htb_cli.time"):
                mock_req.post.return_value = err
                result = htb_mod.spawn_machine_api(42, "tok")
        assert result is False

    def test_post_body_contains_machine_id(self):
        ok = make_response(status_code=200)
        with patch("recon_setup.utils.htb_cli.requests") as mock_req:
            with patch("recon_setup.utils.htb_cli.time"):
                mock_req.post.return_value = ok
                htb_mod.spawn_machine_api(77, "tok")
        call_kwargs = mock_req.post.call_args
        assert call_kwargs.kwargs["json"] == {"machine_id": 77}

    def test_posts_to_correct_url(self):
        ok = make_response(status_code=200)
        with patch("recon_setup.utils.htb_cli.requests") as mock_req:
            with patch("recon_setup.utils.htb_cli.time"):
                mock_req.post.return_value = ok
                htb_mod.spawn_machine_api(1, "tok")
        url = mock_req.post.call_args.args[0]
        assert url.endswith("/api/v4/vm/spawn")


# ---------------------------------------------------------------------------
# AC #4 — get_active_ip: returns data.ip or None
# ---------------------------------------------------------------------------

class TestGetActiveIp:
    def test_returns_ip_from_data_key(self):
        resp = make_response(json_data={"data": {"ip": "10.10.11.100"}})
        with patch("recon_setup.utils.htb_cli.requests") as mock_req:
            with patch("recon_setup.utils.htb_cli.time"):
                mock_req.get.return_value = resp
                ip = htb_mod.get_active_ip("tok")
        assert ip == "10.10.11.100"

    def test_returns_none_when_ip_is_null(self):
        resp = make_response(json_data={"data": {"ip": None}})
        with patch("recon_setup.utils.htb_cli.requests") as mock_req:
            with patch("recon_setup.utils.htb_cli.time"):
                mock_req.get.return_value = resp
                ip = htb_mod.get_active_ip("tok")
        assert ip is None

    def test_returns_none_on_non_200(self):
        resp = make_response(status_code=404)
        with patch("recon_setup.utils.htb_cli.requests") as mock_req:
            with patch("recon_setup.utils.htb_cli.time"):
                mock_req.get.return_value = resp
                ip = htb_mod.get_active_ip("tok")
        assert ip is None

    def test_returns_ip_from_info_key_fallback(self):
        resp = make_response(json_data={"info": {"ip": "10.10.11.200"}})
        with patch("recon_setup.utils.htb_cli.requests") as mock_req:
            with patch("recon_setup.utils.htb_cli.time"):
                mock_req.get.return_value = resp
                ip = htb_mod.get_active_ip("tok")
        assert ip == "10.10.11.200"


# ---------------------------------------------------------------------------
# AC #7 — Rate-limit check sleeps on x-ratelimit-remaining <= 1
# ---------------------------------------------------------------------------

class TestRatelimitCheck:
    def test_sleeps_when_remaining_is_one(self):
        resp = make_response(headers={"x-ratelimit-remaining": "1"})
        with patch("recon_setup.utils.htb_cli.time") as mock_time:
            htb_mod._check_ratelimit(resp)
        mock_time.sleep.assert_called_once_with(RATELIMIT_SLEEP)

    def test_sleeps_when_remaining_is_zero(self):
        resp = make_response(headers={"x-ratelimit-remaining": "0"})
        with patch("recon_setup.utils.htb_cli.time") as mock_time:
            htb_mod._check_ratelimit(resp)
        mock_time.sleep.assert_called_once_with(RATELIMIT_SLEEP)

    def test_no_sleep_when_remaining_is_two(self):
        resp = make_response(headers={"x-ratelimit-remaining": "2"})
        with patch("recon_setup.utils.htb_cli.time") as mock_time:
            htb_mod._check_ratelimit(resp)
        mock_time.sleep.assert_not_called()

    def test_no_sleep_when_header_absent(self):
        resp = make_response(headers={})
        with patch("recon_setup.utils.htb_cli.time") as mock_time:
            htb_mod._check_ratelimit(resp)
        mock_time.sleep.assert_not_called()


# ---------------------------------------------------------------------------
# AC #10 test case: successful non-release spawn
# ---------------------------------------------------------------------------

class TestSuccessfulNonReleaseSpawn:
    def test_returns_ip_after_spawn(self, monkeypatch):
        monkeypatch.setenv("HTB_TOKEN", "fake-token")

        machines = [{"id": 42, "name": "TestMachine"}]
        get_machines_resp = make_response(json_data=machines)
        spawn_ok = make_response(status_code=200)
        ip_resp = make_response(json_data={"data": {"ip": "10.10.11.100"}})

        with patch("recon_setup.utils.htb_cli.requests") as mock_req, \
             patch("recon_setup.utils.htb_cli.time"), \
             patch("recon_setup.utils.htb_cli.Console"):
            mock_req.get.side_effect = [get_machines_resp, ip_resp]
            mock_req.post.return_value = spawn_ok
            ip = htb_mod.spawn_machine("TestMachine", False)

        assert ip == "10.10.11.100"

    def test_spawn_called_with_correct_machine_id(self, monkeypatch):
        monkeypatch.setenv("HTB_TOKEN", "fake-token")

        machines = [{"id": 42, "name": "TestMachine"}]
        get_machines_resp = make_response(json_data=machines)
        spawn_ok = make_response(status_code=200)
        ip_resp = make_response(json_data={"data": {"ip": "10.10.11.100"}})

        with patch("recon_setup.utils.htb_cli.requests") as mock_req, \
             patch("recon_setup.utils.htb_cli.time"), \
             patch("recon_setup.utils.htb_cli.Console"):
            mock_req.get.side_effect = [get_machines_resp, ip_resp]
            mock_req.post.return_value = spawn_ok
            htb_mod.spawn_machine("TestMachine", False)

        mock_req.post.assert_called_once()
        assert mock_req.post.call_args.kwargs["json"]["machine_id"] == 42

    def test_returns_none_when_spawn_fails(self, monkeypatch):
        monkeypatch.setenv("HTB_TOKEN", "fake-token")

        machines = [{"id": 42, "name": "TestMachine"}]
        get_machines_resp = make_response(json_data=machines)
        spawn_fail = make_response(status_code=500)

        with patch("recon_setup.utils.htb_cli.requests") as mock_req, \
             patch("recon_setup.utils.htb_cli.time"), \
             patch("recon_setup.utils.htb_cli.Console"):
            mock_req.get.return_value = get_machines_resp
            mock_req.post.return_value = spawn_fail
            ip = htb_mod.spawn_machine("TestMachine", False)

        assert ip is None


# ---------------------------------------------------------------------------
# AC #10 test case: new_release retry loop (mocking requests)
# ---------------------------------------------------------------------------

class TestNewReleaseRetryLoop:
    def test_retries_spawn_until_success(self, monkeypatch):
        monkeypatch.setenv("HTB_TOKEN", "fake-token")

        # T-2 min before release → wait_seconds = 60s (2*60 - 60)
        now_before = datetime(2026, 3, 8, 18, 58, 0, tzinfo=timezone.utc)

        machines = [{"id": 42, "name": "TestMachine"}]
        get_machines_resp = make_response(json_data=machines)
        spawn_fail = make_response(status_code=500)
        spawn_ok = make_response(status_code=200)
        ip_resp = make_response(json_data={"data": {"ip": "10.10.11.100"}})

        # monotonic calls: window_end=mono[0]+60, then two while-condition checks
        mono_values = [0, 1, 2]

        with patch("recon_setup.utils.htb_cli.requests") as mock_req, \
             patch("recon_setup.utils.htb_cli.get_current_time", return_value=now_before), \
             patch("recon_setup.utils.htb_cli.time") as mock_time, \
             patch("recon_setup.utils.htb_cli.Console"):
            mock_req.get.side_effect = [get_machines_resp, ip_resp]
            mock_req.post.side_effect = [spawn_fail, spawn_ok]
            mock_time.monotonic.side_effect = mono_values

            ip = htb_mod.spawn_machine("TestMachine", True)

        assert ip == "10.10.11.100"

    def test_returns_none_when_window_expires_without_spawn(self, monkeypatch):
        monkeypatch.setenv("HTB_TOKEN", "fake-token")

        now_before = datetime(2026, 3, 8, 18, 58, 0, tzinfo=timezone.utc)

        machines = [{"id": 42, "name": "TestMachine"}]
        get_machines_resp = make_response(json_data=machines)
        spawn_fail = make_response(status_code=500)

        # monotonic: window_end=0+60; first while check returns 100 (> 60 → exit immediately)
        mono_values = [0, 100]

        with patch("recon_setup.utils.htb_cli.requests") as mock_req, \
             patch("recon_setup.utils.htb_cli.get_current_time", return_value=now_before), \
             patch("recon_setup.utils.htb_cli.time") as mock_time, \
             patch("recon_setup.utils.htb_cli.Console"):
            mock_req.get.return_value = get_machines_resp
            mock_req.post.return_value = spawn_fail
            mock_time.monotonic.side_effect = mono_values

            ip = htb_mod.spawn_machine("TestMachine", True)

        assert ip is None

    def test_spawn_interval_constant_is_correct(self):
        """SPAWN_INTERVAL = 60s / 15 limit * 1.1 buffer = 4.4s"""
        assert htb_mod.SPAWN_INTERVAL == pytest.approx(4.4)

    def test_ip_poll_interval_constant_is_correct(self):
        """IP_POLL_INTERVAL = 60s / 60 limit * 1.1 buffer = 1.1s"""
        assert htb_mod.IP_POLL_INTERVAL == pytest.approx(1.1)


# ---------------------------------------------------------------------------
# AC #10 test case: IP poll returning None then IP
# ---------------------------------------------------------------------------

class TestIpPollNoneThenIp:
    def test_polls_until_ip_is_assigned(self, monkeypatch):
        monkeypatch.setenv("HTB_TOKEN", "fake-token")

        machines = [{"id": 42, "name": "TestMachine"}]
        get_machines_resp = make_response(json_data=machines)
        spawn_ok = make_response(status_code=200)
        ip_null_resp = make_response(json_data={"data": {"ip": None}})
        ip_real_resp = make_response(json_data={"data": {"ip": "10.10.11.200"}})

        # GET sequence: get_machine_id (unreleased) → ip=None → ip=real
        with patch("recon_setup.utils.htb_cli.requests") as mock_req, \
             patch("recon_setup.utils.htb_cli.time") as mock_time, \
             patch("recon_setup.utils.htb_cli.Console"):
            mock_req.get.side_effect = [get_machines_resp, ip_null_resp, ip_real_resp]
            mock_req.post.return_value = spawn_ok
            ip = htb_mod.spawn_machine("TestMachine", False)

        assert ip == "10.10.11.200"

    def test_sleep_called_between_null_and_real_ip(self, monkeypatch):
        monkeypatch.setenv("HTB_TOKEN", "fake-token")

        machines = [{"id": 42, "name": "TestMachine"}]
        get_machines_resp = make_response(json_data=machines)
        spawn_ok = make_response(status_code=200)
        ip_null_resp = make_response(json_data={"data": {"ip": None}})
        ip_real_resp = make_response(json_data={"data": {"ip": "10.10.11.200"}})

        with patch("recon_setup.utils.htb_cli.requests") as mock_req, \
             patch("recon_setup.utils.htb_cli.time") as mock_time, \
             patch("recon_setup.utils.htb_cli.Console"):
            mock_req.get.side_effect = [get_machines_resp, ip_null_resp, ip_real_resp]
            mock_req.post.return_value = spawn_ok
            htb_mod.spawn_machine("TestMachine", False)

        # time.sleep must have been called at least once (IP poll back-off)
        assert mock_time.sleep.call_count >= 1

    def test_returns_ip_after_multiple_null_polls(self, monkeypatch):
        monkeypatch.setenv("HTB_TOKEN", "fake-token")

        machines = [{"id": 42, "name": "TestMachine"}]
        get_machines_resp = make_response(json_data=machines)
        spawn_ok = make_response(status_code=200)
        null_resp = make_response(json_data={"data": {"ip": None}})
        ip_real_resp = make_response(json_data={"data": {"ip": "10.10.11.50"}})

        with patch("recon_setup.utils.htb_cli.requests") as mock_req, \
             patch("recon_setup.utils.htb_cli.time"), \
             patch("recon_setup.utils.htb_cli.Console"):
            # Three null polls before a real IP
            mock_req.get.side_effect = [
                get_machines_resp,
                null_resp, null_resp, null_resp,
                ip_real_resp,
            ]
            mock_req.post.return_value = spawn_ok
            ip = htb_mod.spawn_machine("TestMachine", False)

        assert ip == "10.10.11.50"


# ---------------------------------------------------------------------------
# AC #9 — No subprocess / regex / htb-cli binary imports remain
# ---------------------------------------------------------------------------

class TestNoSubprocessDependency:
    def test_subprocess_not_imported(self):
        import sys
        # subprocess should NOT appear in htb_cli's module imports
        assert "subprocess" not in dir(htb_mod)

    def test_re_not_imported(self):
        assert "re" not in dir(htb_mod)
