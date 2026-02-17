from __future__ import annotations

from typing import Dict
from uuid import uuid4

import pytest

from mellophone import Mellophone
from tests.integration.helpers import assert_credentials_invalid, assert_credentials_valid, invoke, users_from_list


@pytest.mark.parametrize("mode", ["sync", "async"], ids=["sync", "async"])
def test_it_user_lifecycle(mode: str, integration_client: Mellophone, integration_user: Dict[str, str]) -> None:
    sid = integration_user["sid"]
    login = integration_user["login"]
    password = integration_user["password"]

    users_payload = invoke(integration_client, mode, "get_user_list", gp="not_defined")
    users = users_from_list(users_payload)
    assert any(user.get("sid") == sid and user.get("login") == login for user in users)

    providers = invoke(integration_client, mode, "import_gp")
    assert providers

    provider_list = invoke(integration_client, mode, "get_provider_list", login, password, gp="not_defined")
    assert provider_list

    assert_credentials_valid(integration_client, mode, login, password, sid)

    session_id = invoke(integration_client, mode, "login", login, password)
    auth = invoke(integration_client, mode, "is_authenticated", session_id)
    assert isinstance(auth, dict)
    assert auth.get("sid") == sid

    check_name_exists = invoke(integration_client, mode, "check_name", login, session_id)
    assert check_name_exists.get("sid") == sid

    check_name_missing = invoke(integration_client, mode, "check_name", f"{login}_missing", session_id)
    assert check_name_missing == {}

    invoke(integration_client, mode, "logout", session_id)
    assert invoke(integration_client, mode, "is_authenticated", session_id) is False


@pytest.mark.parametrize("mode", ["sync", "async"], ids=["sync", "async"])
def test_it_password_changes(mode: str, integration_client: Mellophone, integration_user: Dict[str, str]) -> None:
    sid = integration_user["sid"]
    login = integration_user["login"]
    pwd_before = integration_user["password"]
    pwd_2 = "pwd_2"
    pwd_3 = "pwd_3"
    pwd_after_update = "pwd_4"

    session_id = invoke(integration_client, mode, "login", login, pwd_before)

    invoke(integration_client, mode, "change_pwd", pwd_before, pwd_2, session_id)
    assert_credentials_invalid(integration_client, mode, login, pwd_before)
    assert_credentials_valid(integration_client, mode, login, pwd_2, sid)

    invoke(integration_client, mode, "change_user_pwd", login, pwd_3, session_id)
    assert_credentials_invalid(integration_client, mode, login, pwd_2)
    assert_credentials_valid(integration_client, mode, login, pwd_3, sid)

    invoke(integration_client, mode, "update_user", sid, {"sid": sid, "login": login, "pwd": pwd_after_update})
    assert_credentials_invalid(integration_client, mode, login, pwd_3)
    assert_credentials_valid(integration_client, mode, login, pwd_after_update, sid)

    invoke(integration_client, mode, "logout", session_id)
    assert invoke(integration_client, mode, "is_authenticated", session_id) is False


@pytest.mark.parametrize("mode", ["sync", "async"], ids=["sync", "async"])
def test_it_state_session_settings_and_delete(mode: str, integration_client: Mellophone) -> None:
    unique = uuid4().hex[:8]
    sid = f"it-real-{mode}-{unique}"
    login = f"it_real_{mode}_{unique}"
    pwd_1 = "pwd_1"
    pwd_2 = "pwd_2"
    state_value = f"state_{mode}_{unique}"

    invoke(integration_client, mode, "create_user", {"sid": sid, "login": login, "password": pwd_1})
    assert_credentials_valid(integration_client, mode, login, pwd_1, sid)

    session_id = invoke(integration_client, mode, "login", login, pwd_1)
    invoke(integration_client, mode, "set_state", session_id, state_value)
    assert invoke(integration_client, mode, "get_state", session_id) == state_value

    invoke(integration_client, mode, "set_settings", lockout_time=30, login_attempts_allowed=5)

    new_session_id = f"{session_id}-moved"
    invoke(integration_client, mode, "change_app_ses_id", new_session_id, session_id)
    auth_after_change = invoke(integration_client, mode, "is_authenticated", new_session_id)
    assert isinstance(auth_after_change, dict)
    assert auth_after_change.get("sid") == sid
    assert invoke(integration_client, mode, "is_authenticated", session_id) is False

    invoke(integration_client, mode, "change_user_pwd", login, pwd_2, new_session_id)
    assert_credentials_invalid(integration_client, mode, login, pwd_1)
    assert_credentials_valid(integration_client, mode, login, pwd_2, sid)

    invoke(integration_client, mode, "delete_user", sid)
    assert_credentials_invalid(integration_client, mode, login, pwd_2)


@pytest.mark.parametrize("mode", ["sync", "async"], ids=["sync", "async"])
def test_it_user_additional_fields(mode: str, integration_client: Mellophone) -> None:
    unique = uuid4().hex[:8]
    sid = f"it-extra-{mode}-{unique}"
    login = f"it_extra_{mode}_{unique}"
    pwd_1 = "pwd_1"
    pwd_2 = "pwd_2"

    create_payload = {
        "sid": sid,
        "login": login,
        "password": pwd_1,
        "field_str": f"{login}@example.com",
        "field_int": 20,
        "field_float": 4.5,
        "field_bool": False,
        "field_none": None,
        "field_empty_str": "",
        "field_empty_list": [],
        "field_list": ["org1"],
    }
    update_payload = {
        "sid": sid,
        "login": login,
        "pwd": pwd_2,
        "field_str": f"{login}+updated@example.com",
        "field_int": 30,
        "field_float": 9.75,
        "field_bool": True,
        "field_list": ["org1", "org2"],
    }

    try:
        invoke(integration_client, mode, "create_user", create_payload)
        assert_credentials_valid(integration_client, mode, login, pwd_1, sid)

        users_after_create = users_from_list(invoke(integration_client, mode, "get_user_list", gp="not_defined"))
        created_user = next((user for user in users_after_create if user.get("sid") == sid), None)
        assert created_user is not None
        for key in filter(lambda x: x not in ('password', 'pwd'), create_payload):
            assert created_user.get(key) == str(create_payload[key])

        invoke(integration_client, mode, "update_user", sid, update_payload)
        assert_credentials_invalid(integration_client, mode, login, pwd_1)
        assert_credentials_valid(integration_client, mode, login, pwd_2, sid)

        users_after_update = users_from_list(invoke(integration_client, mode, "get_user_list", gp="not_defined"))
        updated_user = next((user for user in users_after_update if user.get("sid") == sid), None)
        assert updated_user is not None
        for key in filter(lambda x: x not in ('password', 'pwd'), update_payload):
            assert updated_user.get(key) == str(update_payload[key])
    finally:
        ...
        # invoke(integration_client, mode, "delete_user", sid)
