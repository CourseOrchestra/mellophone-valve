from __future__ import annotations

import asyncio
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Tuple
from uuid import uuid4

import httpx
import pytest
import yaml

from mellophone import ForbiddenError, Mellophone

ROOT = Path(__file__).resolve().parents[1]
DOCKER_COMPOSE_PATH = ROOT / "docker-compose.yml"
MELLOPHONE_CONFIG_PATH = ROOT / "docker-config" / "config.xml"


@pytest.fixture(scope="session")
def integration_base_url() -> str:
    base_url = _extract_base_url_from_compose()
    _ensure_service_reachable(base_url)
    return base_url


@pytest.fixture(scope="session")
def integration_tokens() -> Tuple[str, str]:
    return _extract_tokens_from_config()


@pytest.fixture
def integration_client(
    integration_base_url: str,
    integration_tokens: Tuple[str, str],
) -> Mellophone:
    set_token, user_token = integration_tokens
    return Mellophone(
        base_url=integration_base_url,
        set_settings_token=set_token,
        user_manage_token=user_token,
    )


@pytest.fixture
def integration_user(
    integration_client: Mellophone,
) -> Dict[str, str]:
    unique = uuid4().hex[:8]
    sid = f"it-real-{unique}"
    login = f"it_real_{unique}"
    password = "pwd_1"
    integration_client.create_user({"sid": sid, "login": login, "password": password})
    return {"sid": sid, "login": login, "password": password}


def _extract_base_url_from_compose() -> str:
    compose_text = DOCKER_COMPOSE_PATH.read_text(encoding="utf-8")
    data = yaml.safe_load(compose_text)
    ports = data.get("services", {}).get("mellophone", {}).get("ports", [])
    if ports:
        port = ports[0].split(":")[0]
        return f"http://localhost:{port}/mellophone"
    raise RuntimeError("Port mapping not found in docker-compose.yml")


def _extract_tokens_from_config() -> Tuple[str, str]:
    root = ET.parse(MELLOPHONE_CONFIG_PATH).getroot()
    set_token = None
    user_token = None
    for element in root.iter():
        tag = element.tag.split("}")[-1]
        if tag == "setsettingstoken":
            set_token = (element.text or "").strip()
        elif tag == "getuserlisttoken":
            user_token = (element.text or "").strip()
    if not set_token or not user_token:
        raise RuntimeError("Tokens not found in docker-config/config.xml")
    return set_token, user_token


def _ensure_service_reachable(base_url: str) -> None:
    try:
        httpx.get(
            f"{base_url}/isauthenticated",
            params={"sesid": "integration-smoke"},
            timeout=3.0,
        )
    except (httpx.HTTPError, OSError) as exc:
        pytest.skip(f"Mellophone is not available at {base_url}: {exc}")


def _users_from_list(payload: Dict[str, Any]) -> List[Dict[str, str]]:
    users = payload.get("users", {}).get("user", [])
    if isinstance(users, dict):
        return [users]
    return users


def _assert_credentials_valid(
    client: Mellophone,
    login: str,
    password: str,
    sid: str,
) -> None:
    result = client.check_credentials(login, password)
    assert result.get("sid") == sid
    assert result.get("login") == login


def _assert_credentials_invalid(client: Mellophone, login: str, password: str) -> None:
    with pytest.raises(ForbiddenError):
        client.check_credentials(login, password)


def test_real_mellophone_sync_user_lifecycle(
    integration_client: Mellophone,
    integration_tokens: Tuple[str, str],
    integration_user: Dict[str, str],
) -> None:
    _, user_token = integration_tokens
    sid = integration_user["sid"]
    login = integration_user["login"]
    password = integration_user["password"]

    users_payload = integration_client.get_user_list(token=user_token, gp="not_defined")
    users = _users_from_list(users_payload)
    assert any(user.get("sid") == sid and user.get("login") == login for user in users)

    providers = integration_client.import_gp()
    assert providers

    provider_list = integration_client.get_provider_list(login, password, gp="not_defined")
    assert provider_list

    _assert_credentials_valid(integration_client, login, password, sid)

    session_id = integration_client.login(login, password)
    auth = integration_client.is_authenticated(session_id)
    assert auth is not False
    assert auth.get("sid") == sid

    check_name_exists = integration_client.check_name(login, session_id)
    assert check_name_exists.get("sid") == sid

    check_name_missing = integration_client.check_name(f"{login}_missing", session_id)
    assert check_name_missing == {}

    integration_client.logout(session_id)
    assert integration_client.is_authenticated(session_id) is False


def test_real_mellophone_sync_password_changes(
    integration_client: Mellophone,
    integration_tokens: Tuple[str, str],
    integration_user: Dict[str, str],
) -> None:
    _, user_token = integration_tokens
    sid = integration_user["sid"]
    login = integration_user["login"]
    pwd_1 = integration_user["password"]
    pwd_2 = "pwd_2"
    pwd_3 = "pwd_3"
    pwd_4 = "pwd_4"

    session_id = integration_client.login(login, pwd_1)

    integration_client.change_pwd(pwd_1, pwd_2, session_id)
    _assert_credentials_invalid(integration_client, login, pwd_1)
    _assert_credentials_valid(integration_client, login, pwd_2, sid)

    integration_client.change_user_pwd(login, pwd_2, pwd_3, session_id)
    _assert_credentials_invalid(integration_client, login, pwd_2)
    _assert_credentials_valid(integration_client, login, pwd_3, sid)

    integration_client.update_user(sid, user_token, {"sid": sid, "login": login, "pwd": pwd_4})
    _assert_credentials_invalid(integration_client, login, pwd_3)
    _assert_credentials_valid(integration_client, login, pwd_4, sid)

    integration_client.logout(session_id)
    assert integration_client.is_authenticated(session_id) is False


def test_real_mellophone_async_user_lifecycle(
    integration_client: Mellophone,
    integration_tokens: Tuple[str, str],
    integration_user: Dict[str, str],
) -> None:
    _, user_token = integration_tokens
    sid = integration_user["sid"]
    login = integration_user["login"]
    password = integration_user["password"]

    async def _run() -> None:
        providers_async = await integration_client.import_gp_async()
        assert providers_async

        provider_list_async = await integration_client.get_provider_list_async(
            login,
            password,
            gp="not_defined",
        )
        assert provider_list_async

        users_payload_async = await integration_client.get_user_list_async(
            token=user_token,
            gp="not_defined",
        )
        users_async = _users_from_list(users_payload_async)
        assert any(user.get("sid") == sid and user.get("login") == login for user in users_async)

        check_credentials_async = await integration_client.check_credentials_async(
            login,
            password,
        )
        assert check_credentials_async.get("sid") == sid

        session_async = await integration_client.login_async(login, password)
        auth_async = await integration_client.is_authenticated_async(session_async)
        assert auth_async is not False
        assert auth_async.get("sid") == sid

        check_name_async = await integration_client.check_name_async(login, session_async)
        assert check_name_async.get("sid") == sid

        await integration_client.logout_async(session_async)
        assert await integration_client.is_authenticated_async(session_async) is False

    asyncio.run(_run())


def test_real_mellophone_async_password_changes(
    integration_client: Mellophone,
    integration_tokens: Tuple[str, str],
    integration_user: Dict[str, str],
) -> None:
    _, user_token = integration_tokens
    sid = integration_user["sid"]
    login = integration_user["login"]
    pwd_4 = integration_user["password"]
    pwd_5 = "pwd_5"

    async def _run() -> None:
        session_async = await integration_client.login_async(login, pwd_4)

        await integration_client.change_pwd_async(pwd_4, pwd_5, session_async)
        with pytest.raises(ForbiddenError):
            await integration_client.check_credentials_async(login, pwd_4)

        valid_after_change = await integration_client.check_credentials_async(login, pwd_5)
        assert valid_after_change.get("sid") == sid

        await integration_client.update_user_async(
            sid,
            user_token,
            {"sid": sid, "login": login, "pwd": pwd_4},
        )
        with pytest.raises(ForbiddenError):
            await integration_client.check_credentials_async(login, pwd_5)

        valid_after_update = await integration_client.check_credentials_async(login, pwd_4)
        assert valid_after_update.get("sid") == sid

        await integration_client.logout_async(session_async)
        assert await integration_client.is_authenticated_async(session_async) is False

    asyncio.run(_run())
