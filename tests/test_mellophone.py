import asyncio
import xml.etree.ElementTree as ET
from typing import Dict, List

import httpx
import pytest

import mellophone
from mellophone import client as mellophone_client
from mellophone.utils import xml_to_json


class SyncClientStub:
    def __init__(self, response: httpx.Response, calls: List[Dict]):
        self.response = response
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def request(self, method, url, content=None, headers=None):
        self.calls.append({"method": method, "url": url, "content": content, "headers": headers})
        return self.response


class AsyncClientStub:
    def __init__(self, response: httpx.Response, calls: List[Dict]):
        self.response = response
        self.calls = calls

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def request(self, method, url, content=None, headers=None):
        self.calls.append({"method": method, "url": url, "content": content, "headers": headers})
        return self.response


class SyncTimeoutClientStub:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def request(self, method, url, content=None, headers=None):
        raise httpx.TimeoutException("timeout")


class AsyncTimeoutClientStub:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def request(self, method, url, content=None, headers=None):
        raise httpx.TimeoutException("timeout")


class RequestsSessionStub:
    def __init__(self, response, calls: List[Dict]):
        self.response = response
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def request(self, method, url, data=None, headers=None, timeout=None):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "content": data,
                "headers": headers,
                "timeout": timeout,
            }
        )
        return self.response


def _response(status_code: int, text: str = "", url: str = "http://test.local/"):
    return httpx.Response(status_code, text=text, request=httpx.Request("GET", url))


@pytest.fixture
def mock_sync_client(monkeypatch):
    def _install(response: httpx.Response) -> List[Dict]:
        calls: List[Dict] = []

        def client_factory(*_args, **_kwargs):
            return SyncClientStub(response, calls)

        monkeypatch.setattr(mellophone_client.httpx, "Client", client_factory)
        return calls

    return _install


@pytest.fixture
def mock_async_client(monkeypatch):
    def _install(response: httpx.Response) -> List[Dict]:
        calls: List[Dict] = []

        def async_client_factory(*_args, **_kwargs):
            return AsyncClientStub(response, calls)

        monkeypatch.setattr(mellophone_client.httpx, "AsyncClient", async_client_factory)
        return calls

    return _install


@pytest.fixture
def mock_requests_session(monkeypatch):
    def _install(response) -> List[Dict]:
        if mellophone_client.requests is None:
            pytest.skip("requests is not installed")
        calls: List[Dict] = []

        def session_factory(*_args, **_kwargs):
            return RequestsSessionStub(response, calls)

        monkeypatch.setattr(mellophone_client.requests, "Session", session_factory)
        return calls

    return _install


def test_xml_to_json_with_repeated_tags():
    xml = "<users><user login='a'/><user login='b'/></users>"
    result = xml_to_json(xml)
    assert result == {"users": {"user": [{"login": "a"}, {"login": "b"}]}}


def test_login_sync_sets_session_and_sends_request(mock_sync_client):
    calls = mock_sync_client(_response(200))

    client = mellophone.Mellophone("http://example.com", session_id=None)
    ses_id = client.login("john", "secret", ses_id="ses-1", gp="grp", ip="127.0.0.1")

    assert ses_id == "ses-1"
    assert client.session_id == "ses-1"
    assert calls
    assert calls[0]["method"] == "GET"
    assert "/login?" in calls[0]["url"]
    assert "sesid=ses-1" in calls[0]["url"]
    assert "login=john" in calls[0]["url"]


def test_is_authenticated_returns_false_on_forbidden(mock_sync_client):
    mock_sync_client(_response(403, "forbidden"))

    client = mellophone.Mellophone("http://example.com", session_id="ses-1")
    assert client.is_authenticated() is False


def test_bad_request_maps_to_domain_error(mock_sync_client):
    mock_sync_client(_response(400, "bad request"))

    client = mellophone.Mellophone("http://example.com")
    with pytest.raises(mellophone.BadRequestError) as exc:
        client.login("john", "secret", ses_id="ses-1")

    assert exc.value.status_code == 400


def test_server_error_maps_to_domain_error(mock_sync_client):
    mock_sync_client(_response(500, "server error"))

    client = mellophone.Mellophone("http://example.com")
    with pytest.raises(mellophone.ServerError) as exc:
        client.login("john", "secret", ses_id="ses-1")

    assert exc.value.status_code == 500


def test_create_user_converts_password_to_pwd_and_sends_xml(mock_sync_client):
    calls = mock_sync_client(_response(200, "<user sid='1' login='neo'/>"))

    client = mellophone.Mellophone(
        "http://example.com",
        user_manage_token="token-1",
    )
    client.create_user({"sid": "1", "login": "neo", "password": "1234"})
    assert calls
    assert calls[0]["method"] == "POST"
    assert "token=token-1" in calls[0]["url"]
    assert calls[0]["headers"] == {"Content-Type": "application/xml"}
    xml = ET.fromstring(calls[0]["content"])
    assert xml.tag == "user"
    assert xml.attrib["pwd"] == "1234"
    assert "password" not in xml.attrib


def test_set_settings_uses_client_token(mock_sync_client):
    calls = mock_sync_client(_response(200))

    client = mellophone.Mellophone("http://example.com", set_settings_token="set-token")
    client.set_settings(lockout_time=30, login_attempts_allowed=5)

    assert calls
    assert calls[0]["method"] == "GET"
    assert "/setsettings?" in calls[0]["url"]
    assert "token=set-token" in calls[0]["url"]
    assert "lockouttime=30" in calls[0]["url"]
    assert "loginattemptsallowed=5" in calls[0]["url"]


def test_update_user_uses_client_user_manage_token(mock_sync_client):
    calls = mock_sync_client(_response(200))

    client = mellophone.Mellophone("http://example.com", user_manage_token="token-1")
    client.update_user("u-1", {"sid": "u-1", "login": "neo", "pwd": "1234"})

    assert calls
    assert calls[0]["method"] == "POST"
    assert "/user/u-1?" in calls[0]["url"]
    assert "token=token-1" in calls[0]["url"]
    assert calls[0]["headers"] == {"Content-Type": "application/xml"}


def test_change_user_pwd_sends_expected_params(mock_sync_client):
    calls = mock_sync_client(_response(200))

    client = mellophone.Mellophone("http://example.com", session_id="ses-1")
    client.change_user_pwd("neo", "new-secret")

    assert calls
    assert calls[0]["method"] == "GET"
    assert "/changeuserpwd?" in calls[0]["url"]
    assert "sesid=ses-1" in calls[0]["url"]
    assert "username=neo" in calls[0]["url"]
    assert "newpwd=new-secret" in calls[0]["url"]
    assert "oldpwd=" not in calls[0]["url"]


def test_change_app_ses_id(mock_sync_client):
    calls = mock_sync_client(_response(200))

    client = mellophone.Mellophone("http://example.com", session_id="ses-self")
    client.change_app_ses_id("ses-new")
    client.change_app_ses_id("ses-foreign-new", ses_id="ses-foreign-old")

    assert client.session_id == "ses-new"
    assert len(calls) == 2
    assert "oldsesid=ses-self" in calls[0]["url"]
    assert "newsesid=ses-new" in calls[0]["url"]
    assert "oldsesid=ses-foreign-old" in calls[1]["url"]
    assert "newsesid=ses-foreign-new" in calls[1]["url"]


def test_delete_user(mock_sync_client):
    calls = mock_sync_client(_response(200))

    client = mellophone.Mellophone("http://example.com", user_manage_token="token-1")
    client.delete_user("u-1")

    assert calls
    assert calls[0]["method"] == "DELETE"
    assert "/user/u-1?" in calls[0]["url"]
    assert "token=token-1" in calls[0]["url"]


def test_set_state_and_get_state_sync(mock_sync_client):
    calls = mock_sync_client(_response(200, "state-value"))

    client = mellophone.Mellophone("http://example.com")
    client.set_state("ses-1", "new-state")
    state = client.get_state("ses-1")

    assert state == "state-value"
    assert len(calls) == 2
    assert calls[0]["method"] == "POST"
    assert "/setstate?" in calls[0]["url"]
    assert "sesid=ses-1" in calls[0]["url"]
    assert calls[0]["content"] == "new-state"
    assert calls[1]["method"] == "GET"
    assert "/getstate?" in calls[1]["url"]
    assert "sesid=ses-1" in calls[1]["url"]


def test_login_async_sets_session_and_sends_request(mock_async_client):
    calls = mock_async_client(_response(200))

    client = mellophone.Mellophone("http://example.com")
    ses_id = asyncio.run(client.login_async("john", "secret", ses_id="ses-async"))

    assert ses_id == "ses-async"
    assert client.session_id == "ses-async"
    assert calls
    assert calls[0]["method"] == "GET"
    assert "sesid=ses-async" in calls[0]["url"]


def test_check_credentials_async_parses_xml(mock_async_client):
    calls = mock_async_client(_response(200, "<user sid='1' login='neo'/>"))

    client = mellophone.Mellophone("http://example.com")
    result = asyncio.run(client.check_credentials_async("neo", "1234"))

    assert result == {"sid": "1", "login": "neo"}
    assert calls


def test_delete_user_async(mock_async_client):
    calls = mock_async_client(_response(200))

    client = mellophone.Mellophone("http://example.com", user_manage_token="token-2")
    asyncio.run(client.delete_user_async("u-2"))

    assert calls
    assert calls[0]["method"] == "DELETE"
    assert "/user/u-2?" in calls[0]["url"]
    assert "token=token-2" in calls[0]["url"]


def test_change_app_ses_id_async(mock_async_client):
    calls = mock_async_client(_response(200))

    client = mellophone.Mellophone("http://example.com", session_id="ses-self")
    asyncio.run(client.change_app_ses_id_async("ses-new"))
    asyncio.run(client.change_app_ses_id_async("ses-foreign-new", ses_id="ses-foreign-old"))

    assert client.session_id == "ses-new"
    assert len(calls) == 2
    assert "oldsesid=ses-self" in calls[0]["url"]
    assert "newsesid=ses-new" in calls[0]["url"]
    assert "oldsesid=ses-foreign-old" in calls[1]["url"]
    assert "newsesid=ses-foreign-new" in calls[1]["url"]


def test_set_state_and_get_state_async(mock_async_client):
    calls = mock_async_client(_response(200, "async-state"))

    client = mellophone.Mellophone("http://example.com")
    asyncio.run(client.set_state_async("ses-async", "payload"))
    state = asyncio.run(client.get_state_async("ses-async"))

    assert state == "async-state"
    assert len(calls) == 2
    assert calls[0]["method"] == "POST"
    assert "/setstate?" in calls[0]["url"]
    assert calls[0]["content"] == "payload"
    assert calls[1]["method"] == "GET"
    assert "/getstate?" in calls[1]["url"]


def test_parse_error_maps_to_response_parse_error(mock_sync_client):
    mock_sync_client(_response(200, "<user"))

    client = mellophone.Mellophone("http://example.com")
    with pytest.raises(mellophone.ResponseParseError):
        client.check_credentials("neo", "1234")


def test_sync_timeout_maps_to_request_timeout(monkeypatch):
    if mellophone_client.httpx is None:
        pytest.skip("httpx is not installed")

    def client_factory(*_args, **_kwargs):
        return SyncTimeoutClientStub()

    monkeypatch.setattr(mellophone_client.httpx, "Client", client_factory)

    client = mellophone.Mellophone("http://example.com")
    with pytest.raises(mellophone.RequestTimeoutError):
        client.login("john", "secret", ses_id="ses-1")


def test_async_timeout_maps_to_request_timeout(monkeypatch):
    if mellophone_client.httpx is None:
        pytest.skip("httpx is not installed")

    def async_client_factory(*_args, **_kwargs):
        return AsyncTimeoutClientStub()

    monkeypatch.setattr(mellophone_client.httpx, "AsyncClient", async_client_factory)

    client = mellophone.Mellophone("http://example.com")
    with pytest.raises(mellophone.RequestTimeoutError):
        asyncio.run(client.login_async("john", "secret", ses_id="ses-1"))


def test_sync_falls_back_to_requests_when_httpx_unavailable(monkeypatch, mock_requests_session):
    calls = mock_requests_session(_response(200))
    monkeypatch.setattr(mellophone_client, "httpx", None)

    client = mellophone.Mellophone("http://example.com")
    client.login("john", "secret", ses_id="ses-req")

    assert calls
    assert calls[0]["method"] == "GET"
    assert "sesid=ses-req" in calls[0]["url"]


def test_async_raises_without_httpx(monkeypatch):
    monkeypatch.setattr(mellophone_client, "httpx", None)

    client = mellophone.Mellophone("http://example.com")
    with pytest.raises(mellophone.AsyncClientUnavailableError):
        asyncio.run(client.login_async("john", "secret", ses_id="ses-async"))
