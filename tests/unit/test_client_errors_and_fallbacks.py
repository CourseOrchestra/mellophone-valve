import asyncio

import httpx
import pytest

import mellophone
from mellophone import client as mellophone_client


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


def test_sync_falls_back_to_requests_when_httpx_unavailable(monkeypatch, mock_requests_session, response_factory):
    calls = mock_requests_session(response_factory(200))
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


def test_set_settings_raises_when_set_settings_token_missing():
    client = mellophone.Mellophone("http://example.com")
    with pytest.raises(mellophone.MissingTokenError) as exc:
        client.set_settings(lockout_time=5)
    assert "token_set_settings" in str(exc.value)


def test_user_manage_methods_raise_when_user_manage_token_missing():
    client = mellophone.Mellophone("http://example.com")

    with pytest.raises(mellophone.MissingTokenError):
        client.get_user_list(gp="group-1")
    with pytest.raises(mellophone.MissingTokenError):
        client.create_user({"sid": "1", "login": "neo", "password": "1234"})
    with pytest.raises(mellophone.MissingTokenError):
        client.update_user("1", {"sid": "1", "login": "neo", "pwd": "1234"})
    with pytest.raises(mellophone.MissingTokenError):
        client.delete_user("1")
