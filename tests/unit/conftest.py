import httpx
import pytest

from mellophone import client as mellophone_client


class SyncClientStub:
    def __init__(self, response, calls):
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
    def __init__(self, response, calls):
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
    def __init__(self, response, calls):
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


@pytest.fixture
def response_factory():
    def _factory(status_code, text="", url="http://test.local/"):
        return httpx.Response(status_code, text=text, request=httpx.Request("GET", url))

    return _factory


@pytest.fixture
def mock_sync_client(monkeypatch):
    def _install(response):
        calls = []

        def client_factory(*_args, **_kwargs):
            return SyncClientStub(response, calls)

        monkeypatch.setattr(mellophone_client.httpx, "Client", client_factory)
        return calls

    return _install


@pytest.fixture
def mock_async_client(monkeypatch):
    def _install(response):
        calls = []

        def async_client_factory(*_args, **_kwargs):
            return AsyncClientStub(response, calls)

        monkeypatch.setattr(mellophone_client.httpx, "AsyncClient", async_client_factory)
        return calls

    return _install


@pytest.fixture
def mock_requests_session(monkeypatch):
    def _install(response):
        if mellophone_client.requests is None:
            pytest.skip("requests is not installed")
        calls = []

        def session_factory(*_args, **_kwargs):
            return RequestsSessionStub(response, calls)

        monkeypatch.setattr(mellophone_client.requests, "Session", session_factory)
        return calls

    return _install
