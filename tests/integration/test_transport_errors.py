from __future__ import annotations

import socket

import pytest

from mellophone import HttpError, Mellophone, NotFoundError, RequestTimeoutError, TransportError, UnauthorizedError


def _free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.mark.parametrize(
    ("path", "expected_exc", "expected_status"),
    [
        ("unauthorized", UnauthorizedError, 401),
        ("not-found", NotFoundError, 404),
        ("teapot", HttpError, 418),
    ],
)
def test_it_maps_http_errors(
    local_error_server: str, path: str, expected_exc: type[Exception], expected_status: int
) -> None:
    client = Mellophone(local_error_server)
    with pytest.raises(expected_exc) as exc:
        client._request_text(path)
    assert getattr(exc.value, "status_code", None) == expected_status


def test_it_maps_request_timeout_error(local_error_server: str) -> None:
    client = Mellophone(local_error_server, timeout=0.01)
    with pytest.raises(RequestTimeoutError):
        client._request_text("slow")


def test_it_maps_transport_error() -> None:
    port = _free_tcp_port()
    client = Mellophone(f"http://127.0.0.1:{port}")
    with pytest.raises(TransportError):
        client._request_text("down")
