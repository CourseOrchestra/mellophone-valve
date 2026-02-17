from __future__ import annotations

import threading
import time
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Iterator, Tuple
from uuid import uuid4

import httpx
import pytest
import yaml

from mellophone import Mellophone

ROOT = Path(__file__).resolve().parents[2]
DOCKER_COMPOSE_PATH = ROOT / "docker-compose.yml"
MELLOPHONE_CONFIG_PATH = ROOT / "docker-config" / "config.xml"


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


@pytest.fixture(scope="session")
def integration_base_url() -> str:
    base_url = _extract_base_url_from_compose()
    _ensure_service_reachable(base_url)
    return base_url


@pytest.fixture(scope="session")
def integration_tokens() -> Tuple[str, str]:
    return _extract_tokens_from_config()


@pytest.fixture
def integration_client(integration_base_url: str, integration_tokens: Tuple[str, str]) -> Mellophone:
    set_token, user_token = integration_tokens
    return Mellophone(
        base_url=integration_base_url,
        token_set_settings=set_token,
        token_user_manage=user_token,
    )


@pytest.fixture
def integration_user(integration_client: Mellophone) -> Dict[str, str]:
    unique = uuid4().hex[:8]
    sid = f"it-real-{unique}"
    login = f"it_real_{unique}"
    password = "pwd_1"
    integration_client.create_user({"sid": sid, "login": login, "password": password})
    return {"sid": sid, "login": login, "password": password}


@pytest.fixture
def local_error_server() -> Iterator[str]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path.startswith("/unauthorized"):
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b"unauthorized")
                return
            if self.path.startswith("/not-found"):
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"not found")
                return
            if self.path.startswith("/teapot"):
                self.send_response(418)
                self.end_headers()
                self.wfile.write(b"teapot")
                return
            if self.path.startswith("/slow"):
                time.sleep(0.2)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"slow-ok")
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address  # ty:ignore[invalid-assignment]
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        thread.join(timeout=1)
