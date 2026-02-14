from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass
from http import HTTPStatus
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlencode
from uuid import uuid4

from .exceptions import (
    AsyncClientUnavailableError,
    BadRequestError,
    ForbiddenError,
    HttpError,
    NotFoundError,
    RequestTimeoutError,
    ResponseParseError,
    ServerError,
    TransportError,
    UnauthorizedError,
)
from .structures import RequestArgs, RequestParams
from .utils import user_to_xml, xml_to_json

try:
    import httpx
except ImportError:  # pragma: no cover - depends on installed extra
    httpx = None  # type: ignore[assignment]

try:
    import requests
except ImportError:  # pragma: no cover - depends on installed extra
    requests = None  # type: ignore[assignment]


@dataclass
class Mellophone:
    """Unified Mellophone client with sync and async methods."""

    base_url: str
    set_settings_token: Optional[str] = None
    user_manage_token: Optional[str] = None
    session_id: Optional[str] = None
    timeout: float = 10.0

    def _build_url(self, path: str, params: Optional[Dict[str, Any]] = None) -> str:
        if not isinstance(path, str):
            raise TypeError("path must be str")
        path = "/" + path.strip("/")
        if not params:
            return f"{self.base_url}{path}"
        clean = {k: v for k, v in params.items() if v is not None}
        return f"{self.base_url}{path}?{urlencode(clean)}"

    @staticmethod
    def _raise_for_status(response: Any) -> None:
        status_code = int(response.status_code)
        response_text = response.text

        if status_code == HTTPStatus.BAD_REQUEST:
            raise BadRequestError(status_code, response_text)
        if status_code == HTTPStatus.UNAUTHORIZED:
            raise UnauthorizedError(status_code, response_text)
        if status_code == HTTPStatus.FORBIDDEN:
            raise ForbiddenError(status_code, response_text)
        if status_code == HTTPStatus.NOT_FOUND:
            raise NotFoundError(status_code, response_text)
        if HTTPStatus.INTERNAL_SERVER_ERROR <= status_code <= 599:
            raise ServerError(status_code, response_text)
        if status_code >= HTTPStatus.BAD_REQUEST:
            raise HttpError(status_code, response_text)

    @staticmethod
    def _ensure_sync_backend() -> None:
        if httpx is None and requests is None:
            raise RuntimeError(
                "No HTTP client is installed. Install mellophone-valve[httpx] or mellophone-valve[requests]."
            )

    def _request_text(
        self,
        path: str,
        *,
        method: str = "GET",
        params: Optional[Dict[str, Any]] = None,
        data: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> str:
        self._ensure_sync_backend()
        url = self._build_url(path, params)

        if httpx is not None:
            try:
                with httpx.Client(timeout=self.timeout) as client:
                    response = client.request(method, url, content=data, headers=headers)
            except httpx.TimeoutException as exc:
                raise RequestTimeoutError("HTTP request timeout exceeded.") from exc
            except httpx.HTTPError as exc:
                raise TransportError("HTTP transport error in httpx client.") from exc
        else:
            try:
                with requests.Session() as session:  # type: ignore[union-attr]
                    response = session.request(method, url, data=data, headers=headers, timeout=self.timeout)
            except requests.Timeout as exc:  # type: ignore[union-attr]
                raise RequestTimeoutError("HTTP request timeout exceeded.") from exc
            except requests.RequestException as exc:  # type: ignore[union-attr]
                raise TransportError("HTTP transport error in requests client.") from exc

        self._raise_for_status(response)
        return response.text

    async def _request_text_async(
        self,
        path: str,
        *,
        method: str = "GET",
        params: Optional[Dict[str, Any]] = None,
        data: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> str:
        if httpx is None:
            raise AsyncClientUnavailableError("Async methods require httpx. Install mellophone-valve[httpx].")

        url = self._build_url(path, params)
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.request(method, url, content=data, headers=headers)
        except httpx.TimeoutException as exc:
            raise RequestTimeoutError("HTTP request timeout exceeded.") from exc
        except httpx.HTTPError as exc:
            raise TransportError("HTTP transport error in httpx client.") from exc

        self._raise_for_status(response)
        return response.text

    @staticmethod
    def _as_json(response_text: str) -> Dict[str, Any]:
        if not response_text.strip():
            return {}
        try:
            return xml_to_json(response_text)
        except ET.ParseError as exc:
            raise ResponseParseError("Failed to parse API XML response.") from exc

    @staticmethod
    def _require_user(user: Dict[str, Any]) -> Dict[str, Any]:
        if not user:
            raise ValueError("user data cannot be empty")
        payload = dict(user)
        if "password" in payload:
            payload["pwd"] = payload.pop("password")
        return payload

    @staticmethod
    def _login_props(
        login: str,
        password: str,
        ses_id: Optional[str] = None,
        gp: Optional[str] = None,
        ip: Optional[str] = None,
    ) -> RequestParams:
        return RequestParams(
            path="login",
            params={
                "sesid": ses_id,
                "login": login,
                "pwd": password,
                "gp": gp,
                "ip": ip,
            },
        )

    def login(
        self,
        login: str,
        password: str,
        ses_id: Optional[str] = None,
        gp: Optional[str] = None,
        ip: Optional[str] = None,
    ) -> str:
        ses_id = ses_id or self.session_id or str(uuid4())
        self._request_text(**self._login_props(login, password, ses_id, gp, ip))
        self.session_id = ses_id
        return ses_id

    async def login_async(
        self,
        login: str,
        password: str,
        ses_id: Optional[str] = None,
        gp: Optional[str] = None,
        ip: Optional[str] = None,
    ) -> str:
        ses_id = ses_id or self.session_id or str(uuid4())
        await self._request_text_async(**self._login_props(login, password, ses_id, gp, ip))
        self.session_id = ses_id
        return ses_id

    @staticmethod
    def _logout_props(ses_id: Optional[str] = None) -> RequestParams:
        return RequestParams(path="logout", params={"sesid": ses_id})

    def logout(self, ses_id: Optional[str] = None) -> None:
        self._request_text(**self._logout_props(ses_id or self.session_id))

    async def logout_async(self, ses_id: Optional[str] = None) -> None:
        await self._request_text_async(**self._logout_props(ses_id or self.session_id))

    @staticmethod
    def _is_authenticated_props(ses_id: Optional[str]) -> RequestParams:
        return RequestParams(path="isauthenticated", params={"sesid": ses_id})

    def is_authenticated(self, ses_id: Optional[str] = None) -> Union[Dict[str, Any], bool]:
        try:
            response = self._request_text(**self._is_authenticated_props(ses_id or self.session_id))
        except ForbiddenError:
            return False
        return self._as_json(response).get("user", {})

    async def is_authenticated_async(self, ses_id: Optional[str] = None) -> Union[Dict[str, Any], bool]:
        try:
            response = await self._request_text_async(**self._is_authenticated_props(ses_id or self.session_id))
        except ForbiddenError:
            return False
        return self._as_json(response).get("user", {})

    @staticmethod
    def _check_credentials_props(
        login: str,
        password: str,
        gp: Optional[str] = None,
        ip: Optional[str] = None,
    ) -> RequestParams:
        return RequestParams(
            path="checkcredentials",
            params={"login": login, "pwd": password, "gp": gp, "ip": ip},
        )

    def check_credentials(
        self,
        login: str,
        password: str,
        gp: Optional[str] = None,
        ip: Optional[str] = None,
    ) -> Dict[str, Any]:
        response = self._request_text(**self._check_credentials_props(login, password, gp, ip))
        return self._as_json(response).get("user", {})

    async def check_credentials_async(
        self,
        login: str,
        password: str,
        gp: Optional[str] = None,
        ip: Optional[str] = None,
    ) -> Dict[str, Any]:
        response = await self._request_text_async(**self._check_credentials_props(login, password, gp, ip))
        return self._as_json(response).get("user", {})

    @staticmethod
    def _check_name_props(name: str, ses_id: Optional[str]) -> RequestParams:
        return RequestParams(path="checkname", params={"sesid": ses_id, "name": name})

    def check_name(self, name: str, ses_id: Optional[str] = None) -> Dict[str, Any]:
        response = self._request_text(**self._check_name_props(name, ses_id or self.session_id))
        return self._as_json(response).get("user", {})

    async def check_name_async(self, name: str, ses_id: Optional[str] = None) -> Dict[str, Any]:
        response = await self._request_text_async(**self._check_name_props(name, ses_id or self.session_id))
        return self._as_json(response).get("user", {})

    @staticmethod
    def _change_pwd_props(old_pwd: str, new_pwd: str, ses_id: Optional[str]) -> RequestParams:
        return RequestParams(
            path="changepwd",
            params={
                "sesid": ses_id,
                "oldpwd": old_pwd,
                "newpwd": new_pwd,
            },
        )

    def change_pwd(self, old_pwd: str, new_pwd: str, ses_id: Optional[str] = None) -> None:
        self._request_text(**self._change_pwd_props(old_pwd, new_pwd, ses_id or self.session_id))

    async def change_pwd_async(self, old_pwd: str, new_pwd: str, ses_id: Optional[str] = None) -> None:
        await self._request_text_async(**self._change_pwd_props(old_pwd, new_pwd, ses_id or self.session_id))

    @staticmethod
    def _change_user_pwd_props(
        username: str,
        old_pwd: str,
        new_pwd: str,
        ses_id: Optional[str],
    ) -> RequestParams:
        return RequestParams(
            path="changeuserpwd",
            params={
                "sesid": ses_id,
                "oldpwd": old_pwd,
                "newpwd": new_pwd,
                "username": username,
            },
        )

    def change_user_pwd(self, username: str, old_pwd: str, new_pwd: str, ses_id: Optional[str] = None) -> None:
        self._request_text(**self._change_user_pwd_props(username, old_pwd, new_pwd, ses_id or self.session_id))

    async def change_user_pwd_async(
        self, username: str, old_pwd: str, new_pwd: str, ses_id: Optional[str] = None
    ) -> None:
        await self._request_text_async(
            **self._change_user_pwd_props(username, old_pwd, new_pwd, ses_id or self.session_id)
        )

    @staticmethod
    def _change_app_ses_id_props(new_ses_id: str, ses_id: Optional[str]) -> RequestParams:
        return RequestParams(
            path="changeappsesid",
            params={"oldsesid": ses_id, "newsesid": new_ses_id},
        )

    def change_app_ses_id(self, new_ses_id: str, ses_id: Optional[str] = None) -> None:
        self._request_text(**self._change_app_ses_id_props(new_ses_id, ses_id or self.session_id))
        self.session_id = new_ses_id

    async def change_app_ses_id_async(self, new_ses_id: str, ses_id: Optional[str] = None) -> None:
        await self._request_text_async(**self._change_app_ses_id_props(new_ses_id, ses_id or self.session_id))
        self.session_id = new_ses_id

    @staticmethod
    def _import_gp_props() -> RequestParams:
        return RequestParams(path="importgroupsproviders", params={})

    def import_gp(self) -> List[str]:
        return self._request_text(**self._import_gp_props()).split()

    async def import_gp_async(self) -> List[str]:
        response = await self._request_text_async(**self._import_gp_props())
        return response.split()

    @staticmethod
    def _get_provider_list_props(
        login: str,
        password: str,
        gp: Optional[str] = None,
        ip: Optional[str] = None,
    ) -> RequestParams:
        return RequestParams(
            path="getproviderlist",
            params={"login": login, "pwd": password, "gp": gp, "ip": ip},
        )

    def get_provider_list(
        self,
        login: str,
        password: str,
        gp: Optional[str] = None,
        ip: Optional[str] = None,
    ) -> Dict[str, Any]:
        response = self._request_text(**self._get_provider_list_props(login, password, gp, ip))
        return self._as_json(response).get("providers", {})

    async def get_provider_list_async(
        self,
        login: str,
        password: str,
        gp: Optional[str] = None,
        ip: Optional[str] = None,
    ) -> Dict[str, Any]:
        response = await self._request_text_async(**self._get_provider_list_props(login, password, gp, ip))
        return self._as_json(response).get("providers", {})

    @staticmethod
    def _get_user_list_props(
        token: str,
        gp: str,
        ip: Optional[str] = None,
        pid: Optional[str] = None,
    ) -> RequestParams:
        return RequestParams(
            path="getuserlist",
            params={"token": token, "gp": gp, "ip": ip, "pid": pid},
        )

    def get_user_list(self, token: str, gp: str, ip: Optional[str] = None, pid: Optional[str] = None) -> Dict[str, Any]:
        response = self._request_text(**self._get_user_list_props(token, gp, ip, pid))
        return self._as_json(response)

    async def get_user_list_async(
        self, token: str, gp: str, ip: Optional[str] = None, pid: Optional[str] = None
    ) -> Dict[str, Any]:
        response = await self._request_text_async(**self._get_user_list_props(token, gp, ip, pid))
        return self._as_json(response)

    def _set_settings_props(
        self,
        token: Optional[str] = None,
        lockout_time: Optional[int] = None,
        login_attempts_allowed: Optional[int] = None,
    ) -> RequestParams:
        return RequestParams(
            path="setsettings",
            params={
                "token": token or self.set_settings_token,
                "lockouttime": lockout_time,
                "loginattemptsallowed": login_attempts_allowed,
            },
        )

    def set_settings(
        self,
        token: Optional[str] = None,
        lockout_time: Optional[int] = None,
        login_attempts_allowed: Optional[int] = None,
    ) -> None:
        self._request_text(**self._set_settings_props(token, lockout_time, login_attempts_allowed))

    async def set_settings_async(
        self,
        token: Optional[str] = None,
        lockout_time: Optional[int] = None,
        login_attempts_allowed: Optional[int] = None,
    ) -> None:
        await self._request_text_async(**self._set_settings_props(token, lockout_time, login_attempts_allowed))

    def _create_user_props(self, payload: Dict[str, Any], token: Optional[str] = None) -> RequestArgs:
        return RequestArgs(
            path="user/create",
            method="POST",
            params={"token": token or self.user_manage_token},
            data=user_to_xml(payload),
            headers={"Content-Type": "application/xml"},
        )

    def create_user(self, user: Dict[str, Any], token: Optional[str] = None) -> None:
        payload = self._require_user(user)
        self._request_text(**self._create_user_props(payload, token))

    async def create_user_async(self, user: Dict[str, Any], token: Optional[str] = None) -> None:
        payload = self._require_user(user)
        await self._request_text_async(**self._create_user_props(payload, token))

    @staticmethod
    def _update_user_props(sid: str, token: str, user: Dict[str, Any]) -> RequestArgs:
        return RequestArgs(
            path=f"/user/{sid}",
            method="POST",
            params={"token": token},
            data=user_to_xml(user),
            headers={"Content-Type": "application/xml"},
        )

    def update_user(self, sid: str, token: str, user: Dict[str, Any]) -> None:
        self._request_text(**self._update_user_props(sid, token, user))

    async def update_user_async(self, sid: str, token: str, user: Dict[str, Any]) -> None:
        await self._request_text_async(**self._update_user_props(sid, token, user))


__all__ = [
    "Mellophone",
    "RequestParams",
    "RequestArgs",
    "xml_to_json",
    "httpx",
    "requests",
    "HttpError",
    "BadRequestError",
    "UnauthorizedError",
    "ForbiddenError",
    "NotFoundError",
    "ServerError",
    "AsyncClientUnavailableError",
    "TransportError",
    "RequestTimeoutError",
    "ResponseParseError",
]
