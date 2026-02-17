from __future__ import annotations

import warnings
import xml.etree.ElementTree as ET
from http import HTTPStatus
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlencode
from uuid import uuid4

from .exceptions import (
    AsyncClientUnavailableError,
    BadRequestError,
    ForbiddenError,
    HttpError,
    MissingTokenError,
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


class Mellophone:
    """Единый клиент Mellophone с синхронными и асинхронными методами."""

    base_url: str
    token_set_settings: Optional[str]
    token_user_manage: Optional[str]
    session_id: Optional[str]
    timeout: float

    def __init__(
        self,
        base_url: str,
        token_set_settings: Optional[str] = None,
        token_user_manage: Optional[str] = None,
        session_id: Optional[str] = None,
        timeout: float = 10.0,
        set_settings_token: Optional[str] = None,
        user_manage_token: Optional[str] = None,
    ) -> None:
        """Инициализирует клиент и поддерживает устаревшие имена токенов."""
        if set_settings_token is not None:
            warnings.warn(
                "`set_settings_token` is deprecated, use `token_set_settings`.",
                DeprecationWarning,
                stacklevel=2,
            )
            if token_set_settings is None:
                token_set_settings = set_settings_token
        if user_manage_token is not None:
            warnings.warn(
                "`user_manage_token` is deprecated, use `token_user_manage`.",
                DeprecationWarning,
                stacklevel=2,
            )
            if token_user_manage is None:
                token_user_manage = user_manage_token

        self.base_url = base_url
        self.token_set_settings = token_set_settings
        self.token_user_manage = token_user_manage
        self.session_id = session_id
        self.timeout = timeout

    @property
    def set_settings_token(self) -> Optional[str]:
        """Устаревший алиас для token_set_settings."""
        warnings.warn(
            "`set_settings_token` is deprecated, use `token_set_settings`.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.token_set_settings

    @set_settings_token.setter
    def set_settings_token(self, value: Optional[str]) -> None:
        """Устаревший сеттер для token_set_settings."""
        warnings.warn(
            "`set_settings_token` is deprecated, use `token_set_settings`.",
            DeprecationWarning,
            stacklevel=2,
        )
        self.token_set_settings = value

    @property
    def user_manage_token(self) -> Optional[str]:
        """Устаревший алиас для token_user_manage."""
        warnings.warn(
            "`user_manage_token` is deprecated, use `token_user_manage`.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.token_user_manage

    @user_manage_token.setter
    def user_manage_token(self, value: Optional[str]) -> None:
        """Устаревший сеттер для token_user_manage."""
        warnings.warn(
            "`user_manage_token` is deprecated, use `token_user_manage`.",
            DeprecationWarning,
            stacklevel=2,
        )
        self.token_user_manage = value

    def _build_url(self, path: str, params: Optional[Dict[str, Any]] = None) -> str:
        """Собирает полный URL запроса с query-параметрами."""
        if not isinstance(path, str):
            raise TypeError("path must be str")
        path = "/" + path.strip("/")
        if not params:
            return f"{self.base_url}{path}"
        clean = {k: v for k, v in params.items() if v is not None}
        return f"{self.base_url}{path}?{urlencode(clean)}"

    @staticmethod
    def _raise_for_status(response: Any) -> None:
        """Выбрасывает доменное исключение для неуспешных HTTP-статусов."""
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
        """Проверяет, что установлен хотя бы один sync HTTP-бэкенд."""
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
        """Выполняет sync HTTP-запрос и возвращает текст ответа."""
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
                with requests.Session() as session:
                    response = session.request(method, url, data=data, headers=headers, timeout=self.timeout)
            except requests.Timeout as exc:
                raise RequestTimeoutError("HTTP request timeout exceeded.") from exc
            except requests.RequestException as exc:
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
        """Выполняет async HTTP-запрос и возвращает текст ответа."""
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
        """Парсит XML-текст ответа в словарь."""
        if not response_text.strip():
            return {}
        try:
            return xml_to_json(response_text)
        except ET.ParseError as exc:
            raise ResponseParseError("Failed to parse API XML response.") from exc

    @staticmethod
    def _require_user(user: Dict[str, Any]) -> Dict[str, Any]:
        """Проверяет и нормализует payload пользователя для API-вызовов."""
        if not user:
            raise ValueError("user data cannot be empty")
        payload = dict(user)
        if "password" in payload:
            payload["pwd"] = payload.pop("password")
        return payload

    @staticmethod
    def _require_token(token: Optional[str], *, field_name: str) -> str:
        """Возвращает обязательный токен или выбрасывает MissingTokenError."""
        if token:
            return token
        raise MissingTokenError(f"{field_name} is required on Mellophone client.")

    def _require_session_id(self, ses_id: Optional[str] = None) -> str:
        """Определяет session id из аргумента или состояния клиента."""
        resolved_ses_id = ses_id or self.session_id
        if resolved_ses_id:
            return resolved_ses_id
        raise ValueError("ses_id is required. Pass ses_id explicitly or call login first.")

    @staticmethod
    def _login_props(
        login: str,
        password: str,
        ses_id: Optional[str] = None,
        gp: Optional[str] = None,
        ip: Optional[str] = None,
    ) -> RequestParams:
        """Формирует параметры запроса для endpoint `login`."""
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
        """Аутентифицирует пользователя и сохраняет session id в клиенте."""
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
        """Асинхронно аутентифицирует пользователя и сохраняет session id."""
        ses_id = ses_id or self.session_id or str(uuid4())
        await self._request_text_async(**self._login_props(login, password, ses_id, gp, ip))
        self.session_id = ses_id
        return ses_id

    @staticmethod
    def _logout_props(ses_id: Optional[str] = None) -> RequestParams:
        """Формирует параметры запроса для endpoint `logout`."""
        return RequestParams(path="logout", params={"sesid": ses_id})

    def logout(self, ses_id: Optional[str] = None) -> None:
        """Завершает текущую или явно переданную сессию."""
        resolved_ses_id = self._require_session_id(ses_id)
        self._request_text(**self._logout_props(resolved_ses_id))

    async def logout_async(self, ses_id: Optional[str] = None) -> None:
        """Асинхронно завершает текущую или явно переданную сессию."""
        resolved_ses_id = self._require_session_id(ses_id)
        await self._request_text_async(**self._logout_props(resolved_ses_id))

    @staticmethod
    def _is_authenticated_props(ses_id: Optional[str]) -> RequestParams:
        """Формирует параметры запроса для проверки аутентификации."""
        return RequestParams(path="isauthenticated", params={"sesid": ses_id})

    def is_authenticated(self, ses_id: Optional[str] = None) -> Union[Dict[str, Any], bool]:
        """Проверяет, аутентифицирована ли сессия."""
        resolved_ses_id = self._require_session_id(ses_id)
        try:
            response = self._request_text(**self._is_authenticated_props(resolved_ses_id))
        except ForbiddenError:
            return False
        return self._as_json(response).get("user", {})

    async def is_authenticated_async(self, ses_id: Optional[str] = None) -> Union[Dict[str, Any], bool]:
        """Асинхронно проверяет, аутентифицирована ли сессия."""
        resolved_ses_id = self._require_session_id(ses_id)
        try:
            response = await self._request_text_async(**self._is_authenticated_props(resolved_ses_id))
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
        """Формирует параметры запроса для проверки учетных данных."""
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
        """Проверяет учетные данные и возвращает данные пользователя."""
        response = self._request_text(**self._check_credentials_props(login, password, gp, ip))
        return self._as_json(response).get("user", {})

    async def check_credentials_async(
        self,
        login: str,
        password: str,
        gp: Optional[str] = None,
        ip: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Асинхронно проверяет учетные данные и возвращает данные пользователя."""
        response = await self._request_text_async(**self._check_credentials_props(login, password, gp, ip))
        return self._as_json(response).get("user", {})

    @staticmethod
    def _check_name_props(name: str, ses_id: Optional[str]) -> RequestParams:
        """Формирует параметры запроса для проверки доступности имени."""
        return RequestParams(path="checkname", params={"sesid": ses_id, "name": name})

    def check_name(self, name: str, ses_id: Optional[str] = None) -> Dict[str, Any]:
        """Проверяет доступность имени пользователя для сессии."""
        resolved_ses_id = self._require_session_id(ses_id)
        response = self._request_text(**self._check_name_props(name, resolved_ses_id))
        return self._as_json(response).get("user", {})

    async def check_name_async(self, name: str, ses_id: Optional[str] = None) -> Dict[str, Any]:
        """Асинхронно проверяет доступность имени пользователя для сессии."""
        resolved_ses_id = self._require_session_id(ses_id)
        response = await self._request_text_async(**self._check_name_props(name, resolved_ses_id))
        return self._as_json(response).get("user", {})

    @staticmethod
    def _change_pwd_props(old_pwd: str, new_pwd: str, ses_id: Optional[str]) -> RequestParams:
        """Формирует параметры запроса для смены пароля текущего пользователя."""
        return RequestParams(
            path="changepwd",
            params={
                "sesid": ses_id,
                "oldpwd": old_pwd,
                "newpwd": new_pwd,
            },
        )

    def change_pwd(self, old_pwd: str, new_pwd: str, ses_id: Optional[str] = None) -> None:
        """Меняет пароль текущего аутентифицированного пользователя."""
        resolved_ses_id = self._require_session_id(ses_id)
        self._request_text(**self._change_pwd_props(old_pwd, new_pwd, resolved_ses_id))

    async def change_pwd_async(self, old_pwd: str, new_pwd: str, ses_id: Optional[str] = None) -> None:
        """Асинхронно меняет пароль текущего пользователя."""
        resolved_ses_id = self._require_session_id(ses_id)
        await self._request_text_async(**self._change_pwd_props(old_pwd, new_pwd, resolved_ses_id))

    @staticmethod
    def _change_user_pwd_props(
        username: str,
        new_pwd: str,
        ses_id: Optional[str],
    ) -> RequestParams:
        """Формирует параметры запроса для смены пароля пользователя по имени."""
        return RequestParams(
            path="changeuserpwd",
            params={
                "sesid": ses_id,
                "newpwd": new_pwd,
                "username": username,
            },
        )

    def change_user_pwd(self, username: str, new_pwd: str, ses_id: Optional[str] = None) -> None:
        """Меняет пароль пользователя, указанного по имени."""
        resolved_ses_id = self._require_session_id(ses_id)
        self._request_text(**self._change_user_pwd_props(username, new_pwd, resolved_ses_id))

    async def change_user_pwd_async(self, username: str, new_pwd: str, ses_id: Optional[str] = None) -> None:
        """Асинхронно меняет пароль пользователя по имени."""
        resolved_ses_id = self._require_session_id(ses_id)
        await self._request_text_async(**self._change_user_pwd_props(username, new_pwd, resolved_ses_id))

    @staticmethod
    def _change_app_ses_id_props(new_ses_id: str, ses_id: Optional[str]) -> RequestParams:
        """Формирует параметры запроса для смены session id."""
        return RequestParams(
            path="changeappsesid",
            params={"oldsesid": ses_id, "newsesid": new_ses_id},
        )

    def change_app_ses_id(self, new_ses_id: str, ses_id: Optional[str] = None) -> None:
        """Заменяет существующий session id на новый."""
        resolved_ses_id = self._require_session_id(ses_id)
        self._request_text(**self._change_app_ses_id_props(new_ses_id, resolved_ses_id))
        if ses_id is None:
            self.session_id = new_ses_id

    async def change_app_ses_id_async(self, new_ses_id: str, ses_id: Optional[str] = None) -> None:
        """Асинхронно заменяет существующий session id на новый."""
        resolved_ses_id = self._require_session_id(ses_id)
        await self._request_text_async(**self._change_app_ses_id_props(new_ses_id, resolved_ses_id))
        if ses_id is None:
            self.session_id = new_ses_id

    @staticmethod
    def _import_gp_props() -> RequestParams:
        """Формирует параметры запроса для импорта групп и провайдеров."""
        return RequestParams(path="importgroupsproviders", params={})

    def import_gp(self) -> List[str]:
        """Импортирует группы/провайдеров и возвращает их идентификаторы."""
        return self._request_text(**self._import_gp_props()).split()

    async def import_gp_async(self) -> List[str]:
        """Асинхронно импортирует группы/провайдеров и возвращает идентификаторы."""
        response = await self._request_text_async(**self._import_gp_props())
        return response.split()

    @staticmethod
    def _get_provider_list_props(
        login: str,
        password: str,
        gp: Optional[str] = None,
        ip: Optional[str] = None,
    ) -> RequestParams:
        """Формирует параметры запроса для получения списка провайдеров."""
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
        """Возвращает доступных провайдеров для заданных учетных данных и контекста."""
        response = self._request_text(**self._get_provider_list_props(login, password, gp, ip))
        return self._as_json(response).get("providers", {})

    async def get_provider_list_async(
        self,
        login: str,
        password: str,
        gp: Optional[str] = None,
        ip: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Асинхронно возвращает провайдеров для заданных данных и контекста."""
        response = await self._request_text_async(**self._get_provider_list_props(login, password, gp, ip))
        return self._as_json(response).get("providers", {})

    @staticmethod
    def _get_user_list_props(token: str, gp: str, ip: Optional[str] = None, pid: Optional[str] = None) -> RequestParams:
        """Формирует параметры запроса для получения списка пользователей."""
        return RequestParams(
            path="getuserlist",
            params={"token": token, "gp": gp, "ip": ip, "pid": pid},
        )

    def get_user_list(self, gp: str, ip: Optional[str] = None, pid: Optional[str] = None) -> Dict[str, Any]:
        """Возвращает список пользователей для провайдера и дополнительных фильтров."""
        token = self._require_token(self.token_user_manage, field_name="token_user_manage")
        response = self._request_text(**self._get_user_list_props(token, gp, ip, pid))
        return self._as_json(response)

    async def get_user_list_async(self, gp: str, ip: Optional[str] = None, pid: Optional[str] = None) -> Dict[str, Any]:
        """Асинхронно возвращает список пользователей для провайдера и фильтров."""
        token = self._require_token(self.token_user_manage, field_name="token_user_manage")
        response = await self._request_text_async(**self._get_user_list_props(token, gp, ip, pid))
        return self._as_json(response)

    def _set_settings_props(
        self,
        lockout_time: Optional[int] = None,
        login_attempts_allowed: Optional[int] = None,
    ) -> RequestParams:
        """Формирует параметры запроса для обновления настроек сервиса."""
        token = self._require_token(self.token_set_settings, field_name="token_set_settings")
        return RequestParams(
            path="setsettings",
            params={
                "token": token,
                "lockouttime": lockout_time,
                "loginattemptsallowed": login_attempts_allowed,
            },
        )

    def set_settings(
        self,
        lockout_time: Optional[int] = None,
        login_attempts_allowed: Optional[int] = None,
    ) -> None:
        """Обновляет настройки сервиса."""
        self._request_text(**self._set_settings_props(lockout_time, login_attempts_allowed))

    async def set_settings_async(
        self,
        lockout_time: Optional[int] = None,
        login_attempts_allowed: Optional[int] = None,
    ) -> None:
        """Асинхронно обновляет настройки сервиса."""
        await self._request_text_async(**self._set_settings_props(lockout_time, login_attempts_allowed))

    def _create_user_props(self, payload: Dict[str, Any]) -> RequestArgs:
        """Формирует аргументы запроса для создания пользователя."""
        token = self._require_token(self.token_user_manage, field_name="token_user_manage")
        return RequestArgs(
            path="user/create",
            method="POST",
            params={"token": token},
            data=user_to_xml(payload),
            headers={"Content-Type": "application/xml"},
        )

    def create_user(self, user: Dict[str, Any]) -> None:
        """Создает пользователя из переданного payload."""
        payload = self._require_user(user)
        self._request_text(**self._create_user_props(payload))

    async def create_user_async(self, user: Dict[str, Any]) -> None:
        """Асинхронно создает пользователя из переданного payload."""
        payload = self._require_user(user)
        await self._request_text_async(**self._create_user_props(payload))

    def _update_user_props(self, sid: str, user: Dict[str, Any]) -> RequestArgs:
        """Формирует аргументы запроса для обновления пользователя."""
        token = self._require_token(self.token_user_manage, field_name="token_user_manage")
        return RequestArgs(
            path=f"/user/{sid}",
            method="POST",
            params={"token": token},
            data=user_to_xml(user),
            headers={"Content-Type": "application/xml"},
        )

    def update_user(self, sid: str, user: Dict[str, Any]) -> None:
        """Обновляет данные пользователя по sid."""
        self._request_text(**self._update_user_props(sid, user))

    async def update_user_async(self, sid: str, user: Dict[str, Any]) -> None:
        """Асинхронно обновляет данные пользователя по sid."""
        await self._request_text_async(**self._update_user_props(sid, user))

    def _delete_user_props(self, sid: str) -> RequestArgs:
        """Формирует аргументы запроса для удаления пользователя."""
        token = self._require_token(self.token_user_manage, field_name="token_user_manage")
        return RequestArgs(path=f"/user/{sid}", method="DELETE", params={"token": token})

    def delete_user(self, sid: str) -> None:
        """Удаляет пользователя по sid."""
        self._request_text(**self._delete_user_props(sid))

    async def delete_user_async(self, sid: str) -> None:
        """Асинхронно удаляет пользователя по sid."""
        await self._request_text_async(**self._delete_user_props(sid))

    @staticmethod
    def _set_state_props(ses_id: str, state: str) -> RequestArgs:
        """Формирует аргументы запроса для обновления состояния."""
        return RequestArgs(path="setstate", method="POST", params={"sesid": ses_id}, data=state)

    def set_state(self, ses_id: str, state: str) -> None:
        """Устанавливает произвольное состояние в рамках сессии."""
        self._request_text(**self._set_state_props(ses_id, state))

    async def set_state_async(self, ses_id: str, state: str) -> None:
        """Асинхронно устанавливает произвольное состояние в рамках сессии."""
        await self._request_text_async(**self._set_state_props(ses_id, state))

    @staticmethod
    def _get_state_props(ses_id: str) -> RequestParams:
        """Формирует параметры запроса для получения состояния."""
        return RequestParams(path="getstate", params={"sesid": ses_id})

    def get_state(self, ses_id: str) -> str:
        """Возвращает состояние для указанного session id."""
        return self._request_text(**self._get_state_props(ses_id))

    async def get_state_async(self, ses_id: str) -> str:
        """Асинхронно возвращает состояние для указанного session id."""
        return await self._request_text_async(**self._get_state_props(ses_id))


__all__ = [
    "Mellophone",
]
