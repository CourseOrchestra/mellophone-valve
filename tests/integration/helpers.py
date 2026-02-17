from __future__ import annotations

import asyncio
from typing import Any, Dict, List

import pytest

from mellophone import ForbiddenError, Mellophone


def users_from_list(payload: Dict[str, Any]) -> List[Dict[str, str]]:
    users = payload.get("users", {}).get("user", [])
    if isinstance(users, dict):
        return [users]
    return users


def invoke(client: Mellophone, mode: str, method: str, *args: Any, **kwargs: Any) -> Any:
    callable_obj = getattr(client, method if mode == "sync" else f"{method}_async")
    result = callable_obj(*args, **kwargs)
    return asyncio.run(result) if mode == "async" else result


def assert_credentials_valid(client: Mellophone, mode: str, login: str, password: str, sid: str) -> None:
    result = invoke(client, mode, "check_credentials", login, password)
    assert result.get("sid") == sid
    assert result.get("login") == login


def assert_credentials_invalid(client: Mellophone, mode: str, login: str, password: str) -> None:
    with pytest.raises(ForbiddenError):
        invoke(client, mode, "check_credentials", login, password)
