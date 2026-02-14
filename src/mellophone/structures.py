from __future__ import annotations

from typing import Any, Dict, Optional


class RequestParams(dict):
    """Container for request kwargs with validation."""

    def __init__(self, *, path: str, params: Dict[str, Any]) -> None:
        if not isinstance(path, str):
            raise TypeError("path must be str")
        if not isinstance(params, dict):
            raise TypeError("params must be dict")
        super().__init__(path=path, params=params)


class RequestArgs(RequestParams):
    """Extended request kwargs for methods that include body/headers."""

    def __init__(
        self,
        *,
        path: str,
        params: Dict[str, Any],
        method: str = "GET",
        data: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        if not isinstance(method, str):
            raise TypeError("method must be str")
        if data is not None and not isinstance(data, str):
            raise TypeError("data must be str or None")
        if headers is not None and not isinstance(headers, dict):
            raise TypeError("headers must be dict or None")
        super().__init__(path=path, params=params)
        self["method"] = method
        if data is not None:
            self["data"] = data
        if headers is not None:
            self["headers"] = headers


__all__ = ["RequestParams", "RequestArgs"]
