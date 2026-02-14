from __future__ import annotations

from .client import Mellophone, httpx, requests
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
from .utils import element_to_dict, merge_value, normalize_key, user_to_xml, xml_to_json

__all__ = [
    "Mellophone",
    "RequestParams",
    "RequestArgs",
    "xml_to_json",
    "user_to_xml",
    "normalize_key",
    "merge_value",
    "element_to_dict",
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
