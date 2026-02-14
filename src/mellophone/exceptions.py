from __future__ import annotations


class HttpError(Exception):
    """Base API HTTP error."""

    def __init__(self, status_code: int, response_text: str) -> None:
        self.status_code = status_code
        self.response_text = response_text
        super().__init__(f"HTTP {status_code}: {response_text}")


class BadRequestError(HttpError):
    """Raised for HTTP 400."""


class UnauthorizedError(HttpError):
    """Raised for HTTP 401."""


class ForbiddenError(HttpError):
    """Raised for HTTP 403."""


class NotFoundError(HttpError):
    """Raised for HTTP 404."""


class ServerError(HttpError):
    """Raised for HTTP 5xx."""


class AsyncClientUnavailableError(RuntimeError):
    """Raised when async methods are used without httpx installed."""


class TransportError(RuntimeError):
    """Raised when HTTP client transport fails."""


class RequestTimeoutError(TransportError):
    """Raised when HTTP request exceeds timeout."""


class ResponseParseError(ValueError):
    """Raised when API XML response cannot be parsed."""


__all__ = [
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
