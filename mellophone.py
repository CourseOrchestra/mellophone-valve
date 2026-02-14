from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.mellophone import (
        AsyncClientUnavailableError,  # noqa: F401
        BadRequestError,  # noqa: F401
        ForbiddenError,  # noqa: F401
        HttpError,  # noqa: F401
        Mellophone,  # noqa: F401
        NotFoundError,  # noqa: F401
        RequestArgs,  # noqa: F401
        RequestParams,  # noqa: F401
        RequestTimeoutError,  # noqa: F401
        ResponseParseError,  # noqa: F401
        ServerError,  # noqa: F401
        TransportError,  # noqa: F401
        UnauthorizedError,  # noqa: F401
        element_to_dict,  # noqa: F401
        httpx,  # noqa: F401
        merge_value,  # noqa: F401
        normalize_key,  # noqa: F401
        requests,  # noqa: F401
        user_to_xml,  # noqa: F401
        xml_to_json,  # noqa: F401
    )
else:
    import sys

    from src.mellophone import client as _client

    sys.modules[__name__] = _client
