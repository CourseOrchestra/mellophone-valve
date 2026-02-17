from __future__ import annotations

import pytest

from mellophone.structures import RequestArgs, RequestParams


def test_request_params_stores_path_and_params():
    result = RequestParams(path="/login", params={"a": 1})

    assert result == {"path": "/login", "params": {"a": 1}}


def test_request_params_validates_types():
    with pytest.raises(TypeError, match="path must be str"):
        RequestParams(path=123, params={})  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="params must be dict"):
        RequestParams(path="/login", params="not-a-dict")  # type: ignore[arg-type]


def test_request_args_uses_defaults_and_omits_optional_fields():
    result = RequestArgs(path="/state", params={"sesid": "1"})

    assert result == {"path": "/state", "params": {"sesid": "1"}, "method": "GET"}
    assert "data" not in result
    assert "headers" not in result


def test_request_args_includes_data_and_headers_when_provided():
    result = RequestArgs(
        path="/user",
        params={"token": "t1"},
        method="POST",
        data="<user/>",
        headers={"Content-Type": "application/xml"},
    )

    assert result == {
        "path": "/user",
        "params": {"token": "t1"},
        "method": "POST",
        "data": "<user/>",
        "headers": {"Content-Type": "application/xml"},
    }


def test_request_args_validates_types():
    with pytest.raises(TypeError, match="method must be str"):
        RequestArgs(path="/state", params={}, method=1)  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="data must be str or None"):
        RequestArgs(path="/state", params={}, data=1)  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="headers must be dict or None"):
        RequestArgs(path="/state", params={}, headers="not-a-dict")  # type: ignore[arg-type]
