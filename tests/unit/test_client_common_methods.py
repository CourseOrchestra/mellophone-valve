import asyncio
import xml.etree.ElementTree as ET

import pytest

import mellophone


def _call(client, mode, method, *args, **kwargs):
    callable_obj = getattr(client, method if mode == "sync" else f"{method}_async")
    result = callable_obj(*args, **kwargs)
    return asyncio.run(result) if mode == "async" else result


def _assert_call(
    calls,
    *,
    index=0,
    method=None,
    url_contains=(),
    url_not_contains=(),
    headers=None,
    content=None,
):
    assert calls
    assert len(calls) > index
    call = calls[index]
    if method is not None:
        assert call["method"] == method
    for part in url_contains:
        assert part in call["url"]
    for part in url_not_contains:
        assert part not in call["url"]
    if headers is not None:
        assert call["headers"] == headers
    if content is not None:
        assert call["content"] == content
    return call


@pytest.fixture(params=["sync", "async"], ids=["sync", "async"])
def mode_and_mock(request, mock_sync_client, mock_async_client):
    mode = request.param
    install = mock_sync_client if mode == "sync" else mock_async_client
    return mode, install


def test_login_sets_session_and_sends_request(mode_and_mock, response_factory):
    mode, install = mode_and_mock
    calls = install(response_factory(200))
    ses_id = "ses-1" if mode == "sync" else "ses-async"

    client = mellophone.Mellophone("http://example.com", session_id=None)
    result = _call(client, mode, "login", "john", "secret", ses_id=ses_id, gp="grp", ip="127.0.0.1")

    assert result == ses_id
    assert client.session_id == ses_id
    _assert_call(calls, method="GET", url_contains=("/login?", f"sesid={ses_id}", "login=john"))


def test_is_authenticated_returns_false_on_forbidden(mode_and_mock, response_factory):
    mode, install = mode_and_mock
    install(response_factory(403, "forbidden"))

    client = mellophone.Mellophone("http://example.com", session_id="ses-1")
    assert _call(client, mode, "is_authenticated") is False


def test_bad_request_maps_to_domain_error(mode_and_mock, response_factory):
    mode, install = mode_and_mock
    install(response_factory(400, "bad request"))

    client = mellophone.Mellophone("http://example.com")
    with pytest.raises(mellophone.BadRequestError) as exc:
        _call(client, mode, "login", "john", "secret", ses_id="ses-1")

    assert exc.value.status_code == 400


def test_server_error_maps_to_domain_error(mode_and_mock, response_factory):
    mode, install = mode_and_mock
    install(response_factory(500, "server error"))

    client = mellophone.Mellophone("http://example.com")
    with pytest.raises(mellophone.ServerError) as exc:
        _call(client, mode, "login", "john", "secret", ses_id="ses-1")

    assert exc.value.status_code == 500


def test_check_credentials_parses_xml(mode_and_mock, response_factory):
    mode, install = mode_and_mock
    calls = install(response_factory(200, "<user sid='1' login='neo'/>"))

    client = mellophone.Mellophone("http://example.com")
    result = _call(client, mode, "check_credentials", "neo", "1234")

    assert result == {"sid": "1", "login": "neo"}
    assert calls


def test_create_user_converts_password_to_pwd_and_sends_xml(mode_and_mock, response_factory):
    mode, install = mode_and_mock
    calls = install(response_factory(200, "<user sid='1' login='neo'/>"))

    client = mellophone.Mellophone("http://example.com", token_user_manage="token-1")
    _call(client, mode, "create_user", {"sid": "1", "login": "neo", "password": "1234"})

    call = _assert_call(
        calls,
        method="POST",
        url_contains=("token=token-1",),
        headers={"Content-Type": "application/xml"},
    )
    xml = ET.fromstring(call["content"])
    assert xml.tag == "user"
    assert xml.attrib["pwd"] == "1234"
    assert "password" not in xml.attrib


def test_create_user_empty_payload_raises(mode_and_mock):
    mode, _ = mode_and_mock
    client = mellophone.Mellophone("http://example.com")
    with pytest.raises(ValueError):
        _call(client, mode, "create_user", {})


def test_set_settings_uses_client_token(mode_and_mock, response_factory):
    mode, install = mode_and_mock
    calls = install(response_factory(200))

    client = mellophone.Mellophone("http://example.com", token_set_settings="set-token")
    _call(client, mode, "set_settings", lockout_time=30, login_attempts_allowed=5)

    _assert_call(
        calls,
        method="GET",
        url_contains=("/setsettings?", "token=set-token", "lockouttime=30", "loginattemptsallowed=5"),
    )


def test_update_user_uses_client_user_manage_token(mode_and_mock, response_factory):
    mode, install = mode_and_mock
    calls = install(response_factory(200))

    client = mellophone.Mellophone("http://example.com", token_user_manage="token-1")
    _call(client, mode, "update_user", "u-1", {"sid": "u-1", "login": "neo", "pwd": "1234"})

    _assert_call(
        calls,
        method="POST",
        url_contains=("/user/u-1?", "token=token-1"),
        headers={"Content-Type": "application/xml"},
    )


def test_change_user_pwd_sends_expected_params(mode_and_mock, response_factory):
    mode, install = mode_and_mock
    calls = install(response_factory(200))

    client = mellophone.Mellophone("http://example.com", session_id="ses-1")
    _call(client, mode, "change_user_pwd", "neo", "new-secret")

    _assert_call(
        calls,
        method="GET",
        url_contains=("/changeuserpwd?", "sesid=ses-1", "username=neo", "newpwd=new-secret"),
        url_not_contains=("oldpwd=",),
    )


def test_change_app_ses_id(mode_and_mock, response_factory):
    mode, install = mode_and_mock
    calls = install(response_factory(200))

    client = mellophone.Mellophone("http://example.com", session_id="ses-self")
    _call(client, mode, "change_app_ses_id", "ses-new")
    _call(client, mode, "change_app_ses_id", "ses-foreign-new", ses_id="ses-foreign-old")

    assert client.session_id == "ses-new"
    assert len(calls) == 2
    _assert_call(calls, index=0, url_contains=("oldsesid=ses-self", "newsesid=ses-new"))
    _assert_call(calls, index=1, url_contains=("oldsesid=ses-foreign-old", "newsesid=ses-foreign-new"))


def test_delete_user(mode_and_mock, response_factory):
    mode, install = mode_and_mock
    calls = install(response_factory(200))

    client = mellophone.Mellophone("http://example.com", token_user_manage="token-1")
    _call(client, mode, "delete_user", "u-1")

    _assert_call(calls, method="DELETE", url_contains=("/user/u-1?", "token=token-1"))


def test_set_state_and_get_state(mode_and_mock, response_factory):
    mode, install = mode_and_mock
    calls = install(response_factory(200, "state-value"))

    client = mellophone.Mellophone("http://example.com")
    ses_id = "ses-1" if mode == "sync" else "ses-async"
    payload = "new-state" if mode == "sync" else "payload"
    _call(client, mode, "set_state", ses_id, payload)
    state = _call(client, mode, "get_state", ses_id)

    assert state == "state-value"
    assert len(calls) == 2
    _assert_call(calls, index=0, method="POST", url_contains=("/setstate?", f"sesid={ses_id}"), content=payload)
    _assert_call(calls, index=1, method="GET", url_contains=("/getstate?", f"sesid={ses_id}"))


def test_parse_error_maps_to_response_parse_error(mode_and_mock, response_factory):
    mode, install = mode_and_mock
    install(response_factory(200, "<user"))

    client = mellophone.Mellophone("http://example.com")
    with pytest.raises(mellophone.ResponseParseError):
        _call(client, mode, "check_credentials", "neo", "1234")
