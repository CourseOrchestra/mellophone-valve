import pytest

import mellophone
from mellophone.utils import xml_to_json


def test_xml_to_json_with_repeated_tags():
    xml = "<users><user login='a'/><user login='b'/></users>"
    result = xml_to_json(xml)
    assert result == {"users": {"user": [{"login": "a"}, {"login": "b"}]}}


def test_client_options_are_stored():
    client = mellophone.Mellophone(
        "http://example.com",
        token_set_settings="set-token",
        token_user_manage="user-token",
        session_id="ses-1",
        timeout=7.5,
    )

    assert client.base_url == "http://example.com"
    assert client.token_set_settings == "set-token"
    assert client.token_user_manage == "user-token"
    assert client.session_id == "ses-1"
    assert client.timeout == 7.5


def test_client_deprecated_token_aliases_work_and_warn():
    with pytest.warns(DeprecationWarning, match="set_settings_token"):
        with pytest.warns(DeprecationWarning, match="user_manage_token"):
            client = mellophone.Mellophone(
                "http://example.com",
                set_settings_token="set-token-old",
                user_manage_token="user-token-old",
            )

    assert client.token_set_settings == "set-token-old"
    assert client.token_user_manage == "user-token-old"

    with pytest.warns(DeprecationWarning, match="set_settings_token"):
        assert client.set_settings_token == "set-token-old"
    with pytest.warns(DeprecationWarning, match="user_manage_token"):
        assert client.user_manage_token == "user-token-old"

    with pytest.warns(DeprecationWarning, match="set_settings_token"):
        client.set_settings_token = "set-token-updated"
    with pytest.warns(DeprecationWarning, match="user_manage_token"):
        client.user_manage_token = "user-token-updated"

    assert client.token_set_settings == "set-token-updated"
    assert client.token_user_manage == "user-token-updated"


def test_build_url_skips_none_params():
    client = mellophone.Mellophone("http://example.com")

    url = client._build_url("path", {"a": 1, "b": None, "c": "x"})

    assert url == "http://example.com/path?a=1&c=x"
