#
#   Copyright (c) 2019 One Identity
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#

import json
import pytest
from requests.exceptions import ConnectionError
from pytest import raises
from unittest.mock import patch, call, MagicMock
from collections import namedtuple
from textwrap import dedent
from contextlib import contextmanager

from ..client import AuthenticatorFactory, Client, V9Authenticator
from safeguard.sessions.plugin.plugin_configuration import PluginConfiguration
from safeguard.sessions.plugin.endpoint_extractor import EndpointException

Response = namedtuple("Response", "ok text status_code")

ASSET = "1.2.3.4"
ACCOUNT_ID = "12_3"
ACCOUNT_ID_2 = "98_7"
ACCOUNT_USERNAME = "account"
ACCOUNT_PASSWORD = "secret"
ACCOUNT_PASSWORD_2 = "top_secret"
GATEWAY_USERNAME = "gateway"
LOGON_TOKEN = "token"

GET_RESPONSE = Response(
    text=json.dumps(
        {
            "value": [
                {
                    "id": ACCOUNT_ID,
                    "name": f"Database-Oracle-{ASSET}-{ACCOUNT_USERNAME}",
                    "address": ASSET,
                    "userName": ACCOUNT_USERNAME,
                    "platformId": "Oracle",
                    "safeName": "DatabaseAccounts",
                    "secretType": "password",
                }
            ],
            "count": 1,
        }
    ),
    ok=True,
    status_code=200,
)

POST_RESPONSES = [
    Response(text=json.dumps({"CyberArkLogonResult": LOGON_TOKEN}), ok=True, status_code=200),
    Response(text=json.dumps(ACCOUNT_PASSWORD), ok=True, status_code=200),
    Response(text="", ok=True, status_code=200),
]

ADDRESS = "cyberark.host"
VAULT_USERNAME = "vault-user"
VAULT_PASSWORD = "password"

CYBERARK_VAULT_CONFIG = dedent(
    f"""
    [cyberark]
    address = {ADDRESS}
    use_credential=explicit
    username = {VAULT_USERNAME}
    password = {VAULT_PASSWORD}
"""
)


CYBERARK_VAULT_GW_CONFIG = dedent(
    f"""
    [cyberark]
    address = {ADDRESS}
    use_credential=gateway
"""
)


URL = "http://{}".format(ADDRESS)
LOGON_ENDPOINT = URL + "/PasswordVault/WebServices/auth/Cyberark/CyberArkAuthenticationService.svc/Logon"
LOGOFF_ENDPOINT = URL + "/PasswordVault/WebServices/auth/Cyberark/CyberArkAuthenticationService.svc/Logoff"
GET_ACCOUNTS_ENDPOINT = (
    URL + "/PasswordVault/api/Accounts?search=" + ",".join([ACCOUNT_USERNAME, ASSET]) + "&sort=UserName"
)
GET_PASSWORD_ENDPOINT = URL + "/PasswordVault/api/Accounts/" + ACCOUNT_ID + "/Password/Retrieve"
GET_PASSWORD_2_ENDPOINT = URL + "/PasswordVault/api/Accounts/" + ACCOUNT_ID_2 + "/Password/Retrieve"

LOGON_POST_DATA = json.dumps(
    {"username": VAULT_USERNAME, "password": VAULT_PASSWORD, "useRadiusAuthentication": False, "connectionNumber": "1"}
)
GET_PWD_POST_DATA = json.dumps(
    {
        "reason": GATEWAY_USERNAME + ",SPS",
        "TicketingSystemName": "",
        "TicketId": "",
        "Version": 0,
        "ActionType": "show",
        "isUse": False,
        "Machine": ASSET,
    }
)
AUTH_HEADERS = {"Authorization": LOGON_TOKEN, "Content-Type": "application/json"}
HEADERS = {"Content-Type": "application/json"}

AUTH_FAIL_MESSAGE = "Authentication failure."
AUTH_FAIL_RESPONSE = Response(
    text=json.dumps({"ErrorCode": "ITATS004E", "ErrorMessage": AUTH_FAIL_MESSAGE}),
    ok=False,
    status_code=403)
NO_OBJECTS_FOUND_RESPONSE = Response(text=json.dumps({"value": [], "count": 0}), ok=True, status_code=200)


@contextmanager
def _open_session():
    yield SESSION


SESSION = MagicMock()
REQUESTS_TLS = MagicMock()
REQUESTS_TLS.tls_enabled = False
REQUESTS_TLS.open_session = _open_session
DEFAULT_AUTHENTICATOR = V9Authenticator("legacy")


def test_can_instantiate_client_from_config():
    client = Client.create(PluginConfiguration(CYBERARK_VAULT_CONFIG), None, None)
    assert isinstance(client, Client)


@patch("safeguard.sessions.plugin.requests_tls.RequestsTLS", return_value=REQUESTS_TLS)
@patch.object(AuthenticatorFactory, "create", return_value=DEFAULT_AUTHENTICATOR)
def test_client_uses_https_when_tls_is_enabled(_requests_tls, _authenticator_creator, mocker):
    REQUESTS_TLS.tls_enabled = True
    https_url = "https://{}".format(ADDRESS)
    config = PluginConfiguration(CYBERARK_VAULT_CONFIG)
    mocker.spy(Client, "__init__")
    client = Client.create(config, None, None)
    client.__init__.assert_called_with(
        client, REQUESTS_TLS, https_url, None, None, DEFAULT_AUTHENTICATOR
    )


@patch("safeguard.sessions.plugin.requests_tls.RequestsTLS", return_value=REQUESTS_TLS)
@patch.object(AuthenticatorFactory, "create", return_value=DEFAULT_AUTHENTICATOR)
def test_client_uses_gateway_user_when_configured(_requests_tls, _authenticator_creator, mocker):
    REQUESTS_TLS.tls_enabled = True
    https_url = "https://{}".format(ADDRESS)
    config = PluginConfiguration(CYBERARK_VAULT_GW_CONFIG)
    mocker.spy(Client, "__init__")
    client = Client.create(config, "a_gateway_user", "a_gateway_password")
    client.__init__.assert_called_with(
        client, REQUESTS_TLS, https_url, "a_gateway_user", "a_gateway_password", DEFAULT_AUTHENTICATOR
    )


password_test_data = [
    (
        POST_RESPONSES,
        [
            {
                "id": ACCOUNT_ID,
                "name": f"Database-Oracle-{ASSET}-{ACCOUNT_USERNAME}",
                "address": ASSET,
                "userName": ACCOUNT_USERNAME,
                "platformId": "Oracle",
                "safeName": "DatabaseAccounts",
                "secretType": "password",
            }
        ],
        [
            call(LOGON_ENDPOINT, headers=HEADERS, data=LOGON_POST_DATA, params=None),
            call(GET_PASSWORD_ENDPOINT, headers=AUTH_HEADERS, data=GET_PWD_POST_DATA, params=None),
            call(LOGOFF_ENDPOINT, headers=AUTH_HEADERS),
        ],
        [
            call(GET_ACCOUNTS_ENDPOINT, headers=AUTH_HEADERS, params=None),
        ],
        [ACCOUNT_PASSWORD]
    ),
    (
        POST_RESPONSES[:-1] + [Response(text=json.dumps(ACCOUNT_PASSWORD_2), ok=True, status_code=200)] + POST_RESPONSES[-1:],
        [
            {"id": ACCOUNT_ID, "address": ASSET, "userName": ACCOUNT_USERNAME, "secretType": "password"},
            {"id": ACCOUNT_ID_2, "address": ASSET, "userName": ACCOUNT_USERNAME, "secretType": "password" },
        ],
        [
            call(LOGON_ENDPOINT, headers=HEADERS, data=LOGON_POST_DATA, params=None),
            call(GET_PASSWORD_ENDPOINT, headers=AUTH_HEADERS, data=GET_PWD_POST_DATA, params=None),
            call(GET_PASSWORD_2_ENDPOINT, headers=AUTH_HEADERS, data=GET_PWD_POST_DATA, params=None),
            call(LOGOFF_ENDPOINT, headers=AUTH_HEADERS),
        ],
        [
            call(GET_ACCOUNTS_ENDPOINT, headers=AUTH_HEADERS, params=None),
        ],
        [ACCOUNT_PASSWORD, ACCOUNT_PASSWORD_2]
    ),
    (
        POST_RESPONSES,
        [
            {"id": "id1", "address": "not-the-asset", "userName": "not-the-username", "secretType": "password"},
            {"id": "id2", "address": ASSET, "userName": "not-the-username", "secretType": "password"},
            {"id": "id3", "address": "not-the-asset", "userName": ACCOUNT_USERNAME, "secretType": "password"},
        ],
        [call(LOGON_ENDPOINT, headers=HEADERS, data=LOGON_POST_DATA, params=None)],
        [call(GET_ACCOUNTS_ENDPOINT, headers=AUTH_HEADERS, params=None)],
        []
    )
]

password_test_ids = [
    "get_password_based_on_username_and_asset",
    "object_search_returns_multiple_objects_get_secret_returns_multiple_secrets",
    "username_and_asset_gets_verified"

]


@pytest.mark.parametrize("post_se,get_rv,expected_call_to_post,expected_call_to_get,expected_result", password_test_data, ids=password_test_ids)
def test_password_retreiving(post_se, get_rv, expected_call_to_post, expected_call_to_get, expected_result):
    SESSION.get.mock_calls = []
    SESSION.post.mock_calls = []
    SESSION.get.return_value = Response(
        text=json.dumps(
            {
                "value": get_rv,
                "count": len(get_rv),
            }
        ),
        ok=True,
        status_code=200,
    )
    SESSION.post.side_effect = post_se

    client = Client(REQUESTS_TLS, "http://" + ADDRESS, VAULT_USERNAME, VAULT_PASSWORD, DEFAULT_AUTHENTICATOR)
    result = client.get_passwords(ACCOUNT_USERNAME, ASSET, GATEWAY_USERNAME)
    assert result == expected_result
    SESSION.get.assert_has_calls(calls=expected_call_to_get, any_order=False)
    SESSION.post.assert_has_calls(calls=expected_call_to_post, any_order=False)


KEY1 = """-----BEGIN RSA PRIVATE KEY-----
    key1
    -----END RSA PRIVATE KEY-----"""

KEY2 = """-----BEGIN RSA PRIVATE KEY-----
    key2
    -----END RSA PRIVATE KEY-----"""

ACCOUNT_WITH_KEY = "user_with_key"

keys_test_data = [
    (
        [
            Response(text=json.dumps({"CyberArkLogonResult": LOGON_TOKEN}), ok=True, status_code=200),
            Response(text=KEY1, ok=True, status_code=200),
            Response(text=KEY2, ok=True, status_code=200),
            Response(text="", ok=True, status_code=200),
        ],
        [
            {
                "id": "67_9",
                "name": f"Operating System-UnixSSHKeys-{ASSET}-{ACCOUNT_WITH_KEY}",
                "address": ASSET,
                "userName": ACCOUNT_WITH_KEY,
                "platformId": "UnixSSHKeys",
                "safeName": "UnixAccounts_SSHKeys",
                "secretType": "key",
            },
            {
                "id": "67_10",
                "name": f"Operating System-UnixSSHKeys-{ASSET}-{ACCOUNT_WITH_KEY}",
                "address": ASSET,
                "userName": ACCOUNT_WITH_KEY,
                "platformId": "UnixSSHKeys",
                "safeName": "UnixAccounts_SSHKeys",
                "secretType": "key",
            }
        ],
        [
            call(LOGON_ENDPOINT, headers=HEADERS, data=LOGON_POST_DATA, params=None),
            call(URL + "/PasswordVault/api/Accounts/67_9/Password/Retrieve", headers=AUTH_HEADERS, data=GET_PWD_POST_DATA, params=None),
            call(URL + "/PasswordVault/api/Accounts/67_10/Password/Retrieve", headers=AUTH_HEADERS, data=GET_PWD_POST_DATA, params=None),
            call(LOGOFF_ENDPOINT, headers=AUTH_HEADERS),
        ],
        [call(URL + "/PasswordVault/api/Accounts?search=" + ",".join([ACCOUNT_WITH_KEY, ASSET]) + "&sort=UserName", headers=AUTH_HEADERS, params=None)],
        [KEY1, KEY2]
    ),
    (
        [
            Response(text=json.dumps({"CyberArkLogonResult": LOGON_TOKEN}), ok=True, status_code=200),
            Response(text=KEY1, ok=True, status_code=200),
            Response(text="", ok=True, status_code=200),
        ],
        [
            {
                "id": "67_9",
                "name": f"Operating System-UnixSSHKeys-{ASSET}-{ACCOUNT_WITH_KEY}",
                "address": ASSET,
                "userName": ACCOUNT_WITH_KEY,
                "platformId": "UnixSSHKeys",
                "safeName": "UnixAccounts_SSHKeys",
                "secretType": "key",
            }
        ],
        [
            call(LOGON_ENDPOINT, headers=HEADERS, data=LOGON_POST_DATA, params=None),
            call(URL + "/PasswordVault/api/Accounts/67_9/Password/Retrieve", headers=AUTH_HEADERS, data=GET_PWD_POST_DATA, params=None),
            call(LOGOFF_ENDPOINT, headers=AUTH_HEADERS),
        ],
        [call(URL + "/PasswordVault/api/Accounts?search=" + ",".join([ACCOUNT_WITH_KEY, ASSET]) + "&sort=UserName", headers=AUTH_HEADERS, params=None)],
        [KEY1]
    ),
    (
        [
            Response(text=json.dumps({"CyberArkLogonResult": LOGON_TOKEN}), ok=True, status_code=200),
            Response(text=KEY1, ok=True, status_code=200),
            Response(text="", ok=True, status_code=200),
        ],
        [
            {
                "id": "67_9",
                "name": f"Operating System-UnixSSHKeys-{ASSET}-{ACCOUNT_WITH_KEY}",
                "address": ASSET,
                "userName": ACCOUNT_WITH_KEY,
                "platformId": "UnixSSHKeys",
                "safeName": "UnixAccounts_SSHKeys",
                "secretType": "key",
            },
            {
                "id": ACCOUNT_ID,
                "name": f"Database-Oracle-{ASSET}-{ACCOUNT_WITH_KEY}",
                "address": ASSET,
                "userName": ACCOUNT_WITH_KEY,
                "platformId": "Oracle",
                "safeName": "DatabaseAccounts",
                "secretType": "password",
            }
        ],
        [
            call(LOGON_ENDPOINT, headers=HEADERS, data=LOGON_POST_DATA, params=None),
            call(URL + "/PasswordVault/api/Accounts/67_9/Password/Retrieve", headers=AUTH_HEADERS, data=GET_PWD_POST_DATA, params=None),
            call(LOGOFF_ENDPOINT, headers=AUTH_HEADERS),
        ],
        [call(URL + "/PasswordVault/api/Accounts?search=" + ",".join([ACCOUNT_WITH_KEY, ASSET]) + "&sort=UserName", headers=AUTH_HEADERS, params=None)],
        [KEY1]
    ),
    (
        [
            Response(text=json.dumps({"CyberArkLogonResult": LOGON_TOKEN}), ok=True, status_code=200),
            Response(text=KEY1, ok=True, status_code=200),
            Response(text="", ok=True, status_code=200),
        ],
        [],
        [
            call(LOGON_ENDPOINT, headers=HEADERS, data=LOGON_POST_DATA, params=None),
            call(LOGOFF_ENDPOINT, headers=AUTH_HEADERS),
        ],
        [call(URL + "/PasswordVault/api/Accounts?search=" + ",".join([ACCOUNT_WITH_KEY, ASSET]) + "&sort=UserName", headers=AUTH_HEADERS, params=None)],
        []
    ),
]


test_ids = [
    "Retrieves more keys",
    "Can retrieve keys",
    "Retrieves only keys",
    "No object found",
]


@pytest.mark.parametrize("post_se,get_rv,expected_call_to_post,expected_call_to_get,expected_result", keys_test_data, ids=test_ids)
def test_ssh_key_retrieve(post_se, get_rv, expected_call_to_post, expected_call_to_get, expected_result):
    SESSION.get.mock_calls = []
    SESSION.post.mock_calls = []
    SESSION.get.return_value = Response(
        text=json.dumps(
            {
                "value": get_rv,
                "count": len(get_rv),
            }
        ),
        ok=True,
        status_code=200,
    )
    SESSION.post.side_effect = post_se

    client = Client(REQUESTS_TLS, "http://" + ADDRESS, VAULT_USERNAME, VAULT_PASSWORD, DEFAULT_AUTHENTICATOR)
    result = client.get_ssh_keys(ACCOUNT_WITH_KEY, ASSET, GATEWAY_USERNAME)
    assert result == expected_result
    SESSION.get.assert_has_calls(calls=expected_call_to_get, any_order=False)
    SESSION.post.assert_has_calls(calls=expected_call_to_post, any_order=False)


def test_cannot_connect_to_vault():
    SESSION.post.side_effect = [ConnectionError()]
    client = Client(REQUESTS_TLS, "http://" + ADDRESS, VAULT_USERNAME, VAULT_PASSWORD, DEFAULT_AUTHENTICATOR)
    with raises(EndpointException) as exc:
        client.get_passwords(account="dummy", asset="1.2.3.4", gateway_username="dummy")
    assert "Connection error: " in str(exc.value)


def test_cannot_authenticate():
    SESSION.post.side_effect = [AUTH_FAIL_RESPONSE]
    client = Client(REQUESTS_TLS, "http://" + ADDRESS, VAULT_USERNAME, VAULT_PASSWORD, DEFAULT_AUTHENTICATOR)
    with raises(EndpointException) as exc:
        client.get_passwords(account="dummy", asset="1.2.3.4", gateway_username="dummy")
    assert AUTH_FAIL_MESSAGE in str(exc.value)


def test_cannot_find_object_based_on_username_and_asset():
    SESSION.post.side_effect = POST_RESPONSES
    SESSION.get.return_value = NO_OBJECTS_FOUND_RESPONSE
    client = Client(REQUESTS_TLS, "http://" + ADDRESS, VAULT_USERNAME, VAULT_PASSWORD, DEFAULT_AUTHENTICATOR)
    assert client.get_passwords(account="dummy", asset="1.2.3.4", gateway_username="dummy") == []
