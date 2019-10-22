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
from requests.exceptions import ConnectionError
from pytest import raises
from unittest.mock import patch, call, MagicMock
from collections import namedtuple
from textwrap import dedent
from contextlib import contextmanager

from ..client import AuthenticatorFactory, Client, CyberarkException, V9Authenticator
from safeguard.sessions.plugin.plugin_configuration import PluginConfiguration

Response = namedtuple('Response', 'ok text')

ASSET = '1.2.3.4'
ACCOUNT_ID = '12_3'
ACCOUNT_ID_2 = '98_7'
ACCOUNT_USERNAME = 'account'
ACCOUNT_PASSWORD = 'secret'
ACCOUNT_PASSWORD_2 = 'top_secret'
GATEWAY_USERNAME = 'gateway'
LOGON_TOKEN = 'token'

GET_RESPONSE = Response(text=json.dumps({
    'value': [
        {
            'id': ACCOUNT_ID,
            'name': f'Database-Oracle-{ASSET}-{ACCOUNT_USERNAME}',
            'address': ASSET,
            'userName': ACCOUNT_USERNAME,
            'platformId': 'Oracle',
            'safeName': 'DatabaseAccounts',
            'secretType': 'password',
        }
    ],
    'count': 1
}), ok=True)

POST_RESPONSES = [
    Response(text=json.dumps({'CyberArkLogonResult': LOGON_TOKEN}), ok=True),
    Response(text=json.dumps(ACCOUNT_PASSWORD), ok=True),
    Response(text="", ok=True),
]

ADDRESS = 'cyberark.host'
VAULT_USERNAME = 'vault-user'
VAULT_PASSWORD = 'password'

CYBERARK_VAULT_CONFIG = dedent(f'''
    [cyberark]
    address = {ADDRESS}
    username = {VAULT_USERNAME}
    password = {VAULT_PASSWORD}
''')

URL = 'http://{}'.format(ADDRESS)
LOGON_ENDPOINT = URL + '/PasswordVault/WebServices/auth/Cyberark/CyberArkAuthenticationService.svc/Logon'
LOGOFF_ENDPOINT = URL + '/PasswordVault/WebServices/auth/Cyberark/CyberArkAuthenticationService.svc/Logoff'
GET_ACCOUNTS_ENDPOINT = (URL + '/PasswordVault/api/Accounts?search=' +
                         ','.join([ACCOUNT_USERNAME, ASSET]) + '&sort=UserName')
GET_PASSWORD_ENDPOINT = URL + '/PasswordVault/api/Accounts/' + ACCOUNT_ID + '/Password/Retrieve'
GET_PASSWORD_2_ENDPOINT = URL + '/PasswordVault/api/Accounts/' + ACCOUNT_ID_2 + '/Password/Retrieve'

LOGON_POST_DATA = json.dumps({
    'username': VAULT_USERNAME,
    'password': VAULT_PASSWORD,
    'useRadiusAuthentication': False,
    'connectionNumber': '1'
})
GET_PWD_POST_DATA = json.dumps({
    'reason': GATEWAY_USERNAME + ',SPS',
    'TicketingSystemName': '',
    'TicketId': '',
    'Version': 0,
    'ActionType': 'show',
    'isUse': False,
    'Machine': ASSET
})
AUTH_HEADERS = {'Authorization': LOGON_TOKEN, 'Content-Type': 'application/json'}
HEADERS = {'Content-Type': 'application/json'}

AUTH_FAIL_MESSAGE = 'Authentication failure.'
AUTH_FAIL_RESPONSE = Response(text=json.dumps({
    'ErrorCode': 'ITATS004E',
    'ErrorMessage': AUTH_FAIL_MESSAGE
}), ok=False)
NO_OBJECTS_FOUND_RESPONSE = Response(text=json.dumps({'value': [], 'count': 0}), ok=True)


@contextmanager
def _open_session():
    yield SESSION


SESSION = MagicMock()
REQUESTS_TLS = MagicMock()
REQUESTS_TLS.tls_enabled = False
REQUESTS_TLS.open_session = _open_session
DEFAULT_AUTHENTICATOR = V9Authenticator('legacy')


def test_can_instantiate_client_from_config():
    client = Client.from_config(PluginConfiguration(CYBERARK_VAULT_CONFIG))
    assert isinstance(client, Client)


@patch('safeguard.sessions.plugin.requests_tls.RequestsTLS', return_value=REQUESTS_TLS)
@patch.object(AuthenticatorFactory, 'create', return_value=DEFAULT_AUTHENTICATOR)
def test_client_uses_https_when_tls_is_enabled(_requests_tls, _authenticator_creator, mocker):
    REQUESTS_TLS.tls_enabled = True
    https_url = 'https://{}'.format(ADDRESS)
    config = PluginConfiguration(CYBERARK_VAULT_CONFIG)
    mocker.spy(Client, '__init__')
    client = Client.from_config(config)
    client.__init__.assert_called_with(
        client, REQUESTS_TLS, https_url, VAULT_USERNAME, VAULT_PASSWORD, DEFAULT_AUTHENTICATOR
    )


def test_get_password_based_on_username_and_asset():
    SESSION.post.side_effect = POST_RESPONSES
    SESSION.get.return_value = GET_RESPONSE
    expected_calls_to_post = [
        call(LOGON_ENDPOINT, headers=HEADERS, data=LOGON_POST_DATA),
        call(GET_PASSWORD_ENDPOINT, headers=AUTH_HEADERS, data=GET_PWD_POST_DATA),
        call(LOGOFF_ENDPOINT, headers=AUTH_HEADERS),
    ]
    expected_call_to_get = [
        call(GET_ACCOUNTS_ENDPOINT, headers=AUTH_HEADERS),
    ]

    client = Client(REQUESTS_TLS, 'http://' + ADDRESS, VAULT_USERNAME, VAULT_PASSWORD, DEFAULT_AUTHENTICATOR)
    password = client.get_passwords(ACCOUNT_USERNAME, ASSET, GATEWAY_USERNAME)

    assert password == {'passwords': [ACCOUNT_PASSWORD]}
    SESSION.get.assert_has_calls(calls=expected_call_to_get, any_order=False)
    SESSION.post.assert_has_calls(calls=expected_calls_to_post, any_order=False)


def test_if_object_search_returns_multiple_objects_get_secret_returns_multiple_secrets():
    SESSION.post.side_effect = POST_RESPONSES[:-1] +\
                               [Response(text=json.dumps(ACCOUNT_PASSWORD_2), ok=True)] +\
                               POST_RESPONSES[-1:]
    SESSION.get.return_value = Response(text=json.dumps({
        'value': [{
            'id': ACCOUNT_ID,
            'address': ASSET,
            'userName': ACCOUNT_USERNAME
        }, {
            'id': ACCOUNT_ID_2,
            'address': ASSET,
            'userName': ACCOUNT_USERNAME
        }],
        'count': 2
    }), ok=True)
    expected_calls_to_post = [
        call(LOGON_ENDPOINT, headers=HEADERS, data=LOGON_POST_DATA),
        call(GET_PASSWORD_ENDPOINT, headers=AUTH_HEADERS, data=GET_PWD_POST_DATA),
        call(GET_PASSWORD_2_ENDPOINT, headers=AUTH_HEADERS, data=GET_PWD_POST_DATA),
        call(LOGOFF_ENDPOINT, headers=AUTH_HEADERS),
    ]
    expected_call_to_get = [
        call(GET_ACCOUNTS_ENDPOINT, headers=AUTH_HEADERS),
    ]

    client = Client(REQUESTS_TLS, 'http://' + ADDRESS, VAULT_USERNAME, VAULT_PASSWORD, DEFAULT_AUTHENTICATOR)
    passwords = client.get_passwords(ACCOUNT_USERNAME, ASSET, GATEWAY_USERNAME)

    assert passwords == {'passwords': [ACCOUNT_PASSWORD, ACCOUNT_PASSWORD_2]}
    SESSION.get.assert_has_calls(calls=expected_call_to_get, any_order=False)
    SESSION.post.assert_has_calls(calls=expected_calls_to_post, any_order=False)


def test_username_and_asset_gets_verified():
    SESSION.post.side_effect = POST_RESPONSES
    SESSION.get.return_value = Response(text=json.dumps({
        'value': [{
            'id': 'id1',
            'address': 'not-the-asset',
            'userName': 'not-the-username',
        }, {
            'id': 'id2',
            'address': ASSET,
            'userName': 'not-the-username',
        }, {
            'id': 'id3',
            'address': 'not-the-asset',
            'userName': ACCOUNT_USERNAME,
        }],
        'count': 3
    }), ok=True)
    expected_call_to_post = [call(LOGON_ENDPOINT, headers=HEADERS, data=LOGON_POST_DATA)]
    expected_call_to_get = [call(GET_ACCOUNTS_ENDPOINT, headers=AUTH_HEADERS)]

    client = Client(REQUESTS_TLS, 'http://' + ADDRESS, VAULT_USERNAME, VAULT_PASSWORD, DEFAULT_AUTHENTICATOR)
    password = client.get_passwords(ACCOUNT_USERNAME, ASSET, GATEWAY_USERNAME)

    assert password == {'passwords': []}
    SESSION.get.assert_has_calls(calls=expected_call_to_get, any_order=False)
    SESSION.post.assert_has_calls(calls=expected_call_to_post, any_order=False)


def test_cannot_connect_to_vault():
    SESSION.post.side_effect = [ConnectionError()]
    client = Client(REQUESTS_TLS, 'http://' + ADDRESS, VAULT_USERNAME, VAULT_PASSWORD, DEFAULT_AUTHENTICATOR)
    with raises(CyberarkException) as exc:
        client.get_passwords(account='dummy', asset='1.2.3.4', gateway_username='dummy')
    assert 'Connection error:' in str(exc.value)


def test_cannot_authenticate():
    SESSION.post.side_effect = [AUTH_FAIL_RESPONSE]
    client = Client(REQUESTS_TLS, 'http://' + ADDRESS, VAULT_USERNAME, VAULT_PASSWORD, DEFAULT_AUTHENTICATOR)
    with raises(CyberarkException) as exc:
        client.get_passwords(account='dummy', asset='1.2.3.4', gateway_username='dummy')
    assert AUTH_FAIL_MESSAGE in str(exc.value)


def test_cannot_find_object_based_on_username_and_asset():
    SESSION.post.side_effect = POST_RESPONSES
    SESSION.get.return_value = NO_OBJECTS_FOUND_RESPONSE
    client = Client(REQUESTS_TLS, 'http://' + ADDRESS, VAULT_USERNAME, VAULT_PASSWORD, DEFAULT_AUTHENTICATOR)
    assert client.get_passwords(account='dummy', asset='1.2.3.4', gateway_username='dummy') == {'passwords': []}
