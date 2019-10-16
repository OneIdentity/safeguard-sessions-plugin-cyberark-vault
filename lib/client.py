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

import requests
import json
from safeguard.sessions.plugin.requests_tls import RequestsTLS
from safeguard.sessions.plugin.logging import get_logger

logger = get_logger(__name__)


class CyberarkException(Exception):
    pass


class Client:
    def __init__(self, requests_tls, address_url, username, password):
        self.__requests_tls = requests_tls
        self.__address_url = address_url
        self.__username = username
        self.__password = password

    @classmethod
    def from_config(cls, config):
        requests_tls = RequestsTLS.from_config(config)
        address_url = '{}://{}'.format('https' if requests_tls.tls_enabled else 'http',
                                   config.get('cyberark', 'address', required=True))
        username = config.get('cyberark', 'username')
        password = config.get('cyberark', 'password')
        return Client(requests_tls, address_url, username, password)

    def get_passwords(self, account, asset, gateway_username):
        with self.__requests_tls.open_session() as session:
            auth_token = self.__authenticate(session)
            passwords = self.__get_passwords(session, auth_token, account, asset, gateway_username)
        return passwords

    def __authenticate(self, session):
        auth_post_data = {
            'username': self.__username,
            'password': self.__password,
            'useRadiusAuthentication': False,
            'connectionNumber': '1'
        }
        return _extract_data_from_endpoint(
            session,
            endpoint_url=self.__address_url + '/PasswordVault/WebServices/auth/Cyberark/'
                                              'CyberArkAuthenticationService.svc/Logon',
            headers={'Content-Type': 'application/json'},
            method='post',
            field_name='CyberArkLogonResult',
            data=auth_post_data
        )

    def __get_passwords(self, session, auth_token, account, asset, gateway_username):
        headers = {'Content-Type': 'application/json', 'Authorization': auth_token}
        found_objects = _extract_data_from_endpoint(
            session,
            endpoint_url=(self.__address_url + '/PasswordVault/api/Accounts?search=' +
                          ','.join([account, asset]) + '&sort=UserName'),
            headers=headers,
            method='get',
            field_name='value'
        )
        found_objects = list(filter(lambda x: (account == x.get('userName') and asset == x.get('address')),
                                    found_objects))
        if len(found_objects) == 0:
            logger.debug('No objects found in vault for this account and/or asset: account={}, asset={}'
                         .format(account, asset))
            return {'passwords': []}
        pwd_post_data = {
            'reason': '{},SPS'.format(gateway_username),
            'TicketingSystemName': '',
            'TicketId': '',
            'Version': 0,
            'ActionType': 'show',
            'isUse': False,
            'Machine': asset
        }
        endpoint_urls = [self.__address_url + '/PasswordVault/api/Accounts/' + found_object.get('id') +
                         '/Password/Retrieve' for found_object in found_objects]
        return {'passwords': [_extract_data_from_endpoint(session, endpoint_url, headers, 'post', None, pwd_post_data)
                              for endpoint_url in endpoint_urls]}


def _extract_data_from_endpoint(session, endpoint_url, headers, method, field_name=None, data=None):
    logger.debug('Sending http request to Cyberark Vault, endpoint_url="{}", method="{}"'
                 .format(endpoint_url, method))
    try:
        response = session.get(endpoint_url, headers=headers) if method == 'get' \
            else session.post(endpoint_url, headers=headers, data=json.dumps(data) if data else None)
    except requests.exceptions.ConnectionError as exc:
        raise CyberarkException('Connection error: {}'.format(exc))
    if response.ok:
        logger.debug('Got correct response from endpoint: {}'.format(endpoint_url))
        content = json.loads(response.text)
        return content.get(field_name) if field_name else content
    else:
        raise CyberarkException('Received error from Cyberark Vault: {}'
                                .format(json.loads(response.text).get('ErrorMessage')))
