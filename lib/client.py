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
import abc
import json
import requests
from contextlib import contextmanager
from urllib.parse import urljoin

from safeguard.sessions.plugin.requests_tls import RequestsTLS
from safeguard.sessions.plugin.logging import get_logger
from safeguard.sessions.plugin.endpoint_extractor import EndpointExtractor

logger = get_logger(__name__)


class Client:
    def __init__(self, requests_tls, address_url, username, password, authenticator):
        self.__requests_tls = requests_tls
        self.__address_url = address_url
        self.__username = username
        self.__password = password
        self.__authenticator = authenticator
        self.__endpoint_extractor = EndpointExtractor(self.__address_url)
        self.__search_url_template = "PasswordVault/api/Accounts?search={}&sort=UserName"

    @classmethod
    def create(cls, config, username, password):
        requests_tls = RequestsTLS.from_config(config)
        address_url = "{}://{}".format(
            "https" if requests_tls.tls_enabled else "http", config.get("cyberark", "address", required=True)
        )

        return Client(
            requests_tls=requests_tls,
            address_url=address_url,
            username=username,
            password=password,
            authenticator=AuthenticatorFactory.create(config),
        )

    def get_passwords(self, account, asset, gateway_username):
        with self.__requests_tls.open_session() as session:
            with self.__authenticator.authenticate(
                session, self.__address_url, self.__username, self.__password
            ) as auth_token:
                passwords = []
                found_objects = self.__search_for_account_asset_secrets(session, auth_token, account, asset)
                logger.debug("Found the following secrets: %s", found_objects)
                if len(found_objects) == 0:
                    logger.debug(
                        "No password found in vault for this account and/or asset: account=%s, asset=%s", account, asset
                    )
                    return passwords
                secret_endpoints = self.__create_secret_endpoints(self.__is_password, found_objects, account, asset)
                logger.debug("Will retrieve secrets from the following endpoints: %s", ",".join(secret_endpoints))
                for se in secret_endpoints:
                    logger.debug("Getting password from: %s", se)
                    passwords.append(self.__endpoint_extractor.extract_data_from_endpoint(
                        session,
                        endpoint_url=se,
                        headers=self.__make_headers(auth_token),
                        method="post",
                        data=self.__contruct_post_data(gateway_username, asset),
                    ))
                return passwords

    def get_ssh_keys(self, account, asset, gateway_username):
        with self.__requests_tls.open_session() as session:
            with  self.__authenticator.authenticate(
                session, self.__address_url, self.__username, self.__password
            ) as auth_token:
                keys = []
                found_objects = self.__search_for_account_asset_secrets(session, auth_token, account, asset)
                if len(found_objects) == 0:
                    logger.debug(
                        "No keys found in vault for this account and/or asset: account=%s, asset=%s", account, asset
                    )
                    return keys
                secret_endpoints = self.__create_secret_endpoints(self.__is_ssh_key, found_objects, account, asset)
                for se in secret_endpoints:
                    response = session.post(
                        urljoin(self.__address_url, se),
                        headers=self.__make_headers(auth_token),
                        data=json.dumps(self.__contruct_post_data(gateway_username, asset)),
                        params=None,
                    )
                    if response.ok:
                        keys.append(response.text.strip("\""))
                return keys

    def __search_for_account_asset_secrets(self, session, auth_token, account, asset):
        return self.__endpoint_extractor.extract_data_from_endpoint(
            session,
            endpoint_url=self.__search_url_template.format(",".join([account, asset])),
            data_path="value",
            headers=self.__make_headers(auth_token),
            method="get",
       )

    @staticmethod
    def __create_secret_endpoints(secret_type_determinant, found_objects, account, asset):
        return [
            f"PasswordVault/api/Accounts/{fo.get('id')}/Password/Retrieve"
            for fo in found_objects
            if secret_type_determinant(fo, account, asset)
        ]

    @staticmethod
    def __make_headers(auth_token):
        return {"Content-Type": "application/json", "Authorization": auth_token}

    @staticmethod
    def __is_password(found_object, account, asset):
        return (account == found_object.get("userName") and asset == found_object.get("address") and found_object.get("secretType") == "password")

    @staticmethod
    def __is_ssh_key(found_object, account, asset):
        return (account == found_object.get("userName") and asset == found_object.get("address") and found_object.get("secretType") == "key")

    @staticmethod
    def __contruct_post_data(gateway_user, asset):
        return {
            "reason": "{},SPS".format(gateway_user),
            "TicketingSystemName": "",
            "TicketId": "",
            "Version": 0,
            "ActionType": "show",
            "isUse": False,
            "Machine": asset,
        }


class AuthenticatorFactory:
    @classmethod
    def create(cls, config):
        authentication_method = config.getienum(
            "cyberark",
            "authentication_method",
            value_set=V9Authenticator.TYPES + V10Authenticator.TYPES,
            default="legacy",
        )
        if authentication_method in V9Authenticator.TYPES:
            return V9Authenticator(authentication_method)
        else:
            return V10Authenticator(authentication_method)


class Authenticator:
    def __init__(self, auth_type):
        self._authorization = None
        self._type = auth_type

    @abc.abstractmethod
    def authenticate(self, session, base_url, username, password):
        raise NotImplementedError()

    @abc.abstractmethod
    def logoff(self, session, base_url):
        raise NotImplementedError()

    def common_logoff(self, session, url):
        if self._authorization is None:
            return
        logger.debug("Logoff from CyberArk Vault; url=%s", url)
        try:
            response = session.post(
                url, headers={"Content-Type": "application/json", "Authorization": self._authorization}
            )
            if not response.ok:
                logger.warning("Logoff from CyberArk Vault failed; status=%s", response.status_code)
        except requests.exceptions.RequestException as ex:
            logger.warning("Logoff from CyberArk Vault failed; exception=%s", ex)


class V9Authenticator(Authenticator):
    TYPES = ("legacy",)

    @contextmanager
    def authenticate(self, session, base_url, username, password):
        auth_post_data = {
            "username": username,
            "password": password,
            "useRadiusAuthentication": False,
            "connectionNumber": "1",
        }
        self._authorization = EndpointExtractor().extract_data_from_endpoint(
            session,
            endpoint_url=base_url + "/PasswordVault/WebServices/auth/Cyberark/CyberArkAuthenticationService.svc/Logon",
            headers={"Content-Type": "application/json"},
            method="post",
            data_path="CyberArkLogonResult",
            data=auth_post_data,
        )
        try:
            yield self._authorization
        finally:
            self.logoff(session, base_url)

    def logoff(self, session, base_url):
        self.common_logoff(
            session, base_url + "/PasswordVault/WebServices/auth/Cyberark/CyberArkAuthenticationService.svc/Logoff"
        )


class V10Authenticator(Authenticator):
    TYPES = ("cyberark", "ldap", "radius", "windows")
    TYPE_TO_ENDPOINT = {"cyberark": "CyberArk", "ldap": "LDAP", "radius": "radius", "windows": "Windows"}

    @contextmanager
    def authenticate(self, session, base_url, username, password):
        auth_post_data = {"username": username, "password": password}
        self._authorization = EndpointExtractor().extract_data_from_endpoint(
            session,
            data_path=None,
            endpoint_url=base_url + "/PasswordVault/API/Auth/{}/Logon".format(self.TYPE_TO_ENDPOINT[self._type]),
            headers={"Content-Type": "application/json"},
            method="post",
            data=auth_post_data,
        )
        try:
            yield self._authorization
        finally:
            self.logoff(session, base_url)

    def logoff(self, session, base_url):
        self.common_logoff(session, base_url + "/PasswordVault/API/Auth/Logoff")
