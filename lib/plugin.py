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
from requests.exceptions import RequestException
from safeguard.sessions.plugin.exceptions import PluginSDKRuntimeError
from safeguard.sessions.plugin.credentialstore_plugin import CredentialStorePlugin
from .client import Client


class Plugin(CredentialStorePlugin):
    def __init__(self, configuration):
        super().__init__(configuration, configuration_section="cyberark")

    def do_get_password_list(self):
        try:
            vault_client = Client.create(
                self.plugin_configuration, self.authentication_username, self.authentication_password
            )
            passwords = vault_client.get_passwords(self.account, self.asset, self.connection.gateway_username)
            return  {"passwords": passwords}
        except (PluginSDKRuntimeError, RequestException) as ex:
            self.logger.error("Error retrieving passwords: %s", ex)
            return None

    def do_get_private_key_list(self):
        try:
            vault_client = Client.create(
                self.plugin_configuration, self.authentication_username, self.authentication_password
            )
            keys = vault_client.get_ssh_keys(self.account, self.asset, self.connection.gateway_username)
            return {
                "private_keys": [
                    type_key for type_key in
                    [
                        (self.determine_key_type(key), key)
                        for key in keys
                    ]
                    if type_key[0]
                ]
            }
        except (PluginSDKRuntimeError, RequestException) as ex:
            self.logger.error("Error retrieving private keys: %s", ex)
            return None
