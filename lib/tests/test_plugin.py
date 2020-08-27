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

from textwrap import dedent
from unittest.mock import patch
from pytest import fixture

from safeguard.sessions.plugin_impl.test_utils.plugin import assert_plugin_hook_result
from ..plugin import Plugin


@fixture
def configured_plugin():
    config = dedent(
        """
        [cyberark]
        address = test.vault
        use_credential=explicit
        username = vault_user
        password = vault_pwd
    """
    )
    return Plugin(config)


@patch("lib.client.Client.get_passwords", return_value={"passwords": ["password"]})
def test_do_get_password_list(client, configured_plugin, connection_parameters):
    username = "wsmith"
    server = "1.2.3.4"
    gateway_user = "jsmith"
    password_list = configured_plugin.get_password_list(**connection_parameters(username, server, gateway_user))
    client.assert_called_with(username, server, gateway_user)
    assert_plugin_hook_result(password_list, dict(cookie=dict(account=username, asset=server), passwords=["password"]))


@patch("lib.client.Client.get_passwords", return_value=[])
def test_getting_password_for_unknown_user(client, configured_plugin, connection_parameters):
    password_list = configured_plugin.get_password_list(**connection_parameters())
    assert_plugin_hook_result(password_list, dict(cookie=dict(account=None, asset=None), passwords=[]))
