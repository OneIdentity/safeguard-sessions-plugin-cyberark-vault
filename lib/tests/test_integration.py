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
import pytest
from textwrap import dedent
from ..plugin import Plugin
from safeguard.sessions.plugin_impl.test_utils.plugin import assert_plugin_hook_result


def test_cyberark_integration_getting_password(cy_config, cy_account, cy_asset, cy_account_password, connection_parameters):
    plugin = Plugin(cy_config)

    result = plugin.get_password_list(
        **connection_parameters(server_uname=cy_account, server_ip=cy_asset)
    )

    assert_plugin_hook_result(result, {"passwords": [cy_account_password]})


def test_cyberark_integration_getting_password_for_wrong_user(cy_config, cy_wrong_account, cy_asset, connection_parameters):
    plugin = Plugin(cy_config)

    result = plugin.get_password_list(
        **connection_parameters(server_uname=cy_wrong_account, server_ip=cy_asset)
    )

    assert_plugin_hook_result(result, {"passwords": []})


def test_cyberark_integration_getting_private_key(cy_config, cy_account_with_key, cy_asset, cy_account_private_key, connection_parameters):
    plugin = Plugin(cy_config)

    result = plugin.get_private_key_list(
        **connection_parameters(server_uname=cy_account_with_key, server_ip=cy_asset)
    )

    assert_plugin_hook_result(result, {"private_keys": [("ssh-rsa", cy_account_private_key)]})


def test_cyberark_integration_getting_private_key_for_wrong_account(cy_config, cy_wrong_account, cy_asset, connection_parameters):
    plugin = Plugin(cy_config)

    result = plugin.get_private_key_list(
        **connection_parameters(server_uname=cy_wrong_account, server_ip=cy_asset)
    )

    assert_plugin_hook_result(result, {"private_keys": []})


def test_v10_user_logon(cy_config, cy_account, cy_asset, cy_account_password, connection_parameters):
    config = cy_config + "\nauthentication_method=cyberark"
    plugin = Plugin(config)

    result = plugin.get_password_list(
        **connection_parameters(server_uname=cy_account, server_ip=cy_asset)
    )

    assert_plugin_hook_result(result, {"passwords": [cy_account_password]})


@pytest.mark.skip(reason="I don't know how this was tested before, cannot see settings on our CArk")
def test_v10_ldap_logon(
        cy_address,
        cy_ldap_username,
        cy_ldap_password,
        cy_account,
        cy_asset,
        cy_account_password,
        connection_parameters
):
    config = dedent(
        """
        [cyberark]
        address={}
        use_credential=explicit
        username={}
        password={}
        authentication_method=ldap
    """.format(
            cy_address, cy_ldap_username, cy_ldap_password
        )
    )
    plugin = Plugin(config)

    result = plugin.get_password_list(
        **connection_parameters(server_uname=cy_account, server_ip=cy_asset)
    )

    assert_plugin_hook_result(result, {"passwords": [cy_account_password]})
