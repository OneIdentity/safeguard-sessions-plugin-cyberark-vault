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
import pytest


@pytest.fixture
def cy_address(site_parameters):
    return site_parameters["address"]


@pytest.fixture
def cy_username(site_parameters):
    return site_parameters["username"]


@pytest.fixture
def cy_password(site_parameters):
    return site_parameters["password"]


@pytest.fixture
def cy_ldap_username(site_parameters):
    return site_parameters["ldap_username"]


@pytest.fixture
def cy_ldap_password(site_parameters):
    return site_parameters["ldap_password"]


@pytest.fixture
def cy_account(site_parameters):
    return site_parameters["account"]


@pytest.fixture
def cy_account_password(site_parameters):
    return site_parameters["account_password"]


@pytest.fixture
def cy_asset(site_parameters):
    return site_parameters["asset"]


@pytest.fixture
def cy_wrong_account(site_parameters):
    return site_parameters["wrong_account"]


@pytest.fixture
def cy_config(site_parameters):
    yield dedent(
        """
        [cyberark]
        address = {address}
        use_credential=explicit
        username = {username}
        password = {password}
    """.format(
            address=site_parameters["address"],
            username=site_parameters["username"],
            password=site_parameters["password"],
        )
    )


@pytest.fixture
def connection_parameters():
    def wrapper(server_uname="unknown", server_hname="unknown", gateway_uname="unknown", server_ip="unknown"):
        return dict(
            cookie=dict(),
            session_cookie=dict(),
            server_username=server_uname,
            server_hostname=server_hname,
            gateway_username=gateway_uname,
            protocol="SSH",
            session_id="the_id",
            client_ip="1.2.3.4",
            client_hostname="client_host",
            gateway_domain="gateway.domain",
            gateway_password="unknown",
            gateway_groups=[],
            server_domain="acme.com",
            server_ip=server_ip,
            server_port=22,
        )
    return wrapper
