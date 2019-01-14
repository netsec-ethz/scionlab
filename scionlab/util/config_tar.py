# Copyright 2018 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import string
import tarfile
from contextlib import closing

from django.conf import settings
from scionlab.util import generate
from scionlab.util.archive import TarWriter, tar_add_textfile
from scionlab.models import UserAS
from scionlab.util.openvpn_config import generate_vpn_client_config, generate_vpn_server_config, \
    ccd_config

_HOSTFILES_DIR = os.path.join(settings.BASE_DIR, "scionlab", "hostfiles")


def generate_user_as_config_tar(user_as, fileobj):
    """
    Create the configuration tar-gz-ball for the given UserAS and write to the given writable
    file-like object.

    The difference to `generate_host_config` is that additionally, an appropriate README file and
    optionally the configuration for the VM are included.

    :param Host host: the Host for which config should be generated
    :param fileobj: writable, file-like object for output
    """
    _ensure_certificates(user_as)

    host = user_as.hosts.get()
    with closing(tarfile.open(mode='w:gz', fileobj=fileobj)) as tar:
        generate.create_gen(host, TarWriter(tar))
        _add_vpn_config(host, tar)
        if user_as.installation_type == UserAS.VM:
            tar.add(_hostfiles_path("README_vm.md"), arcname="README.md")
            _add_vagrantfiles(host, tar)
        else:
            tar.add(_hostfiles_path("README_dedicated.md"), arcname="README.md")


def generate_host_config_tar(host, fileobj):
    """
    Create the configuration tar-gz-ball for the given host and write to the given writable
    file-like object.
    :param Host host: the Host for which config should be generated
    :param fileobj: writable, file-like object for output
    """
    _ensure_certificates(host.AS)

    with closing(tarfile.open(mode='w:gz', fileobj=fileobj)) as tar:
        generate.create_gen(host, TarWriter(tar))
        _add_vpn_config(host, tar)


def is_empty_config(host):
    """
    Check if any services should to be configured to run on the given host.
    """
    return (not host.services.exists()
            and not host.interfaces.exists()
            and not host.vpn_clients.filter(active=True).exists()
            and not host.vpn_servers.exists())


def _ensure_certificates(as_):
    """
    Create/update TRC and AS certificates if necessary.
    """
    # XXX(matzf): this is a bad design flaw. The idea was to generate trc and certs "asynchronously"
    # and "on demand" during the actual config file generation, to allow for multiple updates to
    # be included in one TRC/cert version update.
    # But now i notice this is bad; lets say an admin is making some changes to the ISD core that
    # should be "bundled" in one TRC/certificate update; e.g. renew keys for multiple ASes, add and
    # remove core ASes. If any user as in the ISD downloads its configuration during this process,
    # the TRC will be regenerated.
    # The time at which the TRC will be created now just seems random.
    # Also, we cannot update the TRC arbitrarily often; can NOT skip versions (might need an
    # additional mechanism to keep track of this btw.)
    #
    # Planning to remove this `needs_update` in favour of explicit, "synchronous" cert/TRC
    # generation. Will make it impossible to "simply" bundle changes, but still seems better. If we
    # want to be able to bundle changes, we can maybe later introduce this explicitly...

    isd = as_.isd
    if isd.trc_needs_update:
        isd.update_trc()
        isd.save()
    isd.ases.update_certificates()
    as_.refresh_from_db()


def _add_vpn_config(host, tar):
    """
    Generate the VPN config files and add them to the tar.
    """
    vpn_clients = list(host.vpn_clients.filter(active=True))
    for vpn_client in vpn_clients:
        client_config = generate_vpn_client_config(vpn_client.host.AS.attachment_point.AS,
                                                   vpn_client.private_key,
                                                   vpn_client.cert)
        tar_add_textfile(tar, "client.conf", client_config)

    vpn_servers = list(host.vpn_servers.all())
    for vpn_server in vpn_servers:
        tar_add_textfile(tar, "server.conf", generate_vpn_server_config(vpn_server))
        for vpn_client in vpn_server.clients:
            common_name, config_string = ccd_config(vpn_client)
            tar_add_textfile(tar, common_name, config_string)


def _add_vagrantfiles(host, tar):
    """
    Add the Vagrantfiles and additional required files to the tar.
    Expands the 'Vagrantfile.tmpl'-template.
    """
    if not host.vpn_clients.filter(active=True).exists():
        forwarding_string = 'config.vm.network "forwarded_port",' \
                            ' guest: {0}, host: {0}, protocol: "udp"'. \
            format(host.interfaces.get().public_port)
    else:
        forwarding_string = ''

    with open(_hostfiles_path("Vagrantfile.tmpl")) as f:
        vagrant_tmpl = f.read()
    vagrant_file_content = string.Template(vagrant_tmpl).substitute(
        PortForwarding=forwarding_string,
        ASID=host.AS.as_id,
    )
    tar_add_textfile(tar, "Vagrantfile", vagrant_file_content)

    # Add services and scripts:
    # Note: in the future, some of these may be included in the "box".
    service_files = ["scion.service", "scionupgrade.service",
                     "scion-viz.service", "scionupgrade.timer"]
    script_files = ["run.sh", "scionupgrade.sh"]
    for f in service_files + script_files:
        tar.add(_hostfiles_path(f), arcname=f)


def _hostfiles_path(filename):
    """
    Shortcut to path join in `_HOSTFILES_DIR`
    """
    return os.path.join(_HOSTFILES_DIR, filename)
