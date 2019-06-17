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

import json
import os
import string
import tarfile
from contextlib import closing

from django.conf import settings
from scionlab import scion_config
from scionlab.models.user_as import UserAS
from scionlab.openvpn_config import (
    generate_vpn_client_config,
    generate_vpn_server_config,
    ccd_config,
)
from scionlab.util.archive import TarWriter, tar_add_textfile, tar_add_dir

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
    host = user_as.hosts.get()
    with closing(tarfile.open(mode='w:gz', fileobj=fileobj)) as tar:
        _add_config_info(host, tar)
        scion_config.create_gen(host, TarWriter(tar))
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
    with closing(tarfile.open(mode='w:gz', fileobj=fileobj)) as tar:
        _add_config_info(host, tar)
        scion_config.create_gen(host, TarWriter(tar))
        _add_vpn_config(host, tar)


def is_empty_config(host):
    """
    Check if any services should to be configured to run on the given host.
    """
    return (not host.services.exists()
            and not host.interfaces.exists()
            and not host.vpn_clients.filter(active=True).exists()
            and not host.vpn_servers.exists())


def _add_vpn_config(host, tar):
    """
    Generate the VPN config files and add them to the tar.
    """
    vpn_clients = list(host.vpn_clients.filter(active=True))
    for vpn_client in vpn_clients:
        client_config = generate_vpn_client_config(vpn_client)
        tar_add_textfile(tar, "client.conf", client_config)

    vpn_servers = list(host.vpn_servers.all())
    for vpn_server in vpn_servers:
        tar_add_textfile(tar, "server.conf", generate_vpn_server_config(vpn_server))
        tar_add_dir(tar, 'ccd')
        for vpn_client in vpn_server.clients.iterator():
            common_name, config_string = ccd_config(vpn_client)
            tar_add_textfile(tar, 'ccd/' + common_name, config_string)


def _add_vagrantfiles(host, tar):
    """
    Add the Vagrantfiles and additional required files to the tar.
    Expands the 'Vagrantfile.tmpl'-template.
    """
    tar_add_textfile(tar, "Vagrantfile", _expand_vagrantfile_template(host))

    # Add services and scripts:
    # Note: in the future, some of these may be included in the "box".
    service_files = ["scion.service", "scionupgrade.service",
                     "scionupgrade.timer"]
    script_files = ["run.sh", "scion_install_script.sh", "scionupgrade.sh"]
    for f in service_files + script_files:
        tar.add(_hostfiles_path(f), arcname=f)


def _expand_vagrantfile_template(host):
    if not host.vpn_clients.filter(active=True).exists():
        interface = host.interfaces.get()
        port = interface.bind_port or interface.public_port
        forwarding_string = 'config.vm.network "forwarded_port",' \
                            ' guest: {port}, host: {port}, protocol: "udp"'.format(port=port)
    else:
        forwarding_string = ''

    with open(_hostfiles_path("Vagrantfile.tmpl")) as f:
        vagrant_tmpl = f.read()
    return string.Template(vagrant_tmpl).substitute(
        PortForwarding=forwarding_string,
        hostname="scionlab-" + host.AS.as_id.replace(":", "-"),
        vmname="SCIONLabVM-" + host.AS.as_id,
    )


def _add_config_info(host, tar):
    tar_add_textfile(tar, "gen/scionlab-config.json", _generate_config_info_json(host))


def _generate_config_info_json(host):
    """
    Return a JSON-formatted string; a dict containing the authentication parameters for the host
    and the current configuration version number.
    :param Host host:
    :returns: json string
    """
    config_info = {
        'host_id': host.uid,
        'host_secret': host.secret,
        'version': host.config_version,
        'url': settings.SCIONLAB_SITE
    }
    return json.dumps(config_info)


def _hostfiles_path(filename):
    """
    Shortcut to path join in `_HOSTFILES_DIR`
    """
    return os.path.join(_HOSTFILES_DIR, filename)
