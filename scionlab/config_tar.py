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
import pathlib

from django.conf import settings
from scionlab import scion_config
from scionlab.defines import GEN_PATH
from scionlab.models.user_as import UserAS
from scionlab.openvpn_config import (
    generate_vpn_client_config,
    generate_vpn_server_config,
    ccd_config,
)

_HOSTFILES_DIR = os.path.join(settings.BASE_DIR, "scionlab", "hostfiles")


def generate_user_as_config_tar(user_as, archive):
    """
    Create the configuration tar-gz-ball for the given UserAS and write to the given writable
    file-like object.

    The difference to `generate_host_config` is that additionally, an appropriate README file and
    optionally the configuration for the VM are included.

    :param Host host: the Host for which config should be generated
    :param scionlab.util.archive.BaseArchiveWriter archive: output archive-writer
    """
    host = user_as.hosts.get()
    if user_as.installation_type == UserAS.VM:
        _add_files_user_as_vm(archive, host)
    elif user_as.installation_type == UserAS.PKG:
        _add_files_user_as_dedicated(archive, host, scion_config.ProcessControl.SYSTEMD)
    else:
        assert user_as.installation_type == UserAS.SRC
        _add_files_user_as_dedicated(archive, host, scion_config.ProcessControl.SUPERVISORD)


def _add_files_user_as_vm(archive, host):
    """
    The configuration tar for a VM user AS contains:
    - Vagrantfile
    - README

    Does NOT contain the actual scion configuration (the "gen/" folder), as this will
    be fetched (using the host-api) during the Vagrant provisioning using scionlab-config.
    """
    _add_vagrantfiles(host, archive)
    archive.add("README.md", _hostfiles_path("README_vm.md"))


def _add_files_user_as_dedicated(archive, host, process_control):
    """
    The configuration tar for a SRC or PKG user AS contains:
    - README
    - if PKG: scionlab-services.txt file listing the services running in the host
    - config_info file (scionlab-config.json) inside the gen directory
    - full gen directory:
        - if SRC: including supervisord files
    - VPN file client.conf (if using VPN)
    """

    _add_config_info(host, archive, with_version=True)
    _add_ia_file(host, archive)
    scion_config.create_gen(host, archive, process_control)
    _add_vpn_config(host, archive)
    archive.add("README.md", _hostfiles_path("README_dedicated.md"))


def generate_host_config_tar(host, archive):
    """
    Create the configuration tar-gz-ball for the given host and write to the given writable
    file-like object.
    :param Host host: the Host for which config should be generated
    :param scionlab.util.archive.BaseArchiveWriter archive: output archive-writer
    """
    _add_config_info(host, archive, with_version=True)
    _add_ia_file(host, archive)
    _add_vpn_config(host, archive)
    scion_config.create_gen(host, archive, scion_config.ProcessControl.SYSTEMD)


def is_empty_config(host):
    """
    Check if any services should to be configured to run on the given host.
    """
    return (not host.services.exists()
            and not host.interfaces.exists()
            and not host.vpn_clients.filter(active=True).exists()
            and not host.vpn_servers.exists())


def _add_vpn_config(host, archive):
    """
    Generate the VPN config files and add them to the tar.
    """
    vpn_clients = list(host.vpn_clients.filter(active=True))
    for vpn_client in vpn_clients:
        client_config = generate_vpn_client_config(vpn_client)
        archive.write_text("client.conf", client_config)

    vpn_servers = list(host.vpn_servers.all())
    for vpn_server in vpn_servers:
        archive.write_text("server.conf", generate_vpn_server_config(vpn_server))
        archive.add_dir("ccd")
        for vpn_client in vpn_server.clients.iterator():
            common_name, config_string = ccd_config(vpn_client)
            archive.write_text("ccd/" + common_name, config_string)


def _add_vagrantfiles(host, archive):
    """
    Add the Vagrantfiles and additional required files to the tar.
    Expands the 'Vagrantfile.tmpl'-template.
    """
    archive.write_text("Vagrantfile", _expand_vagrantfile_template(host))


def _expand_vagrantfile_template(host):
    if not host.vpn_clients.filter(active=True).exists():
        interface = host.interfaces.get()
        port = interface.bind_port or interface.public_port
        forwarding_string = 'config.vm.network "forwarded_port",' \
                            ' guest: {port}, host: {port}, protocol: "udp"'.format(port=port)
    else:
        forwarding_string = ''

    vagrant_tmpl = pathlib.Path(_hostfiles_path("Vagrantfile.tmpl")).read_text()

    return string.Template(vagrant_tmpl).safe_substitute(
        PortForwarding=forwarding_string,
        host_id=host.uid,
        host_secret=host.secret,
        url=settings.SCIONLAB_SITE,
        hostname="scionlab-" + host.AS.as_id.replace(":", "-"),
        vmname="SCIONLabVM-" + host.AS.as_id.as_path_str()
    )


def _add_config_info(host, archive, with_version):
    archive.write_json((GEN_PATH, 'scionlab-config.json'),
                       _generate_config_info_json(host, with_version))


def _generate_config_info_json(host, with_version):
    """
    Return a JSON-formatted string; a dict containing the authentication parameters for the host
    and the current configuration version number.
    :param Host host:
    :returns: json string
    """
    config_info = {
        'host_id': host.uid,
        'host_secret': host.secret,
        'url': settings.SCIONLAB_SITE
    }
    if with_version:
        config_info['version'] = host.config_version
    return config_info


def _add_ia_file(host, archive):
    archive.write_text((GEN_PATH, 'ia'),
                       host.AS.isd_as_path_str())


def _hostfiles_path(filename):
    """
    Shortcut to path join in `_HOSTFILES_DIR`
    """
    return os.path.join(_HOSTFILES_DIR, filename)
