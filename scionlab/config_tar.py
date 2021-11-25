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
import pathlib

from django.conf import settings
from jinja2 import Environment
from scionlab.defines import OPENVPN_CONFIG_DIR
from scionlab.scion.config import generate_systemd_scion_config, generate_supervisord_scion_config
from scionlab.models.user_as import UserAS
from scionlab.openvpn_config import (
    generate_vpn_client_config,
    generate_vpn_server_config,
    ccd_config,
)
from scionlab.util.archive import HashedArchiveWriter

_HOSTFILES_DIR = os.path.join(settings.BASE_DIR, "scionlab", "hostfiles")


# Version of the config generation process. This number is included the version string in
# the scionlab-config.json manifest file in the configuration tar ball.
# This version number should be incremented whenever code changes globally affect the generated
# configuration of hosts.
CONFIG_GEN_VERSION = 14


def generate_user_as_config_tar(user_as, archive):
    """
    Write the configuration for the given UserAS to the archive.

    The difference to `generate_host_config` is that an appropriate README file and
    optionally the configuration for the VM are included.

    :param Host host: the Host for which config should be generated
    :param scionlab.util.archive.BaseArchiveWriter archive: output archive-writer
    """
    host = user_as.hosts.get()
    if user_as.installation_type == UserAS.VM:
        _add_files_user_as_vm(archive, host)
    elif user_as.installation_type == UserAS.PKG:
        _add_files_user_as_pkg(archive, host)
    else:
        assert user_as.installation_type == UserAS.SRC
        _add_files_user_as_src(archive, host)


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


def _add_files_user_as_pkg(archive, host):
    """
    The configuration tar for a PKG user AS contains:
    - README
    - scionlab-config.json metadata file
    - scion config /etc/scion/*
    - VPN config /etc/openvpn/client-scionlab-*.conf (if using VPN)
    """
    generate_host_config_tar(host, archive)
    archive.add("README.md", _hostfiles_path("README_dedicated.md"))


def _add_files_user_as_src(archive, host):
    """
    The configuration tar for a SRC user AS contains:
    - README
    - full gen directory, including supervisord files
    - VPN config /etc/openvpn/client-scionlab-*.conf (if using VPN)
    """
    _add_vpn_client_configs(host, archive)
    generate_supervisord_scion_config(host, archive, with_sig_dummy_entry=True)
    archive.add("README.md", _hostfiles_path("README_dedicated.md"))


def generate_host_config_tar(host, archive):
    """
    Write the configuration for the given host to the archive.

    :param Host host: the Host for which config should be generated
    :param scionlab.util.archive.BaseArchiveWriter archive: output archive-writer
    """
    hashed_archive = HashedArchiveWriter(archive)
    units = generate_systemd_scion_config(host,
                                          hashed_archive,
                                          with_sig_dummy_entry=hasattr(host.AS, 'useras'))
    _add_vpn_client_configs(host, hashed_archive)  # note: not adding these to the file list
    _add_vpn_server_config(host, hashed_archive)
    _add_config_info(host, hashed_archive.hashes, units, archive)


def is_empty_config(host):
    """
    Check if any services should to be configured to run on the given host.
    """
    return host.AS is None


def fmt_config_version(host, gen=CONFIG_GEN_VERSION):
    """
    Build the version string the configuration, consisting of a generation version part and a host
    version part.
    """
    return "%i.%i" % (gen, host.config_version)


def _add_vpn_client_configs(host, archive):
    """
    Generate the VPN config files and add them to the tar.
    """
    vpn_dir = OPENVPN_CONFIG_DIR.lstrip("/")  # don't use absolute paths in the archive
    # Each host can run at most one VPN-Client per VPN
    clients = host.vpn_clients.filter(active=True).select_related('vpn__server__AS').all()
    configs = dict()
    for client in clients:
        name = client.vpn.server.AS.isd_as_path_str()
        configs[name] = generate_vpn_client_config(client)

    for name, config in configs.items():
        archive.write_text((vpn_dir, "client-scionlab-{}.conf".format(name)), config)


def _add_vpn_server_config(host, archive):
    vpn_dir = OPENVPN_CONFIG_DIR.lstrip("/")  # don't use absolute paths in the archive
    server = host.vpn_servers.first()  # only one server per host supported for now
    if server:
        archive.write_text((vpn_dir, "server.conf"), generate_vpn_server_config(server))
        archive.add_dir((vpn_dir, "ccd"))
        for client in server.clients.iterator():
            common_name, config_string = ccd_config(client)
            archive.write_text((vpn_dir, "ccd", common_name), config_string)


def _add_vagrantfiles(host, archive):
    """
    Add the Vagrantfiles and additional required files to the tar.
    Expands the 'Vagrantfile.tmpl'-template.
    """
    archive.write_text("Vagrantfile", _expand_vagrantfile_template(host))


def _expand_vagrantfile_template(host):
    public_ifaces = [iface for iface in host.interfaces.iterator()
                     if not UserAS.is_link_over_vpn(iface)]
    forwarded_ports = [iface.public_port for iface in public_ifaces]

    vagrant_tmpl = pathlib.Path(_hostfiles_path("Vagrantfile.tmpl")).read_text()

    env = Environment(lstrip_blocks=True, trim_blocks=True)
    return env.from_string(vagrant_tmpl).render(
        forwarded_ports=forwarded_ports,
        host_id=host.uid,
        host_secret=host.secret,
        url=settings.SCIONLAB_SITE,
        hostname="scionlab-" + host.AS.as_id.replace(":", "-"),
        vmname="SCIONLabVM-" + host.AS.as_path_str()
    )


def _add_config_info(host, hashes, systemd_units, archive):
    archive.write_json('scionlab-config.json',
                       _generate_config_info_json(host, hashes, systemd_units))


def _generate_config_info_json(host, hashes, systemd_units):
    """
    Return a dict containing
    - authentication parameters for the host
    - current configuration version number
    - hashes of all installed config files; used in scionlab-config to determine
      whether a file has local changes
    - list of systemd units to be started

    :param Host host:
    :param hashes: dict filename -> hash
    :param List[str] systemd_units:
    :returns: dict
    """
    config_info = {
        'host_id': host.uid,
        'host_secret': host.secret,
        'url': settings.SCIONLAB_SITE,
        'version': fmt_config_version(host),
        'files': hashes,
        'systemd_units': systemd_units,
    }
    return config_info


def _hostfiles_path(filename):
    """
    Shortcut to path join in `_HOSTFILES_DIR`
    """
    return os.path.join(_HOSTFILES_DIR, filename)
