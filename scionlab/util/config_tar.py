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
import shutil
import tarfile
import tempfile
from contextlib import closing

from django.conf import settings
from scionlab.util import generate
from scionlab.models import UserAS

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
        _add_gen_folder(host, tar)
        _add_vpn_config(host, tar)
        if user_as.installation_type == UserAS.VM:
            tar.add(_hostfiles_path("README_vm.md"), arcname="README.md")
            _add_vagrantfiles(user_as, tar)
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
        _add_gen_folder(host, tar)
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
    # TODO(matzf)
    pass


def _add_gen_folder(host, tar):
    """
    Generate the gen/-folder config and it to the tar.
    """
    # Add the gen/-folder
    gen_dir = tempfile.mkdtemp()
    generate.create_gen(host, gen_dir)
    tar.add(gen_dir, arcname="gen")
    shutil.rmtree(gen_dir)


def _add_vpn_config(host, tar):
    """
    Generate the VPN config files and add them to the tar.
    """
    vpn_clients = list(host.vpn_clients.filter(active=True))
    for vpn_client in vpn_clients:
        # TODO Get file from issue #10
        # _tar_add_textfile(tar, "client.conf", generate_vpn_client_conf(vpn_client))
        raise NotImplementedError('Missing OpenVPN client.conf generation.')

    vpn_servers = list(host.vpn_servers.all())
    for vpn_server in vpn_servers:
        # TODO Get server config file from issue #10
        # _tar_add_textfile(tar, "server.conf", generate_vpn_server_conf(vpn_server))
        raise NotImplementedError('Missing OpenVPN server.conf generation.')


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
    vagrant_file_content = vagrant_tmpl.\
        replace("{{.PortForwarding}}", forwarding_string).\
        replace("{{.ASID}}", host.AS.as_id)
    _tar_add_textfile(tar, "Vagrantfile", vagrant_file_content)

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


def _tar_add_textfile(tar, name, content):
    """
    Helper for tarfile: add a text-file `name` with the given `content` to a tarfile `tar`.
    :param TarFile tar: an open tarfile.TarFile
    :param str name: name for the file in the tarfile
    :param str content: file content
    """
    tarinfo = tarfile.TarInfo()
    tarinfo.name = name
    content_bytes = content.encode()
    tarinfo.size = len(content_bytes)
    tar.addfile(tarinfo, io.BytesIO(content_bytes))
