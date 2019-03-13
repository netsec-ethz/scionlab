#!/usr/bin/env python3
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

"""
TODO(matzf) doc
"""

import argparse
import base64
import filecmp
import io
import json
import logging
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from collections import namedtuple


DEFAULT_SCION_PATH = os.path.expanduser('~/go/src/github.com/scionproto/scion')
SCION_PATH = os.environ.get('SC', DEFAULT_SCION_PATH)

DEFAULT_CONFIG_INFO_PATH = os.path.join(SCION_PATH, 'gen/scionlab-config.json')
DEFAULT_COORDINATOR_URL = 'https://www.scionlab.org'
REQUEST_TIMEOUT_SECONDS = 10


_CONFIG_EMPTY = object()
_CONFIG_UNCHANGED = object()

ConfigInfo = namedtuple('ConfigInfo',
                        ['host_id',
                         'host_secret',
                         'url',
                         'version'])


def main():
    sys.tracebacklimit = -1
    args = parse_command_line_args()

    if not args.tar:
        config_info = get_config_info(args)
        config = fetch_config(config_info)
        if config is _CONFIG_EMPTY:
            # stop_scion()
            pass
        elif config is _CONFIG_UNCHANGED:
            logging.info('Configuration unchanged (version %s). Nothing to do.',
                         config_info.version)
        else:
            install_config(config)
            confirm_deployed(args)
    else:
        tar = tarfile.open(args.tar, mode='r')
        install_config(tar)


def parse_command_line_args():
    parser = argparse.ArgumentParser(description='Install configuration for a SCIONLab host.')

    group_fetch = parser.add_argument_group('Fetch options')
    parser.add_argument('--config-info',
                        help="Path to json file containing host-id, secret and the local version. "
                             "(default=%s)" % DEFAULT_CONFIG_INFO_PATH)
    group_fetch.add_argument('--host-id', help='Host identifier', type=int)
    group_fetch.add_argument('--host-secret', help='Authentication for host')
    # Either 'local-version' or 'force'
    group_version = group_fetch.add_mutually_exclusive_group()
    group_version.add_argument('--local-version', help='',
                               action='store', type=int)
    group_version.add_argument('--force', help='',
                               action='store_true')
    group_fetch.add_argument('--url', help='URL of the SCIONLab coordination service')

    parser.add_argument('--tar')

    return parser.parse_args()


def get_config_info(args):
    if args.config_info:
        return _get_config_info_from_file(args.config_info, args)
    elif args.host_id or args.host_secret:
        if not args.host_id and args.host_secret:
            _error_exit("Either none of or --host-id and --host-secret parameters need to be set")
        return ConfigInfo(args.host_id,
                          args.host_secret,
                          args.url or DEFAULT_COORDINATOR_URL,
                          args.local_version if not args.force else None)
    else:
        if not os.path.exists(DEFAULT_CONFIG_INFO_PATH):
            _error_exit("No scionlab config info file found at '%s'. Please specify the path to "
                        "an existing config info file with --config-info, or explicitly provide "
                        "authentication parameters for this host with --host-id and --host-secret.",
                        DEFAULT_CONFIG_INFO_PATH)
        return _get_config_info_from_file(DEFAULT_CONFIG_INFO_PATH, args)


def _get_config_info_from_file(file, args):
    """
    Load config info file.
    Overwrite url with the URL argument.
    Overwrite the version if '--force' or '--local-version' are given.
    """
    config_info = _load_config_info(file)

    if args.url:
        config_info = config_info._replace(url=args.url)

    if args.force:
        config_info = config_info._replace(version=None)
    elif args.local_version:
        config_info = config_info._replace(version=args.local_version)

    return config_info


def _load_config_info(file):
    """
    Load and parse the config info json-file.
    :returns: ConfigInfo
    """
    try:
        with open(file, 'r') as f:
            config_info_dict = json.load(f)
    except IOError as e:
        _error_exit("Error loading the scionlab config info file '%s': %s", file, e)
    try:
        return ConfigInfo(config_info_dict['host_id'],
                          config_info_dict['host_secret'],
                          config_info_dict.get('url') or DEFAULT_COORDINATOR_URL,
                          config_info_dict.get('version'))
    except KeyError as e:
        _error_exit("Invalid scionlab config info file '%s': %s", file, e)


def fetch_config(config_info):
    """
    Request configuration tar-ball from SCIONLab coordinator.

    If available from either the config file or the command line and --force is not used, the
    request sent to the coordinator will include the currently installed version. If the current
    version is already the latest version, the server will reply with 304 Not Modified.

    :param ConfigInfo config_info: base url, host-id/secret for authentication, version (optional).
    :returns:
        - _CONFIG_UNCHANGED if the current version is already the latest version, or
        - _CONFIG_EMPTY if there is currently no configuration for this host, or
        - tarfile.tar the configuration archive
    """

    url = '{coordinator_url}/api/host/{host_id}/config'.format(
        coordinator_url=config_info.url.rstrip('/'),
        host_id=config_info.host_id
    )

    # version may be None (if "--force" is used or if version is not in the config info file)
    data = {}
    if config_info.version:
        data['version'] = config_info.version

    try:
        conn = _http_get(url, data, username=config_info.host_id, password=config_info.host_secret)
        response_data = conn.read()
    except urllib.error.HTTPError as e:
        if e.code == 304:
            return _CONFIG_UNCHANGED
        elif e.code == 204:
            return _CONFIG_EMPTY
        else:
            _error_exit("Failed to fetch configuration from SCIONLab coordinator at %s: %s",
                        config_info.url, e)
    except Exception as e:
            _error_exit("Failed to fetch configuration from SCIONLab coordinator at %s: %s",
                        config_info.url, e)
    return tarfile.open(mode='r:gz', fileobj=io.BytesIO(response_data))


def confirm_deployed(args):
    """
    Inform the SCIONLab coordinator of the currently installed version of the configuration. This
    confirms that this version has been sucessfully installed. This information is used coordinator
    by the coordinator only in the case where it actively pushes configuration to a host. A failure
    in this step is generally unproblematic.

    :param args: commandline arguments for optional coordinator URL
    """
    # Get newly installed config info
    config_info = _load_config_info(DEFAULT_CONFIG_INFO_PATH)
    if args.url:
        config_info = config_info._replace(url=args.url)

    url = '{coordinator_url}/api/host/{host_id}/deployed_config_version'.format(
        coordinator_url=config_info.url.rstrip('/'),
        host_id=config_info.host_id
    )
    data = {'version': config_info.version}
    _http_post(url, data, username=config_info.host_id, password=config_info.host_secret)


def _http_get(url, params, username, password):
    """ Helper: make GET request to URL with given params.  """
    query = ''
    if params:
        query += '?' + urllib.parse.urlencode(params)
    request = urllib.request.Request(url + query)
    _add_basic_auth(request, username, password)
    return urllib.request.urlopen(
        request,
        timeout=REQUEST_TIMEOUT_SECONDS
    )


def _http_post(url, params, username, password):
    """ Helper: make POST request to URL with given params """

    request = urllib.request.Request(url,
                                     data=urllib.parse.urlencode(params).encode('utf-8'),
                                     method='POST')
    _add_basic_auth(request, username, password)
    return urllib.request.urlopen(
        request,
        timeout=REQUEST_TIMEOUT_SECONDS
    )


def _add_basic_auth(request, username, password):
    """ Helper: add basic authorization header to a request """
    uname_pwd = '%s:%s' % (username, password)
    uname_pwd_encoded = base64.b64encode(uname_pwd.encode('utf-8')).decode('ascii')
    request.add_header("Authorization", "Basic %s" % uname_pwd_encoded)


def _error_exit(*args, **kwargs):
    logging.error(*args, **kwargs)
    sys.exit(1)


def install_config(tar):
    try:
        tmpdir = tempfile.mkdtemp()
        tar.extractall(path=tmpdir)
        install_scion_config(tmpdir)
        install_vpn_client_config(tmpdir)
        install_vpn_server_config(tmpdir)
    finally:
        shutil.rmtree(tmpdir)


def install_scion_config(tmpdir):
    sc = SCION_PATH
    if not os.path.isdir(sc):
        _error_exit('No SCION installation found at $SC (%s).', sc)
    _mv_dir(tmpdir, 'gen', sc)
    restart_scion()


def restart_scion():
    # TODO quick reload: only restart if set of processes changed, otherwise trigger config
    # reloading
    sc = SCION_PATH
    scion_sh = os.path.join(sc, 'scion.sh')
    supervisor_sh = os.path.join(sc, 'supervisor/supervisor.sh')
    subprocess.check_call([scion_sh, 'stop'], cwd=sc)
    subprocess.check_call([supervisor_sh, 'reload'], cwd=sc)
    subprocess.check_call([scion_sh, 'start', 'nobuild'], cwd=sc)


def install_vpn_client_config(tmpdir):
    # TODO subfolder "vpn_client"?
    changed = _install_file(tmpdir, 'client.conf', '/etc/openvpn/')
    if changed:
        subprocess.check_call(['sudo', 'systemctl', 'reload-or-restart', 'openvpn@client'])


def install_vpn_server_config(tmpdir):
    changed = _install_file(tmpdir, 'server.conf', '/etc/openvpn/')
    if changed:
        subprocess.check_call(['sudo', 'systemctl', 'reload-or-restart', 'openvpn@client'])
    _sudo_mv(os.path.join(tmpdir, 'openvpn_ccd'), '/etc/openvpn')


def _mv_dir(srcdir, dirname, dstdir):
    shutil.rmtree(os.path.join(dstdir, dirname), ignore_errors=True)
    shutil.move(os.path.join(srcdir, dirname), dstdir)


def _install_file(srcdir, filename, dstdir):
    """
    Installs the file into the dir at the path.
    Returns False iff the file was changed.
    If the member doesn't exist, the file at path will be removed.
    """
    srcfilename = os.path.join(srcdir, filename)
    dstfilename = os.path.join(srcdir, filename)
    if not os.path.exists(srcfilename):
        if os.path.exists(dstfilename):
            os.remove(dstfilename)
            return True
        return False

    try:
        equal = filecmp.cmp(srcfilename, dstfilename, shallow=False)
    except FileNotFoundError:
        equal = False
    if not equal:
        _sudo_mv(srcfilename, dstfilename)
    return not equal


def _sudo_mv(src, dst):
    subprocess.check_call(["sudo", "mv", src, dst])


if __name__ == '__main__':
    main()
