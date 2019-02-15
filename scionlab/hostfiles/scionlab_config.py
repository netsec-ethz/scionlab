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
import io
import json
import logging
import os
import tarfile
import urllib.request
import sys
import subprocess
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
    sys.traceback = None
    args = parse_command_line_args()

    if not args.tar:
        config_info = get_config_info(args)
        config = fetch_config(config_info)
        if config is _CONFIG_EMPTY:
            # stop_scion()
            pass
        elif config is _CONFIG_UNCHANGED:
            # log debug
            pass
        else:
            install_config(config)
            confirm_deployed(args)
    else:
        tar = tarfile.open(args.tar, mode='r')
        install_config(tar)


def parse_command_line_args():
    parser = argparse.ArgumentParser(description='')  # TODO(matzf) doc

    group_fetch = parser.add_argument_group('Fetch configuration options')
    parser.add_argument('--config-info',
                        help="Path to json file containing host-id, secret and the local version. "
                             "(default=%s)" % DEFAULT_CONFIG_INFO_PATH)
    group_fetch.add_argument('--host-id', help='The host ID of the ',
                             type=int)
    group_fetch.add_argument('--host-secret', help='The secret for this host')
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
                        "authentication parameters for this host with --host-id and --host-secret."
                        % DEFAULT_CONFIG_INFO_PATH)
        return _get_config_info_from_file(DEFAULT_CONFIG_INFO_PATH, args)


def _get_config_info_from_file(file, args):
    """
    Load config info file.
    Overwrite url with the URL argument.
    Overwrite the version if '--force' or '--local-version' are given.
    """
    config_info = _load_config_info(file)
    url = args.url or config_info.url or DEFAULT_COORDINATOR_URL
    version = config_info.version
    if args.force:
        version = None
    elif args.local_version:
        version = args.local_version
    return config_info._replace(url=url, version=version)


def _load_config_info(file):
    try:
        with open(file, 'r') as f:
            config_info_dict = json.load(f)
    except IOError as e:
        _error_exit("Error loading the scionlab config info file '%s'" % file, e)
    try:
        return ConfigInfo(config_info_dict['host_id'],
                          config_info_dict['host_secret'],
                          config_info_dict.get('url'),
                          config_info_dict.get('version'))
    except KeyError as e:
        _error_exit("Invalid scionlab config info file '%s'" % file, e)


def fetch_config(config_info):
    url = '{coordinator_url}/api/host/{host_id}/config'.format(
        coordinator_url=config_info.url,
        host_id=config_info.host_id
    )
    data = {'secret': config_info.host_secret}
    # version may be None (if "--force" is used or if version is not in the config info file)
    if config_info.version:
        data['version'] = config_info.version

    try:
        conn = _http_get(url, data)
        response_data = conn.read()
    except urllib.error.HTTPError as e:
        if e.code == 304:
            return _CONFIG_EMPTY
        elif e.code == 204:
            return _CONFIG_UNCHANGED
        else:
            _error_exit("Failed to fetch configuration from SCIONLab coordinator at '%s'"
                        % config_info.url, e)
    return tarfile.open(mode='r:gz', fileobj=io.BytesIO(response_data))


def confirm_deployed(args):
    # Get newly installed config info
    config_info = _load_config_info(DEFAULT_CONFIG_INFO_PATH)
    if args.url:
        config_info = config_info._replace(url=args.url)

    url = '{coordinator_url}/api/host/{host_id}/deployed_config_version'.format(
        coordinator_url=config_info.url,
        host_id=config_info.host_id
    )
    data = {'secret': config_info.host_secret, 'version': config_info.version}
    _http_post(url, data)


def _http_get(url, params):
    """ Helper: make GET request to URL with given params
    :returns: urlopen return
    """
    return urllib.request.urlopen(
        url + '?' + urllib.parse.urlencode(params),
        timeout=REQUEST_TIMEOUT_SECONDS
    )


def _http_post(url, params):
    """ Helper: make POST request to URL with given params """
    return urllib.request.urlopen(
        url,
        data=urllib.parse.urlencode(params).encode('utf-8'),
        timeout=REQUEST_TIMEOUT_SECONDS
    )


def _error_exit(*args, **kwargs):
    logging.error(*args, **kwargs)
    sys.exit(1)


def install_config(tar):
    sc = SCION_PATH
    if not os.path.isdir(sc):
        _error_exit('No SCION installation found at $SC (%s).' % sc)

    gen_members = [f for f in tar.getmembers() if f.path == 'gen' or f.path.startswith('gen/')]
    tar.extractall(members=gen_members, path=sc)

    restart_scion()

    # TODO
    # - VPN Client
    # - VPN Server


def restart_scion():
    # TODO quick reload: only restart if set of processes changed, otherwise trigger config
    # reloading
    sc = SCION_PATH
    scion_sh = os.path.join(sc, 'scion.sh')
    supervisor_sh = os.path.join(sc, 'supervisor/supervisor.sh')
    subprocess.check_call([scion_sh, 'stop'], cwd=sc)
    subprocess.check_call([supervisor_sh, 'reload'], cwd=sc)
    subprocess.check_call([scion_sh, 'start', 'nobuild'], cwd=sc)


if __name__ == '__main__':
    main()
