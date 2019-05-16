# Copyright 2017 ETH Zurich
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

# Stdlib
import configparser
import os
import pathlib
from string import Template

# SCION
from scionlab.models.core import Service
from lib.crypto.asymcrypto import (
    get_core_sig_key_file_path,
    get_enc_key_file_path,
    get_sig_key_file_path,
)
from lib.crypto.util import (
    CERT_DIR,
    get_offline_key_file_path,
    get_online_key_file_path,
    get_master_key_file_path,
    MASTER_KEY_0,
    MASTER_KEY_1,
)
from lib.defines import (
    AS_CONF_FILE,
    PROJECT_ROOT,
    SCIOND_API_SOCKDIR,
    PATH_POLICY_FILE,
    GEN_PATH,
)

DEFAULT_PATH_POLICY_FILE = "topology/PathPolicy.yml"
DEFAULT_ENV = ['TZ=UTC']

KEY_BR = 'BorderRouters'
KEY_BS = 'BeaconService'
KEY_CS = 'CertificateService'
KEY_PS = 'PathService'
KEY_ZK = 'ZookeeperService'

TYPES_TO_KEYS = {
    "BR": KEY_BR,
    "BS": KEY_BS,
    "CS": KEY_CS,
    "PS": KEY_PS,
    "ZK": KEY_ZK,
}


def generate_instance_dir(archive, as_, stype, tp, name):
    """
    Generate the service instance directory for the gen folder
    :param AS as_: AS in which the instance runs
    :param str directory: base directory of the gen folder
    :param str stype: service type
    :param tp: topology dict
    :param str name: instance name
    :return:
    """
    elem_dir = _elem_dir(as_, name)

    prom_port = 31000 + (hash(name) % 1000)  # TODO(matzf) should be obtained from model
    prom_addr = "127.0.0.1:%i" % prom_port
    env = DEFAULT_ENV.copy()
    if stype == 'BR':
        env.append('GODEBUG="cgocheck=0"')
        cmd = 'bin/border -id=%s -confd=%s -log.age=2 -prom=%s' % (name, elem_dir, prom_addr)
    elif stype == 'CS':
        cmd = 'bin/cert_srv -config "%s/csconfig.toml"' % elem_dir
    elif stype == 'PS':
        cmd = 'bin/path_srv -config %s/psconfig.toml' % elem_dir
    else:  # beacon server
        assert stype == 'BS'
        env.append('PYTHONPATH=python/:.')
        cmd = ('python/bin/beacon_server --filter_isd_loops --prom {prom} --sciond_path '
               '/run/shm/sciond/default.sock "{instance}" "{elem_dir}"'
               ).format(prom=prom_addr, instance=name, elem_dir=elem_dir)

    archive.write_config((elem_dir, 'supervisord.conf'),
                         _make_supervisord_conf(name, cmd, env))

    if stype == 'PS':
        archive.write_toml((elem_dir, 'psconfig.toml'),
                           _build_ps_conf(name, elem_dir))
    elif stype == 'CS':
        archive.write_toml((elem_dir, 'csconfig.toml'),
                           _build_cs_conf(name, elem_dir))

    _write_topo(archive, elem_dir, tp)
    _write_as_conf_and_path_policy(archive, elem_dir)
    _write_certs_trc(archive, elem_dir, as_)
    _write_keys(archive, elem_dir, as_)


def generate_server_app_dir(archive, as_, app_type, name, host_ip, app_port):
    """
    Generates a server application directory
    :param archive: object writing the content
    :param str app_type: server application type
    :param AS as_: AS where the server apps run
    :param str name application name e.g. pp1-ff00_0_111-1
    :param str host_ip: the host IP where that application is reachable
    :param int app_port: the host port where that application is reachable
    """
    ia = as_.isd_as_str()
    elem_dir = _elem_dir(as_, name)
    if app_type == Service.BW:
        cmd = 'bash -c "sleep 10 && exec bin/bwtestserver -s {ia},[{ip}]:{port}"'.format(
            ia=ia, ip=host_ip, port=app_port)
    elif app_type == Service.PP:
        cmd = ('bash -c "sleep 10 && exec bin/pingpong -mode server -local '
               '{ia},[{ip}]:{port}"').format(ia=ia, ip=host_ip, port=app_port)
    archive.write_config((elem_dir, 'supervisord.conf'),
                         _make_supervisord_conf(name, cmd, DEFAULT_ENV, priority=200, startsecs=15))


def generate_sciond_config(archive, as_, tp, name):
    """
    Writes the endhost folder into the given location.
    :param AS as_: AS of the sciond instance
    :param dict tp: the topology as a dict of dicts.
    """
    elem_dir = _elem_dir(as_, "endhost")

    superv = _make_supervisord_conf(name,
                                    'bin/sciond -config "%s/sciond.toml"' % elem_dir,
                                    DEFAULT_ENV)
    archive.write_config((elem_dir, 'supervisord.conf'), superv)

    archive.write_toml((elem_dir, 'sciond.toml'),
                       _build_sciond_conf(name, elem_dir, as_.isd_as_str()))

    _write_topo(archive, elem_dir, tp)
    _write_as_conf_and_path_policy(archive, elem_dir)
    _write_certs_trc(archive, elem_dir, as_)


def write_supervisord_group_config(archive, as_, processes):
    config = configparser.ConfigParser()
    config['group:' + "as%s" % as_.isd_as_path_str()] = {'programs': ",".join(processes)}
    archive.write_config((_isd_as_dir(as_), 'supervisord.conf'), config)


def write_dispatcher_config(archive):
    """
    Creates the supervisord and zlog files for the dispatcher and writes
    them into the dispatcher folder.
    """
    superv = _make_supervisord_conf('dispatcher',
                                    'bin/dispatcher',
                                    DEFAULT_ENV + ['ZLOG_CFG=gen/dispatcher/dispatcher.zlog.conf'],
                                    priority=50)
    archive.write_config('gen/dispatcher/supervisord.conf', superv)

    zlog_templ = Template(pathlib.Path(PROJECT_ROOT, "topology/zlog.tmpl").read_text())
    zlog = zlog_templ.substitute(name='dispatcher', elem='dispatcher')
    archive.write_text('gen/dispatcher/dispatcher.zlog.conf', zlog)


def write_ia_file(archive, as_):
    archive.write_text('gen/ia', as_.isd_as_path_str())


def _make_supervisord_conf(name, cmd, envs, priority=100, startsecs=5):
    config = configparser.ConfigParser()
    config['program:' + name] = {
        'autostart': 'false',
        'autorestart': 'true',
        'environment': ','.join(envs),
        'stdout_logfile': 'logs/%s.OUT' % name,
        'stderr_logfile': 'logs/%s.ERR' % name,
        'startretries': '0',
        'startsecs': str(startsecs),
        'priority': str(priority),
        'command':  cmd
    }
    return config


def _isd_as_dir(as_):
    return os.path.join(GEN_PATH, "ISD%s/AS%s" % (as_.isd.isd_id, as_.as_path_str()))


def _elem_dir(as_, elem_id):
    return os.path.join(_isd_as_dir(as_), elem_id)


def _cert_chain_filename(as_, version):
    """
    Return the certificate chain file path for a given ISD.
    """
    return 'ISD%s-AS%s-V%s.crt' % (as_.isd.isd_id, as_.as_path_str(), version)


def _trc_filename(isd, version):
    """
    Return the TRC file path for a given ISD.
    """
    return 'ISD%s-V%s.trc' % (isd.isd_id, version)


def _write_certs_trc(archive, elem_dir, as_):
    trc_version = as_.isd.trc['Version']
    archive.write_json((elem_dir, CERT_DIR, _trc_filename(as_.isd, trc_version)),
                       as_.isd.trc)

    cert_version = as_.certificate_chain['0']['Version']
    archive.write_json((elem_dir, CERT_DIR, _cert_chain_filename(as_, cert_version)),
                       as_.certificate_chain)


def _write_keys(archive, elem_dir, as_):
    archive.write_text(get_sig_key_file_path(elem_dir), as_.sig_priv_key)
    archive.write_text(get_enc_key_file_path(elem_dir), as_.enc_priv_key)
    archive.write_text(get_master_key_file_path(elem_dir, MASTER_KEY_0), as_.master_as_key)
    archive.write_text(get_master_key_file_path(elem_dir, MASTER_KEY_1), as_.master_as_key)  # TODO
    if as_.is_core:
        archive.write_text(get_core_sig_key_file_path(elem_dir), as_.core_sig_priv_key)
        archive.write_text(get_online_key_file_path(elem_dir), as_.core_online_priv_key)
        archive.write_text(get_offline_key_file_path(elem_dir), as_.core_offline_priv_key)


def _write_topo(archive, elem_dir, tp):
    archive.write_json((elem_dir, 'topology.json'), tp)


def _write_as_conf_and_path_policy(archive, elem_dir):
    conf = {
        'RegisterTime': 5,
        'PropagateTime': 5,
        'CertChainVersion': 0,
        'RegisterPath': True,
        'PathSegmentTTL': 21600,
    }
    archive.write_yaml((elem_dir, AS_CONF_FILE), conf)

    default_path_policy = pathlib.Path(PROJECT_ROOT, DEFAULT_PATH_POLICY_FILE).read_text()
    archive.write_text((elem_dir, PATH_POLICY_FILE), default_path_policy)


def _build_ps_conf(instance_name, instance_path):
    conf = _build_common_goservice_conf(instance_name, instance_path)
    conf.update({
        'infra': {
            'Type': "PS"
        },
        'ps': {
            'PathDB': {
                'Backend': 'sqlite',
                'Connection': 'gen-cache/%s.path.db' % instance_name,
            },
            'SegSync': True,
        },
    })
    return conf


def _build_cs_conf(instance_name, instance_path):
    conf = _build_common_goservice_conf(instance_name, instance_path)
    conf.update({
        'sd_client': {
            'Path': os.path.join(SCIOND_API_SOCKDIR, 'default.sock')
        },
        'infra': {
            'Type': "CS"
        },
        'cs': {
            'LeafReissueTime': "6h",
            'IssuerReissueTime': "3d",
            'ReissueRate': "10s",
            'ReissueTimeout': "5s",
        },
    })
    return conf


def _build_sciond_conf(instance_name, instance_path, ia):
    conf = _build_common_goservice_conf(instance_name, instance_path)
    conf.update({
        'sd': {
            'Reliable': os.path.join(SCIOND_API_SOCKDIR, "default.sock"),
            'Unix': os.path.join(SCIOND_API_SOCKDIR, "default.unix"),
            'Public': '%s,[127.0.0.1]:0' % ia,  # XXX(matzf): Should rather be the host addr?
            'PathDB': {
                'Connection': 'gen-cache/%s.path.db' % instance_name,
            },
        },
    })
    return conf


def _build_common_goservice_conf(instance_name, instance_path):
    """ Helper: return common settings for golang CS/PS/sciond """
    return {
        'general': {
            'ID': instance_name,
            'ConfigDir': instance_path,
            'ReconnectToDispatcher': True,  # XXX(matzf): for CS, topology/go.py this is False. Why?
        },
        'logging': {
            'file': {
                'Path': 'logs/%s.log' % instance_name,
                'Level': 'debug',
            },
            'console': {
                'Level': 'crit',
            },
        },
        'TrustDB': {
            'Backend': 'sqlite',
            'Connection': 'gen-cache/%s.trust.db' % instance_name,
        }
    }
