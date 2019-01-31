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
"""
:mod:`local_config_util' --- library functions for SCION topology generator
===========================================================================
"""

# This library file is created in order to use the functions from
# services such as scion-coord, without having to run the whole
# scion-web instance on that machine.

# Stdlib
import configparser
import json
import os
import yaml
import toml
from string import Template

# SCION
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
    GEN_PATH,
    PROJECT_ROOT,
    SCIOND_API_SOCKDIR,
    PATH_POLICY_FILE,
)
from lib.util import (
    copy_file,
    read_file,
    write_file,
)

DEFAULT_PATH_POLICY_FILE = "topology/PathPolicy.yml"
DEFAULT_ENV = ['TZ=UTC']

KEY_BR = 'BorderRouters'
KEY_BS = 'BeaconService'
KEY_CS = 'CertificateService'
KEY_PS = 'PathService'

TYPES_TO_KEYS = {
    "BR": KEY_BR,
    "BS": KEY_BS,
    "CS": KEY_CS,
    "PS": KEY_PS,
}


PROM_PORT_OFFSET = 1000  # TODO(matzf) move to model for port assignment


def write_dispatcher_config(local_gen_path):
    """
    Creates the supervisord and zlog files for the dispatcher and writes
    them into the dispatcher folder.
    :param str local_gen_path: the location to create the dispatcher folder in.
    """
    disp_folder_path = os.path.join(local_gen_path, 'dispatcher')
    if not os.path.exists(disp_folder_path):
        os.makedirs(disp_folder_path)
    disp_supervisord_conf = prep_dispatcher_supervisord_conf()
    _write_supervisord_config(disp_supervisord_conf, disp_folder_path)
    _write_dispatcher_zlog_file(disp_folder_path)


def _write_dispatcher_zlog_file(path):
    """
    Creates and writes the zlog configuration file for the dispatcher from a template
    in the scion code base.
    """
    tmpl = Template(read_file(os.path.join(PROJECT_ROOT, "topology/zlog.tmpl")))
    cfg = os.path.join(path, "dispatcher.zlog.conf")
    write_file(cfg, tmpl.substitute(name='dispatcher', elem='dispatcher'))


def _prep_supervisord_conf(service_type, name, path):
    """
    Prepares the supervisord configuration for the infrastructure elements
    and returns it as a ConfigParser object.
    :param str service_type: the type of the service (e.g. beacon_server).
    :param str name: the instance of the service (e.g. br1-8-1).
    :param str path: the directory containing the configuration of the instance
    :returns: supervisord configuration as a ConfigParser object
    :rtype: ConfigParser
    """

def _make_supervisord_conf(name, cmd, envs, priority=100):
    config = configparser.ConfigParser()
    config['program:' + name] = {
        'autostart': 'false',
        'autorestart': 'true',
        'environment': ','.join(envs),
        'stdout_logfile': 'logs/%s.OUT' % name,
        'stderr_logfile': 'logs/%s.ERR' % name,
        'startretries': '0',
        'startsecs': '5',
        'priority': str(priority),
        'command':  cmd
    }
    return config




def get_elem_dir(path, as_, elem_id):
    """
    Generates and returns the directory of a SCION element.
    :param str path: Relative or absolute path.
    :param AS as_: AS to which the element belongs.
    :param elem_id: The name of the instance.
    :returns: The directory of the instance.
    :rtype: string
    """
    ISD = as_.isd.isd_id
    AS = as_.as_path_str()
    return "%s/ISD%s/AS%s/%s" % (path, ISD, AS, elem_id)


def get_cert_chain_file_path(conf_dir, as_, version):  # pragma: no cover
    """
    Return the certificate chain file path for a given ISD.
    """
    return os.path.join(conf_dir, CERT_DIR, 'ISD%s-AS%s-V%s.crt' %
                        (as_.isd.isd_id, as_.as_path_str(), version))


def get_trc_file_path(conf_dir, isd, version):  # pragma: no cover
    """
    Return the TRC file path for a given ISD.
    """
    return os.path.join(conf_dir, CERT_DIR, 'ISD%s-V%s.trc' % (isd, version))


def prep_dispatcher_supervisord_conf():
    """
    Prepares the supervisord configuration for dispatcher.
    :returns: supervisord configuration as a ConfigParser object
    :rtype: ConfigParser
    """
    return _make_supervisord_conf('dispatcher',
                                  'bin/dispatcher',
                                  DEFAULT_ENV + ['ZLOG_CFG=gen/dispatcher/dispatcher.zlog.conf'],
                                  priority=50)


def _write_topology_file(tp, instance_path):
    """
    Writes the topology file into the instance's location.
    :param dict tp: the topology as a dict of dicts.
    :param instance_path: the folder to write the file into.
    """
    path = os.path.join(instance_path, 'topology.json')
    with open(path, 'w') as file:
        json.dump(tp, file, indent=2)


def _write_supervisord_config(config, instance_path):
    """
    Writes the given supervisord config into the provided location.
    :param ConfigParser config: supervisord configuration to write.
    :param instance_path: the folder to write the config into.
    """
    if not os.path.exists(instance_path):
        os.makedirs(instance_path)
    conf_file_path = os.path.join(instance_path, 'supervisord.conf')
    with open(conf_file_path, 'w') as configfile:
        config.write(configfile)


def write_certs_trc_keys(as_, as_obj, instance_path):
    """
    Writes the certificate and the keys for the given service
    instance of the given AS.
    :param AS as_: AS of the service instance
    :param obj as_obj: An object that stores crypto information for AS
    :param str instance_path: Location (in the file system) to write
    the configuration into.
    """
    # write keys
    # cert_version = json.loads(as_obj.certificate)['0']['Version']
    # trc_version = json.loads(as_obj.trc)['Version']
    as_key_path = {
        # 'cert': get_cert_chain_file_path(instance_path, as_, cert_version),
        # 'trc': get_trc_file_path(instance_path, as_.isd.isd_id, trc_version),
        'enc_key': get_enc_key_file_path(instance_path),
        'sig_key': get_sig_key_file_path(instance_path),
        'master0_as_key': get_master_key_file_path(instance_path, MASTER_KEY_0),
        'master1_as_key': get_master_key_file_path(instance_path, MASTER_KEY_1),
    }
    core_key_path = {
        'core_sig_key': get_core_sig_key_file_path(instance_path),
        'online_key': get_online_key_file_path(instance_path),
        'offline_key': get_offline_key_file_path(instance_path),
    }
    for key, path in as_key_path.items():
        if key == 'cert':  # write certificates
            write_file(path, str(as_obj.certificate))
        elif key == 'trc':  # write trc
            write_file(path, str(as_obj.trc))
        else:  # write keys
            write_file(path, as_obj.keys[key])
    if as_obj.core_keys:
        for key, path in core_key_path.items():
            write_file(path, as_obj.core_keys[key])


def write_as_conf_and_path_policy(as_, as_obj, instance_path):
    """
    Writes AS configuration (i.e. as.yml) and path policy files.
    :param AS as_: AS for which the config will be written.
    :param obj as_obj: An object that stores crypto information for AS
    :param str instance_path: Location (in the file system) to write
    the configuration into.
    """
    conf = {
        'RegisterTime': 5,
        'PropagateTime': 5,
        'CertChainVersion': 0,
        'RegisterPath': True,
        'PathSegmentTTL': 21600,
    }
    conf_file = os.path.join(instance_path, AS_CONF_FILE)
    write_file(conf_file, yaml.dump(conf, default_flow_style=False))
    path_policy_file = os.path.join(PROJECT_ROOT, DEFAULT_PATH_POLICY_FILE)
    copy_file(path_policy_file, os.path.join(instance_path, PATH_POLICY_FILE))


def generate_instance_dir(as_, directory, stype, tp, name):
    """
    Generate the service instance directory for the gen folder
    :param AS as_: AS in which the instance runs
    :param str directory: base directory of the gen folder
    :param str stype: service type
    :param tp: topology dict
    :param str name: instance name
    :return:
    """
    path = get_elem_dir(directory, as_, name)

    prom_port = 123456  # TODO(matzf) should be obtained from model
    prom_addr = "127.0.0.1:%i" % prom_port
    env = DEFAULT_ENV.copy()
    if stype == 'BR':
        env.append('GODEBUG="cgocheck=0"')
        cmd = 'bin/border -id=%s -confd=%s -log.age=2 -prom=%s' % (name, path, prom_addr)
    elif stype == 'CS':
        cmd = 'bin/cert_srv -config "%s/csconfig.toml"' % path
    elif stype == 'PS':
        cmd = 'bin/path_server -config %s/psconfig.tom' % path
    else:  # beacon server
        assert stype == 'BS'
        env.append('PYTHONPATH=python/')
        cmd = ('python/bin/beacon_server --prom {prom} --sciond_path '
               '/run/shm/sciond/default.sock "{instance}" "{elem_dir}"'
               ).format(prom=prom_addr, instance=name, elem_dir=path)
    config = _make_supervisord_conf(name, cmd, env)
    _write_supervisord_config(config, path)

    # Generate service configuration to directory, with certs and keys
    as_crypto_obj = AScrypto.from_AS(as_)
    write_certs_trc_keys(as_, as_crypto_obj, path)
    write_as_conf_and_path_policy(as_, as_crypto_obj, path)
    _write_topology_file(tp, path)

    if stype == 'PS':
        _write_ps_conf(name, path, as_.isd_as_str())
    elif stype == 'CS':
        _write_cs_conf(name, path, as_.isd_as_str())


def generate_sciond_config(as_, topo_dicts, gen_path=GEN_PATH):
    """
    Writes the endhost folder into the given location.
    :param AS as_: AS of the sciond instance
    :param dict topo_dicts: the topology as a dict of dicts.
    :param str gen_path: the target location for a gen folder.
    """
    name = "sd%s" % as_.isd_as_path_str()
    path = get_elem_dir(gen_path, as_, "endhost")

    # TODO(matzf): broken, needs to filter for processes on this host. More than one place!
    processes = []
    for svc_type in ["BorderRouters", "BeaconService",
                     "CertificateService", "PathService"]:
        if svc_type not in topo_dicts:
            continue
        for elem_id, elem in topo_dicts[svc_type].items():
            processes.append(elem_id)
    processes.append(name)


    config = _make_supervisord_conf(name,
                                    'bin/sciond -config "%s/sciond.toml"' % path,
                                    DEFAULT_ENV)

    config['group:' + "as%s" % as_.isd_as_path_str()] = {'programs': ",".join(processes)}
    _write_supervisord_config(config, os.path.join(gen_path, "ISD%s" % as_.isd.isd_id, "AS%s" % as_.as_path_str()))

    as_crypto = AScrypto.from_AS(as_)
    write_certs_trc_keys(as_, as_crypto, path)
    write_as_conf_and_path_policy(as_, as_crypto, path)
    _write_topology_file(topo_dicts, path)
    _write_sciond_conf(name, path, as_.isd_as_str())


def _write_ps_conf(instance_name, instance_path, ia):
    filename = os.path.join(instance_path, 'psconfig.toml')
    sciond_conf = _build_ps_conf(instance_name, instance_path, ia)
    write_file(filename, toml.dumps(sciond_conf))


def _build_ps_conf(instance_name, instance_path, ia):
    log_dir = 'logs'
    db_dir = 'gen-cache'
    log_level = 'debug'
    raw_entry = {
        'general': {
            'ID': instance_name,
            'ConfigDir': instance_path,
            'ReconnectToDispatcher': True,
        },
        'logging': {
            'file': {
                'Path': os.path.join(log_dir, "%s.log" % instance_name),
                'Level': log_level,
            },
            'console': {
                'Level': 'crit',
            },
        },
        'TrustDB': {
            'Backend': 'sqlite',
            'Connection': os.path.join(db_dir, '%s.trust.db' % instance_name),
        },
        'infra': {
            'Type': "PS"
        },
        'ps': {
            'PathDB': {
                'Backend': 'sqlite',
                'Connection': os.path.join(db_dir, '%s.path.db' % instance_name),
            },
            'SegSync': True,
        },
    }
    return raw_entry


def _write_cs_conf(instance_name, instance_path, ia):
    filename = os.path.join(instance_path, 'csconfig.toml')
    sciond_conf = _build_sciond_conf(instance_name, instance_path, ia)
    write_file(filename, toml.dumps(sciond_conf))


def _build_cs_conf(instance_name, instance_path, ia):
    log_dir = 'logs'
    db_dir = 'gen-cache'
    log_level = 'debug'
    raw_entry = {
        'general': {
            'ID': instance_name,
            'ConfigDir': instance_path,
        },
        'sd_client': {
            'Path': os.path.join(SCIOND_API_SOCKDIR, 'default.sock')
        },
        'logging': {
            'file': {
                'Path': os.path.join(log_dir, "%s.log" % instance_name),
                'Level': log_level,
            },
            'console': {
                'Level': 'crit',
            },
        },
        'TrustDB': {
            'Backend': 'sqlite',
            'Connection': os.path.join(db_dir, '%s.trust.db' % instance_name),
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
    }
    return raw_entry


def _write_sciond_conf(instance_name, instance_path, ia):
    filename = os.path.join(instance_path, 'sciond.toml')
    sciond_conf = _build_sciond_conf(instance_name, instance_path, ia)
    write_file(filename, toml.dumps(sciond_conf))


def _build_sciond_conf(instance_name, instance_path, ia):
    log_dir = 'logs'
    db_dir = 'gen-cache'
    log_level = 'debug'
    raw_entry = {
        'general': {
            'ID': instance_name,
            'ConfigDir': instance_path,
            'ReconnectToDispatcher': True,
        },
        'logging': {
            'file': {
                'Path': os.path.join(log_dir, "%s.log" % instance_name),
                'Level': log_level,
            },
            'console': {
                'Level': 'crit',
            },
        },
        'TrustDB': {
            'Backend': 'sqlite',
            'Connection': os.path.join(db_dir, '%s.trust.db' % instance_name),
        },
        'sd': {
            'Reliable': os.path.join(SCIOND_API_SOCKDIR, "default.sock"),
            'Unix': os.path.join(SCIOND_API_SOCKDIR, "default.unix"),
            'Public': '%s,[127.0.0.1]:0' % ia,  # TODO(matzf): IPv6!
            'PathDB': {
                'Connection': os.path.join(db_dir, '%s.path.db' % instance_name),
            },
        },
    }
    return raw_entry


class AScrypto:
    """
    Class representing an AS with the crypto information required to generate the gen folder
    """
    certificate = None
    trc = None
    keys = {}
    core_keys = {}

    @classmethod
    def from_AS(cls, as_):
        """
        Build AS_crypto from a model.AS object
        :param AS as_: AS object of the target AS
        :return:
        """
        inst = cls()
        inst.certificate = as_.certificates
        inst.trc = as_.isd.trc
        inst.keys = {
            'sig_key': as_.sig_priv_key,
            'sig_key_raw': as_.enc_priv_key,

            'enc_key': as_.master_as_key,
            'master0_as_key': as_.master_as_key,
            'master1_as_key': as_.master_as_key,  # TODO(matzf)
        }
        if as_.is_core:
            inst.core_keys = {
                'core_sig_key': as_.core_sig_priv_key,
                'online_key': as_.core_online_priv_key,
                'offline_key': as_.core_offline_priv_key,
            }
        return inst
