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

# SCION
from scionlab.models.core import Service

from scionlab.defines import (
    PROPAGATE_TIME_CORE,
    PROPAGATE_TIME_NONCORE,
    PROM_PORT_DI,
    PROM_PORT_SD,
    BS_QUIC_PORT,
    PS_QUIC_PORT,
    CS_QUIC_PORT,
    SD_QUIC_PORT,
    SCION_CONFIG_DIR,
    SCION_LOG_DIR,
    SCION_VAR_DIR,
)

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
    SCIOND_API_SOCKDIR,
    GEN_PATH,
)


DEFAULT_ENV = ['TZ=UTC']

KEY_BR = 'BorderRouters'
KEY_BS = 'BeaconService'
KEY_CS = 'CertificateService'
KEY_PS = 'PathService'
KEY_DI = 'Discovery'

TYPES_TO_KEYS = {
    "BR": KEY_BR,
    "BS": KEY_BS,
    "CS": KEY_CS,
    "PS": KEY_PS,
}


def generate_instance_dir(archive, host, stype, tp, name, prometheus_port):
    """
    Generate the service instance directory for the gen folder
    :param Host host: Host in which the instance runs
    :param str directory: base directory of the gen folder
    :param str stype: service type
    :param tp: topology dict
    :param str name: instance name
    :return:
    """
    elem_dir = _elem_dir(host.AS, name)
    env = DEFAULT_ENV.copy()
    if stype == 'BR':
        env.append('GODEBUG="cgocheck=0"')
        program = 'border'
        gen_toml = _build_br_conf
    elif stype == 'CS':
        program = 'cert_srv'
        gen_toml = _build_cs_conf
    elif stype == 'PS':
        program = 'path_srv'
        gen_toml = _build_ps_conf
    else:
        assert stype == 'BS'
        program = 'beacon_srv'
        gen_toml = _build_bs_conf
    cmd = '{program} -config {dir}/{srv}.toml'.format(
        program=os.path.join('bin', program),
        dir=elem_dir,
        srv=stype.lower())

    archive.write_config((elem_dir, 'supervisord.conf'),
                         _make_supervisord_conf(name, cmd, env))
    full_elem_dir = os.path.join(SCION_CONFIG_DIR, elem_dir)
    archive.write_toml((elem_dir, stype.lower()+'.toml'),
                       gen_toml(name, full_elem_dir, host, prometheus_port))

    _write_topo(archive, elem_dir, tp)
    _write_as_conf(archive, elem_dir)
    _write_certs_trc(archive, elem_dir, host.AS)
    _write_keys(archive, elem_dir, host.AS)


def generate_server_app_dir(archive, host, app_type, name, app_port):
    """
    Generates a server application directory
    :param archive: object writing the content
    :param str app_type: server application type
    :param Host host: Host where the server apps run
    :param str name application name e.g. pp1-ff00_0_111-1
    :param int app_port: the host port where that application is reachable
    """
    ia = host.AS.isd_as_str()
    host_ip = host.internal_ip
    elem_dir = _elem_dir(host.AS, name)
    if app_type == Service.BW:
        cmd = 'bash -c "sleep 10 && exec {program} -s {ia},[{ip}]:{port}"'.format(
            program=os.path.join('bin', 'bwtestserver'),
            ia=ia, ip=host_ip, port=app_port)
    elif app_type == Service.PP:
        cmd = ('bash -c "sleep 10 && exec {program} -mode server -local '
               '{ia},[{ip}]:{port}"').format(
            program=os.path.join('bin', 'pingpong'),
            ia=ia, ip=host_ip, port=app_port)
    archive.write_config((elem_dir, 'supervisord.conf'),
                         _make_supervisord_conf(name, cmd, DEFAULT_ENV, priority=200, startsecs=15))


def generate_sciond_config(archive, host, tp, name):
    """
    Writes the endhost folder into the given location.
    :param Host host: Host of the sciond instance
    :param dict tp: the topology as a dict of dicts.
    """
    elem_dir = _elem_dir(host.AS, "endhost")
    superv = _make_supervisord_conf(name,
                                    '{program} -config "{config}"'.format(
                                        program=os.path.join('bin', 'sciond'),
                                        config=os.path.join(elem_dir, 'sd.toml')),
                                    DEFAULT_ENV)
    archive.write_config((elem_dir, 'supervisord.conf'), superv)

    full_elem_dir = os.path.join(SCION_CONFIG_DIR, elem_dir)
    archive.write_toml((elem_dir, 'sd.toml'),
                       _build_sciond_conf(name, full_elem_dir, host, PROM_PORT_SD))

    _write_topo(archive, elem_dir, tp)
    _write_as_conf(archive, elem_dir)
    _write_certs_trc(archive, elem_dir, host.AS)


def write_supervisord_group_config(archive, as_, processes):
    config = configparser.ConfigParser()
    config['group:' + "as%s" % as_.isd_as_path_str()] = {'programs': ",".join(processes)}
    archive.write_config((GEN_PATH, _isd_as_dir(as_), 'supervisord.conf'), config)


def write_dispatcher_config(archive):
    """
    Creates the supervisord files for the dispatcher and writes
    them into the dispatcher folder.
    """
    cmd = '"{program}" "-config" "{config}"'.format(
        program=os.path.join('bin', 'godispatcher'),
        config=os.path.join(GEN_PATH, 'dispatcher', 'disp.toml'))
    superv = _make_supervisord_conf('dispatcher',
                                    cmd,
                                    DEFAULT_ENV,
                                    priority=50,
                                    startsecs=1)
    archive.write_config(os.path.join(GEN_PATH, 'dispatcher', 'supervisord.conf'),
                         superv)
    archive.write_toml(os.path.join(GEN_PATH, 'dispatcher', 'disp.toml'),
                       _build_disp_conf())


def write_ia_file(archive, as_):
    archive.write_text(os.path.join(GEN_PATH, 'ia'),
                       as_.isd_as_path_str())


def write_services_file(archive, services):
    srv_file = '\n'.join(services)
    archive.write_text('scionlab-services.txt', srv_file)


def _make_supervisord_conf(name, cmd, envs, priority=100, startsecs=5):
    config = configparser.ConfigParser()
    config['program:' + name] = {
        'autostart': 'false',
        'autorestart': 'true',
        'environment': ','.join(envs),
        'stdout_logfile': '%s.OUT' % os.path.join('logs', name),
        'stderr_logfile': '%s.ERR' % os.path.join('logs', name),
        'startretries': '0',
        'startsecs': str(startsecs),
        'priority': str(priority),
        'command':  cmd,
    }
    return config


def _isd_as_dir(as_):
    return os.path.join("ISD%s" % as_.isd.isd_id, "AS%s" % as_.as_path_str())


def _elem_dir(as_, elem_id):
    return os.path.join(GEN_PATH, _isd_as_dir(as_), elem_id)


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


def _write_as_conf(archive, elem_dir):
    conf = {
        'RegisterTime': 5,
        'PropagateTime': 5,
        'CertChainVersion': 0,
        'RegisterPath': True,
        'PathSegmentTTL': 21600,
    }
    archive.write_yaml((elem_dir, AS_CONF_FILE), conf)


def _build_disp_conf():
    conf = _build_common_conf('dispatcher', PROM_PORT_DI)
    conf.update({
        'dispatcher': {'ID': 'dispatcher', 'SocketFileMode': '0777'},
    })
    return conf


def _build_br_conf(instance_name, instance_path, host, prometheus_port):
    conf = _build_base_goservice_conf(instance_name, instance_path, prometheus_port)
    conf.update({
        'br': {
            'Profile': False,
        }
    })
    return conf


def _build_bs_conf(instance_name, instance_path, host, prometheus_port):
    interval = '{}s'.format(PROPAGATE_TIME_CORE if host.AS.is_core else PROPAGATE_TIME_NONCORE)
    conf = _build_goservice_conf(instance_name, instance_path, host.internal_ip,
                                 BS_QUIC_PORT, prometheus_port)
    conf.update({
        'beaconDB': {
            'Backend': 'sqlite',
            'Connection': '%s.beacon.db' % os.path.join(SCION_VAR_DIR, instance_name),
        },
        'BS': {
            'OriginationInterval': interval,
            'PropagationInterval': interval,
            'RevTTL': '20s',
            'RevOverlap': '5s'
        },
    })
    return conf


def _build_ps_conf(instance_name, instance_path, host, prometheus_port):
    conf = _build_goservice_conf(instance_name, instance_path, host.internal_ip,
                                 PS_QUIC_PORT, prometheus_port)
    conf.update({
        'ps': {
            'PathDB': {
                'Backend': 'sqlite',
                'Connection': '%s.path.db' % os.path.join(SCION_VAR_DIR, instance_name),
            },
            'SegSync': True,
        },
    })
    return conf


def _build_cs_conf(instance_name, instance_path, host, prometheus_port):
    conf = _build_goservice_conf(instance_name, instance_path, host.internal_ip,
                                 CS_QUIC_PORT, prometheus_port)
    conf.update({
        'sd_client': {
            'Path': os.path.join(SCIOND_API_SOCKDIR, 'default.sock')
        },
        'cs': {
            'LeafReissueTime': "6h",
            'IssuerReissueTime': "3d",
            'ReissueRate': "10s",
            'ReissueTimeout': "5s",
        },
    })
    return conf


def _build_sciond_conf(instance_name, instance_path, host, prometheus_port):
    conf = _build_goservice_conf(instance_name, instance_path, host.internal_ip,
                                 SD_QUIC_PORT, prometheus_port)
    conf.update({
        'sd': {
            'Reliable': os.path.join(SCIOND_API_SOCKDIR, "default.sock"),
            'Unix': os.path.join(SCIOND_API_SOCKDIR, "default.unix"),
            'SocketFileMode': '0777',
            'Public': '{IA},[{ip}]:0'.format(IA=host.AS.isd_as_str(), ip=host.internal_ip),
            'PathDB': {
                'Connection': '%s.path.db' % os.path.join(SCION_VAR_DIR, instance_name),
            },
        },
    })
    return conf


def _build_common_conf(logfile_name, prometheus_port):
    """ Builds the toml configuration common to all services (disp,SD,BS,CS,PS and BR) """
    conf = {
        'metrics': {'Prometheus': '[127.0.0.1]:%s' % prometheus_port},
        'logging': {
            'file': {
                'Path': '%s.log' % os.path.join(SCION_LOG_DIR, logfile_name),
                'Level': 'debug',
            },
            'console': {
                'Level': 'crit',
            },
        },
    }
    return conf


def _build_base_goservice_conf(instance_name, instance_path, prometheus_port):
    """ Builds the toml configuration common to SD,BS,CS,PS and BR """
    conf = _build_common_conf(instance_name, prometheus_port)
    conf.update({
        'general': {
            'ID': instance_name,
            'ConfigDir': instance_path,
        },
        'discovery': {
            'static': {'Enable': False},
            'dynamic': {'Enable': False},
        },
    })
    return conf


def _build_goservice_conf(instance_name, instance_path, host_ip, quic_port, prometheus_port):
    """ Builds the toml configuration common to SD,BS,CS and PS """
    conf = _build_base_goservice_conf(instance_name, instance_path, prometheus_port)
    conf['general']['ReconnectToDispatcher'] = True
    conf.update({
        'trustDB': {
            'Backend': 'sqlite',
            'Connection': '%s.trust.db' % os.path.join(SCION_VAR_DIR, instance_name),
        },
        'quic': {
            'KeyFile':  os.path.join(SCION_CONFIG_DIR, 'gen-certs/tls.key'),
            'CertFile': os.path.join(SCION_CONFIG_DIR, 'gen-certs/tls.pem'),
            'ResolutionFraction': 0.4,
            'Address': '[{host}]:{port}'.format(host=host_ip, port=quic_port)
        },
    })
    return conf
