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

import configparser
import enum
import os
from collections import OrderedDict

from scionlab.models.core import Service
from scionlab.scion_topology import TopologyInfo

from scionlab.defines import (
    PROPAGATE_TIME_CORE,
    PROPAGATE_TIME_NONCORE,
    PROM_PORT_OFFSET,
    PROM_PORT_DI,
    PROM_PORT_SD,
    BS_PORT,
    PS_PORT,
    CS_PORT,
    BS_QUIC_PORT,
    PS_QUIC_PORT,
    CS_QUIC_PORT,
    SD_QUIC_PORT,
    SCION_CONFIG_DIR,
    SCION_LOG_DIR,
    SCION_VAR_DIR,
    GEN_PATH,
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
)

SERVICE_TYPES_CONTROL_PLANE = [Service.BS, Service.CS, Service.PS]
SERVICE_TYPES_SERVER_APPS = [Service.BW, Service.PP]

TYPE_BR = 'BR'
TYPE_SD = 'SD'
SERVICES_TO_SYSTEMD_NAMES = {
    Service.BS: 'scion-beacon-server',
    Service.CS: 'scion-certificate-server',
    Service.PS: 'scion-path-server',
    TYPE_BR: 'scion-border-router',
    TYPE_SD: 'scion-daemon',
}
SYSTEMD_NAMES_ALWAYS_PRESENT = [
    'scion-dispatcher.service'
]

DEFAULT_ENV = ['TZ=UTC']
BORDER_ENV = DEFAULT_ENV + ['GODEBUG="cgocheck=0"']

CMDS = {
    Service.BS: 'beacon_srv',
    Service.CS: 'cert_srv',
    Service.PS: 'path_srv',
    TYPE_BR: 'border',
    TYPE_SD: 'sciond',
}


class ProcessControl(enum.Enum):
    SYSTEMD = 0
    SUPERVISORD = 1


def create_gen(host, archive, process_control):
    """
    Generate the gen/ folder for the :host: in the given archive-writer
    :param host: Host object
    :param scionlab.util.archive.BaseArchiveWriter archive: output archive-writer
    :param ProcessControl process_control: configuration generated for installation with
                                           supervisord/systemd
    """
    generator = _ConfigGenerator(host, archive)
    if process_control == ProcessControl.SUPERVISORD:
        generator.generate_for_supervisord()
    else:
        assert process_control == ProcessControl.SYSTEMD
        generator.generate_for_systemd()


class _ConfigGenerator:
    """
    Generate the configuration for the given host into an archive.
    This class exists mainly to avoid passing the same information (host, AS, topology information
    and archive writer) to all the helper functions.
    """
    def __init__(self, host, archive):
        self.host = host
        self.archive = archive
        self.AS = host.AS
        self.topo_info = TopologyInfo(self.AS)

    def generate_for_systemd(self):
        config_builder = _ConfigBuilder(config_dir=SCION_CONFIG_DIR,
                                        log_dir=SCION_LOG_DIR,
                                        var_dir=SCION_VAR_DIR,
                                        isd_as_dir=_isd_as_dir(self.AS))
        self._gen_configs(config_builder)

        self._write_systemd_services_file()

    def generate_for_supervisord(self):
        config_builder = _ConfigBuilder(config_dir='',
                                        log_dir='logs',
                                        var_dir='gen-cache',
                                        isd_as_dir=_isd_as_dir(self.AS))
        self._gen_configs(config_builder)

        self._write_supervisord_files()

    def _gen_configs(self, cb):
        for router in self._routers():
            self._write_elem_dir(router.instance_name, 'br.toml', cb.build_br_conf(router))

        for service in self._services():
            if service.type == Service.BS:
                self._write_elem_dir(service.instance_name, 'bs.toml', cb.build_bs_conf(service))
            elif service.type == Service.PS:
                self._write_elem_dir(service.instance_name, 'ps.toml', cb.build_ps_conf(service))
            elif service.type == Service.CS:
                self._write_elem_dir(service.instance_name, 'cs.toml', cb.build_cs_conf(service))

        self._write_elem_dir('endhost', 'sd.toml', cb.build_sciond_conf(self.host),
                             with_keys=False)
        self.archive.write_toml((GEN_PATH, 'dispatcher', 'disp.toml'), cb.build_disp_conf())

    def _write_elem_dir(self, elem_id, toml_filename, conf, with_keys=True):
        """
        Fill the service instance configuration directory for in the gen folder for a SCION element.
        Adds
          ISD<isd>/AS<as>/<elem-id>/
            - topology.json
            - as.yml
            - certs/
            - keys/, if with_keys
        """
        elem_dir = self._elem_dir(elem_id)

        self.archive.write_toml((elem_dir, toml_filename), conf)

        self._write_topo(elem_dir)
        self._write_as_conf(elem_dir)
        self._write_certs_trc(elem_dir)
        if with_keys:
            self._write_keys(elem_dir)

    def _write_certs_trc(self, elem_dir):
        trc_version = self.AS.isd.trc['Version']
        self.archive.write_json((elem_dir, CERT_DIR, _trc_filename(self.AS.isd, trc_version)),
                                self.AS.isd.trc)

        cert_version = self.AS.certificate_chain['0']['Version']
        self.archive.write_json((elem_dir, CERT_DIR, _cert_chain_filename(self.AS, cert_version)),
                                self.AS.certificate_chain)

    def _write_keys(self, elem_dir):
        as_ = self.AS
        archive = self.archive
        archive.write_text(get_sig_key_file_path(elem_dir), as_.sig_priv_key)
        archive.write_text(get_enc_key_file_path(elem_dir), as_.enc_priv_key)
        archive.write_text(get_master_key_file_path(elem_dir, MASTER_KEY_0), as_.master_as_key)
        archive.write_text(get_master_key_file_path(elem_dir, MASTER_KEY_1), as_.master_as_key)
        if as_.is_core:
            archive.write_text(get_core_sig_key_file_path(elem_dir), as_.core_sig_priv_key)
            archive.write_text(get_online_key_file_path(elem_dir), as_.core_online_priv_key)
            archive.write_text(get_offline_key_file_path(elem_dir), as_.core_offline_priv_key)

    def _write_topo(self, elem_dir):
        self.archive.write_json((elem_dir, 'topology.json'), self.topo_info.topo)

    def _write_as_conf(self, elem_dir):
        conf = {
            'RegisterTime': 5,
            'PropagateTime': 5,
            'CertChainVersion': 0,
            'RegisterPath': True,
            'PathSegmentTTL': 21600,
        }
        self.archive.write_yaml((elem_dir, AS_CONF_FILE), conf)

    def _write_systemd_services_file(self):
        instance_names = [r.instance_name for r in self._routers()] + \
                         [s.instance_name for s in self._services()] + \
                         ["sd%s" % self.AS.isd_as_path_str()]
        unit_names = _get_systemd_services(instance_names)
        self.archive.write_text('scionlab-services.txt', '\n'.join(unit_names))

    def _write_supervisord_files(self):
        for r in self._routers():
            self._write_supervisord_conf(r.instance_name, CMDS[TYPE_BR], 'br.toml', env=BORDER_ENV)
        for s in self._services():
            self._write_supervisord_conf(s.instance_name, CMDS[s.type], '%s.toml' % s.type.lower())

        sd_prog_id = "sd%s" % self.AS.isd_as_path_str()
        self._write_supervisord_conf('endhost', CMDS[TYPE_SD], 'sd.toml', prog_id=sd_prog_id)
        self._write_disp_supervisord_conf()

        prog_ids = [r.instance_name for r in self._routers()] + \
                   [s.instance_name for s in self._services()] + \
                   [sd_prog_id, 'dispatcher']
        self._write_supervisord_group_config(prog_ids)

    def _write_supervisord_conf(self, elem_id, prog, toml_filename, env=DEFAULT_ENV, prog_id=None):
        elem_dir = self._elem_dir(elem_id)
        cmd = 'bin/%s -config %s/%s' % (prog, elem_dir, toml_filename)
        prog_id = prog_id or elem_id
        conf = _build_supervisord_conf(prog_id, cmd, env)
        self.archive.write_config((elem_dir, 'supervisord.conf'), conf)

    def _write_disp_supervisord_conf(self):
        cmd = 'bin/godispatcher -config %s' % os.path.join(GEN_PATH, 'dispatcher', 'disp.toml')
        conf = _build_supervisord_conf('dispatcher', cmd, DEFAULT_ENV, priority=50, startsecs=1)
        self.archive.write_config((GEN_PATH, 'dispatcher', 'supervisord.conf'), conf)

    def _write_supervisord_group_config(self, prog_ids):
        config = configparser.ConfigParser()
        config['group:' + "as%s" % self.AS.isd_as_path_str()] = {'programs': ",".join(prog_ids)}
        self.archive.write_config((_isd_as_dir(self.AS), 'supervisord.conf'), config)

    def _routers(self):
        return (r for r in self.topo_info.routers if r.host == self.host)

    def _services(self):
        return (s for s in self.topo_info.services if s.host == self.host)

    def _elem_dir(self, elem_id):
        return os.path.join(_isd_as_dir(self.AS), elem_id)


class _ConfigBuilder:
    """
    Helper object for `_ConfigGenerator`
    Builds the *.toml-configuration for the SCION services.
    """
    def __init__(self, config_dir, log_dir, var_dir, isd_as_dir):
        self.config_dir = config_dir
        self.config_isd_as_dir = os.path.join(config_dir, isd_as_dir)
        self.log_dir = log_dir
        self.var_dir = var_dir

    def build_disp_conf(self):
        conf = self._build_common_conf('dispatcher', PROM_PORT_DI)
        conf.update({
            'dispatcher': {'ID': 'dispatcher', 'SocketFileMode': '0777'},
        })
        return conf

    def build_br_conf(self, router):
        conf = self._build_base_goservice_conf(router.instance_name,
                                               router.internal_port + PROM_PORT_OFFSET)
        conf.update({
            'br': {
                'Profile': False,
            }
        })
        return conf

    def build_bs_conf(self, service):
        conf = self._build_goservice_conf(service.instance_name, service.host.internal_ip,
                                          BS_QUIC_PORT, BS_PORT + PROM_PORT_OFFSET)

        propagate_time = PROPAGATE_TIME_CORE if service.AS.is_core else PROPAGATE_TIME_NONCORE
        interval = '{}s'.format(propagate_time)

        conf.update({
            'beaconDB': {
                'Backend': 'sqlite',
                'Connection': '%s.beacon.db' % os.path.join(self.var_dir, service.instance_name),
            },
            'BS': {
                'OriginationInterval': interval,
                'PropagationInterval': interval,
                'RevTTL': '20s',
                'RevOverlap': '5s'
            },
        })
        return conf

    def build_ps_conf(self, service):
        conf = self._build_goservice_conf(service.instance_name, service.host.internal_ip,
                                          PS_QUIC_PORT, PS_PORT + PROM_PORT_OFFSET)
        conf.update({
            'ps': {
                'PathDB': {
                    'Backend': 'sqlite',
                    'Connection': '%s.path.db' % os.path.join(self.var_dir, service.instance_name),
                },
                'SegSync': True,
            },
        })
        return conf

    def build_cs_conf(self, service):
        conf = self._build_goservice_conf(service.instance_name, service.host.internal_ip,
                                          CS_QUIC_PORT, CS_PORT + PROM_PORT_OFFSET)
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

    def build_sciond_conf(self, host):
        instance_name = 'sd%s' % host.AS.isd_as_path_str()
        instance_dir = 'endhost'
        conf = self._build_goservice_conf(instance_name, host.internal_ip, SD_QUIC_PORT,
                                          PROM_PORT_SD, instance_dir=instance_dir)
        conf.update({
            'sd': {
                'Reliable': os.path.join(SCIOND_API_SOCKDIR, "default.sock"),
                'Unix': os.path.join(SCIOND_API_SOCKDIR, "default.unix"),
                'SocketFileMode': '0777',
                'Public': '{IA},[{ip}]:0'.format(IA=host.AS.isd_as_str(), ip=host.internal_ip),
                'PathDB': {
                    'Connection': '%s.path.db' % os.path.join(self.var_dir, instance_name),
                },
            },
        })
        return conf

    def _build_goservice_conf(self, instance_name, host_ip, quic_port, prometheus_port,
                              instance_dir=None):
        """ Builds the toml configuration common to SD,BS,CS and PS """
        conf = self._build_base_goservice_conf(instance_name, prometheus_port, instance_dir)
        conf['general']['ReconnectToDispatcher'] = True
        conf.update({
            'trustDB': {
                'Backend': 'sqlite',
                'Connection': '%s.trust.db' % os.path.join(self.var_dir, instance_name),
            },
            'quic': {
                'KeyFile':  os.path.join(self.config_dir, 'gen-certs/tls.key'),
                'CertFile': os.path.join(self.config_dir, 'gen-certs/tls.pem'),
                'ResolutionFraction': 0.4,
                'Address': '[{host}]:{port}'.format(host=host_ip, port=quic_port)
            },
        })
        return conf

    def _build_base_goservice_conf(self, instance_name, prometheus_port, instance_dir=None):
        """ Builds the toml configuration common to SD,BS,CS,PS and BR """
        conf = self._build_common_conf(instance_name, prometheus_port)
        conf.update({
            'general': {
                'ID': instance_name,
                'ConfigDir': os.path.join(self.config_isd_as_dir, instance_dir or instance_name),
            },
            'discovery': {
                'static': {'Enable': False},
                'dynamic': {'Enable': False},
            },
        })
        return conf

    def _build_common_conf(self, logfile_name, prometheus_port):
        """ Builds the toml configuration common to all services (disp,SD,BS,CS,PS and BR) """
        conf = {
            'metrics': {'Prometheus': '[127.0.0.1]:%s' % prometheus_port},
            'logging': {
                'file': {
                    'Path': '%s.log' % os.path.join(self.log_dir, logfile_name),
                    'Level': 'debug',
                    'MaxAge': 3,
                    'MaxBackups': 1,
                },
            },
        }
        return conf


def _build_supervisord_conf(program_id, cmd, envs, priority=100, startsecs=5):
    config = configparser.ConfigParser()
    config['program:' + program_id] = OrderedDict([
        ('autostart', 'false'),
        ('autorestart', 'true'),
        ('environment', ','.join(envs)),
        ('stdout_logfile', '%s.OUT' % os.path.join('logs', program_id)),
        ('stderr_logfile', '%s.ERR' % os.path.join('logs', program_id)),
        ('startretries', '0'),
        ('startsecs', str(startsecs)),
        ('priority', str(priority)),
        ('command',  cmd),
    ])
    return config


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


def _isd_as_dir(as_):
    return os.path.join(GEN_PATH, "ISD%s" % as_.isd.isd_id, "AS%s" % as_.as_path_str())


def _get_systemd_services(instance_names):
    """
    converts instance names ('cs17-ffaa_1_a-1')
    to systemd names ('scion-certificate-server@17-ffaa_1_a-1.service')
    :param list processes: list of process names e.g. ['cs17-ffaa_1_a-1']
    """
    units = []
    for p in instance_names:
        type_ = p[:2].upper()
        name = p[2:]
        systemd_unit = SERVICES_TO_SYSTEMD_NAMES.get(type_)
        if systemd_unit is None:
            continue
        unit = '{sysd}@{name}.service'.format(sysd=systemd_unit, name=name)
        units.append(unit)
    return units + SYSTEMD_NAMES_ALWAYS_PRESENT
