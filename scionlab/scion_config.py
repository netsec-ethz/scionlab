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
import ipaddress
import os
from collections import OrderedDict
from datetime import datetime

from scionlab.models.core import Service
from scionlab.scion_topology import TopologyInfo

from scionlab.defines import (
    PROPAGATE_TIME_CORE,
    PROPAGATE_TIME_NONCORE,
    PROM_PORT_OFFSET,
    PROM_PORT_DI,
    PROM_PORT_SD,
    CS_PORT,
    CS_QUIC_PORT,
    SD_QUIC_PORT,
    SD_TCP_PORT,
    SCION_CONFIG_DIR,
    SCION_LOG_DIR,
    SCION_VAR_DIR,
    GEN_PATH,
)

CERT_DIR = "certs"
KEY_DIR = "keys"
MASTER_KEY_0 = "master0.key"
MASTER_KEY_1 = "master1.key"


TYPE_BR = 'BR'
TYPE_SD = 'SD'
SERVICES_TO_SYSTEMD_NAMES = {
    Service.CS: 'scion-control-server',
    Service.BW: 'scion-bwtestserver',
    TYPE_BR: 'scion-border-router',
}

DEFAULT_ENV = ['TZ=UTC']
BORDER_ENV = DEFAULT_ENV + ['GODEBUG="cgocheck=0"']

CMDS = {
    Service.CS: 'cs',
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

        for service in self._control_services():
            if service.type == Service.CS:
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
        self._write_trcs(elem_dir)
        self._write_certs(elem_dir)
        if with_keys:
            self._write_keys(elem_dir)

    def _write_trcs(self, elem_dir):
        if self.AS.is_core:
            # keep _all_ TRCs
            relevant_trcs = self.AS.isd.trcs.all()
        else:
            # only active TRCs required; simplify, include all non-expired.
            # XXX(matzf): this will lead to issues for tests as testdata has fixed date...
            relevant_trcs = self.AS.isd.trcs.filter(not_after__gt=datetime.utcnow())
        for trc in relevant_trcs:
            self.archive.write_json((elem_dir, CERT_DIR, trc.filename()), trc.trc)

    def _write_certs(self, elem_dir):
        for cert in self.AS.certificates.all():
            self.archive.write_json((elem_dir, CERT_DIR, cert.filename()), cert.certificate)

    def _write_keys(self, elem_dir):
        self.archive.write_text((elem_dir, KEY_DIR, MASTER_KEY_0), self.AS.master_as_key)
        self.archive.write_text((elem_dir, KEY_DIR, MASTER_KEY_1), self.AS.master_as_key)

        for key in self.AS.keys.all():
            self.archive.write_json((elem_dir, KEY_DIR, key.filename()), key.format_keyfile())

    def _write_topo(self, elem_dir):
        self.archive.write_json((elem_dir, 'topology.json'), self.topo_info.topo)

    def _write_systemd_services_file(self):
        ia = self.AS.isd_as_path_str()
        unit_names = ["scion-border-router@%s-%i.service" % (ia, router.instance_id)
                      for router in self._routers()]
        unit_names += ["%s@%s-%i.service" % (SERVICES_TO_SYSTEMD_NAMES[service.type], ia,
                                             service.instance_id)
                       for service in self._control_services()]
        unit_names += ["%s.service" % SERVICES_TO_SYSTEMD_NAMES[service.type]
                       for service in self._extra_services()]
        unit_names.append('scion-daemon@%s.service' % self.AS.isd_as_path_str())
        unit_names.append('scion-dispatcher.service')

        self.archive.write_text('scionlab-services.txt', '\n'.join(unit_names))

    def _write_supervisord_files(self):
        for r in self._routers():
            self._write_supervisord_conf(r.instance_name, CMDS[TYPE_BR], 'br.toml', env=BORDER_ENV)
        for s in self._control_services():
            self._write_supervisord_conf(s.instance_name, CMDS[s.type], '%s.toml' % s.type.lower())

        sd_prog_id = "sd%s" % self.AS.isd_as_path_str()
        self._write_supervisord_conf('endhost', CMDS[TYPE_SD], 'sd.toml', prog_id=sd_prog_id)
        self._write_disp_supervisord_conf()

        prog_ids = [r.instance_name for r in self._routers()] + \
                   [s.instance_name for s in self._control_services()] + \
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

    def _control_services(self):
        return (s for s in self.topo_info.services
                if s.type in Service.CONTROL_SERVICE_TYPES and s.host == self.host)

    def _extra_services(self):
        return (s for s in self.topo_info.services
                if s.type in Service.EXTRA_SERVICE_TYPES and s.host == self.host)

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
        conf = self._build_logging_conf('dispatcher', PROM_PORT_DI)
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

    def build_cs_conf(self, service):
        conf = self._build_goservice_conf(service.instance_name, service.host.internal_ip,
                                          CS_QUIC_PORT, CS_PORT + PROM_PORT_OFFSET)

        propagate_time = PROPAGATE_TIME_CORE if service.AS.is_core else PROPAGATE_TIME_NONCORE
        interval = '{}s'.format(propagate_time)

        conf.update({
            'bs': {
                'OriginationInterval': interval,
                'PropagationInterval': interval,
                'RevTTL': '20s',
                'RevOverlap': '5s'
            },
            'cs': {
                'IssuerReissueLeadTime': "3d",
                'LeafReissueLeadTime': "6h",
                'ReissueRate': "10s",
                'ReissueTimeout': "5s",
            },
            'ps': {
                'pathDB': {
                    'Backend': 'sqlite',
                    'Connection': '%s.path.db' % os.path.join(self.var_dir, service.instance_name),
                },
                'SegSync': True
            },
            'beaconDB': {
                'Backend': 'sqlite',
                'Connection': '%s.beacon.db' % os.path.join(self.var_dir, service.instance_name),
            },
            'trustDB': {
                'Backend': 'sqlite',
                'Connection': '%s.trust.db' % os.path.join(self.var_dir, service.instance_name),
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
                'address': _join_host_port('127.0.0.1', SD_TCP_PORT),
                'pathDB': {
                    'Backend': 'sqlite',
                    'Connection': '%s.path.db' % os.path.join(self.var_dir, instance_name),
                },
            },
            'trustDB': {
                'Backend': 'sqlite',
                'Connection': '%s.trust.db' % os.path.join(self.var_dir, instance_name),
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
                'address': _join_host_port(host_ip, quic_port)
            },
        })
        return conf

    def _build_base_goservice_conf(self, instance_name, prometheus_port, instance_dir=None):
        """ Builds the toml configuration common to SD,CS and BR """
        conf = self._build_logging_conf(instance_name, prometheus_port)
        conf.update({
            'general': {
                'ID': instance_name,
                'ConfigDir': os.path.join(self.config_isd_as_dir, instance_dir or instance_name),
            },
        })
        return conf

    def _build_logging_conf(self, logfile_name, prometheus_port):
        """ Builds the metrics and logging configuration common to all services """
        conf = {
            'metrics': {'Prometheus': _join_host_port('127.0.0.1', prometheus_port)},
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


def _join_host_port(host, port):
    """
    Returns joined host:port, wrapping host in brackets if it looks like an IPv6 address
    :param str host:
    :param int port:
        :return str:
    """
    if ':' in host:
        return '[%s]:%s' % (host, port)
    else:
        return '%s:%s' % (host, port)


def _localhost(ip):
    """
    Returns a/the loopback address for an address of the same type as host_ip
    :param str host_ip: IP address
    :return str: loopback address
    """
    if isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address):
        return "::1"
    else:
        return "127.0.0.1"
