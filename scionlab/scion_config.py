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

from scionlab.models.core import Service
from scionlab.models.pki import TRC, Certificate
from scionlab.scion_topology import TopologyInfo

from scionlab.defines import (
    PROPAGATE_TIME_CORE,
    PROPAGATE_TIME_NONCORE,
    BR_PROM_PORT_OFFSET,
    DISPATCHER_PROM_PORT,
    CS_QUIC_PORT,
    CS_PROM_PORT,
    SD_TCP_PORT,
    SD_PROM_PORT,
    SCION_CONFIG_DIR,
    SCION_LOG_DIR,
    SCION_VAR_DIR,
    GEN_PATH,
)

CERT_DIR = "certs"
KEY_DIR = "keys"
TRC_DIR = "trcs"
MASTER_KEY_0 = "master0.key"
MASTER_KEY_1 = "master1.key"


TYPE_BR = 'BR'
TYPE_SD = 'SD'
SERVICES_TO_SYSTEMD_NAMES = {
    Service.CS: 'scion-control-service',
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


def create_gen(host, archive, process_control, with_sig_dummy_entry=False):
    """
    Generate the gen/ folder for the :host: in the given archive-writer
    :param host: Host object
    :param scionlab.util.archive.BaseArchiveWriter archive: output archive-writer
    :param ProcessControl process_control: configuration generated for installation with
                                           supervisord/systemd
    """
    generator = _ConfigGenerator(host, archive, with_sig_dummy_entry)
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
    def __init__(self, host, archive, with_sig_dummy_entry=False):
        self.host = host
        self.archive = archive
        self.AS = host.AS
        self.topo_info = TopologyInfo(self.AS, with_sig_dummy_entry)

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
        self.archive.write_toml((GEN_PATH, 'dispatcher', 'disp.toml'), cb.build_disp_conf())

        for router in self._routers():
            self._write_elem_dir(router.instance_name, 'br.toml', cb.build_br_conf(router))

        for service in self._control_services():
            if service.type == Service.CS:
                self._write_beacon_policy(service.instance_name, cb.build_beacon_policy(service))
                self._write_elem_dir(service.instance_name, 'cs.toml', cb.build_cs_conf(service))

        self._write_elem_dir('endhost', 'sd.toml', cb.build_sciond_conf(self.host),
                             with_keys=False)

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
        self._write_trcs(os.path.join(elem_dir, CERT_DIR))
        self._write_certs(os.path.join(elem_dir, CERT_DIR))
        if with_keys:
            self._write_keys(os.path.join(elem_dir, KEY_DIR))

    def _write_trcs(self, dir):

        # Note: we are in "Manual Mode" as described in the ControlPlanePKI.md; this means
        # that for each ISD, we need to include at least the base TRC version.
        # - For core ASes, we of course need to include all local TRC versions.
        # - For all other ASes, We _could probably_ only include the base TRC version, and newer
        #   versions will be fetched over the network. Right now, it's not completely clear to me,
        #   however, whether that is really enough.
        #   As there are no big disadvantages in always including all versions, that's what we do
        #   for now.
        for trc in TRC.objects.all():
            self.archive.write_json((dir, trc.filename()), trc.trc)

    def _write_certs(self, dir):
        for cert in self.AS.certificates.filter(type=Certificate.CHAIN):
            self.archive.write_json((dir, cert.filename()), cert.certificate)

    def _write_keys(self, dir):
        self.archive.write_text((dir, MASTER_KEY_0), self.AS.master_as_key)
        self.archive.write_text((dir, MASTER_KEY_1), self.AS.master_as_key)

        for key in self.AS.keys.all():
            self.archive.write_text((dir, key.filename()), key.format_keyfile())

    def _write_topo(self, dir):
        self.archive.write_json((dir, 'topology.json'), self.topo_info.topo)

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

    def _write_beacon_policy(self, elem_id, policy):
        dir = self._elem_dir(elem_id)
        self.archive.write_yaml((dir, 'beacon_policy.yaml'), policy)

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
        logging_conf = self._build_logging_conf('dispatcher')
        metrics_conf = self._build_metrics_conf(DISPATCHER_PROM_PORT)
        conf = _chain_dicts(logging_conf, metrics_conf)
        conf.update({
            'dispatcher': {
                'id': 'dispatcher',
                'socket_file_mode': '0777'
            },
        })
        return conf

    def build_br_conf(self, router):
        general_conf = self._build_general_conf(router.instance_name)
        logging_conf = self._build_logging_conf(router.instance_name)
        metrics_conf = self._build_metrics_conf(router.control_port + BR_PROM_PORT_OFFSET)
        conf = _chain_dicts(general_conf, logging_conf, metrics_conf)
        return conf

    def build_cs_conf(self, service):
        propagate_time = PROPAGATE_TIME_CORE if service.AS.is_core else PROPAGATE_TIME_NONCORE
        interval = '{}s'.format(propagate_time)

        general_conf = self._build_general_conf(service.instance_name)
        logging_conf = self._build_logging_conf(service.instance_name)
        metrics_conf = self._build_metrics_conf(CS_PROM_PORT)
        conf = _chain_dicts(general_conf, logging_conf, metrics_conf)
        conf.update({
            'beaconing': {
                'origination_interval': interval,
                'propagation_interval': interval,
                'rev_ttl': '20s',
                'rev_overlap': '5s',
                'policies': {
                    'Propagation': os.path.join(
                        self.config_isd_as_dir, service.instance_name, 'beacon_policy.yaml')
                }
            },
            'path_db': {
                'backend': 'sqlite',
                'connection': '%s.path.db' % os.path.join(self.var_dir, service.instance_name),
            },
            'beacon_db': {
                'backend': 'sqlite',
                'connection': '%s.beacon.db' % os.path.join(self.var_dir, service.instance_name),
            },
            'trust_db': {
                'backend': 'sqlite',
                'connection': '%s.trust.db' % os.path.join(self.var_dir, service.instance_name),
            },
            'quic': {
                'address': _join_host_port(service.host.internal_ip, CS_QUIC_PORT),
                'key_file':  os.path.join(self.config_dir, 'gen-certs/tls.key'),
                'cert_file': os.path.join(self.config_dir, 'gen-certs/tls.pem'),
                'resolution_fraction': 0.4,
            },
        })
        return conf

    def build_sciond_conf(self, host):
        instance_name = 'sd%s' % host.AS.isd_as_path_str()
        instance_dir = 'endhost'

        general_conf = self._build_general_conf(instance_name, instance_dir=instance_dir)
        logging_conf = self._build_logging_conf(instance_name)
        metrics_conf = self._build_metrics_conf(SD_PROM_PORT)
        conf = _chain_dicts(general_conf, logging_conf, metrics_conf)
        conf.update({
            'sd': {
                'address': _join_host_port('127.0.0.1', SD_TCP_PORT),
            },
            'path_db': {
                'backend': 'sqlite',
                'connection': '%s.path.db' % os.path.join(self.var_dir, instance_name),
            },
            'trust_db': {
                'backend': 'sqlite',
                'connection': '%s.trust.db' % os.path.join(self.var_dir, instance_name),
            },
        })
        return conf

    def build_beacon_policy(self, service):
        """ Returns a beacon policy, in which ISD loops are not allowed """
        return {'Filter': {
            'AllowIsdLoop': False
        }}

    def _build_general_conf(self, instance_name, instance_dir=None):
        """ Builds the 'general' configuration section common to SD,CS and BR """
        return {
            'general': {
                'id': instance_name,
                'config_dir': os.path.join(self.config_isd_as_dir, instance_dir or instance_name),
                # Note: this has performance impacts (for BR, only control plane)
                'reconnect_to_dispatcher': True,
            },
        }

    def _build_metrics_conf(self, prometheus_port):
        """ Builds the 'metrics' configuration common to all services """
        return {
            'metrics': {
                'prometheus': _join_host_port('127.0.0.1', prometheus_port)
            },
        }

    def _build_logging_conf(self, instance_name):
        """ Builds the 'logging' configuration section common to all services """
        return {
            'log': {
                'file': {
                    'path': '%s.log' % os.path.join(self.log_dir, instance_name),
                    'level': 'debug',
                    'max_age': 3,
                    'max_backups': 1,
                },
            },
        }


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


def _isd_dir(isd):
    return os.path.join(GEN_PATH, "ISD%s" % isd.isd_id)


def _isd_as_dir(as_):
    return os.path.join(_isd_dir(as_.isd), "AS%s" % as_.as_path_str())


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


def _chain_dicts(dict0, *dicts):
    """
    Combine / concatenate multiple dicts
    """
    r = dict(dict0.items())
    for dict_i in dicts:
        r.update(dict_i)
    return r
