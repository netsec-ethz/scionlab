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
import os
from collections import OrderedDict

from scionlab.models.core import Service
from scionlab.models.pki import TRC, Certificate
from scionlab.scion.topology import TopologyInfo

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
)

GEN = "gen"
GEN_CERTS = "gen-certs"
GEN_CACHE = "gen-cache"
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


def generate_systemd_scion_config(host, archive, with_sig_dummy_entry=False):
    """
    Generate the configuration archive for the :host: in the given archive-writer
    :param host: Host object
    :param scionlab.util.archive.BaseArchiveWriter archive: output archive-writer
    :returns: list of systemd units that should be enabled on this host
    """
    generator = _ConfigGeneratorSystemd(host, archive, with_sig_dummy_entry)
    generator.generate()
    return generator.systemd_units()


def generate_supervisord_scion_config(host, archive, with_sig_dummy_entry=False):
    """
    Generate the configuration archive for the :host: in the given archive-writer
    :param host: Host object
    :param scionlab.util.archive.BaseArchiveWriter archive: output archive-writer
    """
    generator = _ConfigGeneratorSupervisord(host, archive, with_sig_dummy_entry)
    generator.generate()


class _ConfigGeneratorBase:
    """
    Generate the configuration for the given host into an archive.
    This class hierarchy exists mainly to avoid passing the same information (host, AS, topology
    information and archive writer) to all the helper functions, and to have clean separation
    between systemd and supervisord config generation.
    """
    def __init__(self, host, archive, with_sig_dummy_entry=False):
        self.host = host
        self.archive = archive
        self.AS = host.AS
        self.topo_info = TopologyInfo(self.AS, with_sig_dummy_entry)

    def _write_as_config(self, cb: '_ConfigBuilder'):
        config_dir = cb.config_dir.lstrip('/')  # don't use absolute paths in the archive

        for router in self._routers():
            self.archive.write_toml((config_dir, f'{router.instance_name}.toml'),
                                    cb.build_br_conf(router))

        for service in self._control_services():
            assert service.type == Service.CS
            self.archive.write_toml((config_dir, f'{service.instance_name}.toml'),
                                    cb.build_cs_conf(service))

        self.archive.write_toml((config_dir, 'sd.toml'),
                                cb.build_sciond_conf(self.host))

        self._write_beacon_policy(config_dir, cb.build_beacon_policy(service))
        self._write_topo(config_dir)
        self._write_trcs(config_dir)
        self._write_certs(config_dir)
        self._write_keys(config_dir)

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
            self.archive.write_json((dir, CERT_DIR, trc.filename()), trc.trc)

    def _write_certs(self, dir):
        for cert in self.AS.certificates.filter(type=Certificate.CHAIN):
            self.archive.write_json((dir, CERT_DIR, cert.filename()), cert.certificate)

    def _write_keys(self, dir):
        self.archive.write_text((dir, KEY_DIR, MASTER_KEY_0), self.AS.master_as_key)
        self.archive.write_text((dir, KEY_DIR, MASTER_KEY_1), self.AS.master_as_key)

        for key in self.AS.keys.all():
            self.archive.write_text((dir, KEY_DIR, key.filename()), key.format_keyfile())

    def _write_topo(self, dir):
        self.archive.write_json((dir, 'topology.json'), self.topo_info.topo)

    def _write_beacon_policy(self, dir, policy):
        self.archive.write_yaml((dir, 'beacon_policy.yaml'), policy)

    def _routers(self):
        return (r for r in self.topo_info.routers if r.host == self.host)

    def _control_services(self):
        return (s for s in self.topo_info.services
                if s.type in Service.CONTROL_SERVICE_TYPES and s.host == self.host)

    def _extra_services(self):
        return (s for s in self.topo_info.services
                if s.type in Service.EXTRA_SERVICE_TYPES and s.host == self.host)


class _ConfigGeneratorSystemd(_ConfigGeneratorBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def generate(self):
        config_builder = _ConfigBuilder(config_dir=SCION_CONFIG_DIR,
                                        log_dir=SCION_LOG_DIR,
                                        var_dir=SCION_VAR_DIR,
                                        tls_certs_dir=os.path.join(SCION_CONFIG_DIR, GEN_CERTS))
        self._write_as_config(config_builder)
        # dispatcher config is installed with the package

    def systemd_units(self):
        units = ["scion-border-router@%s.service" % router.instance_name
                 for router in self._routers()]
        units += ["%s@%s.service" % (SERVICES_TO_SYSTEMD_NAMES[service.type], service.instance_name)
                  for service in self._control_services()]
        # XXX(matzf) drop this!
        units += ["%s.service" % SERVICES_TO_SYSTEMD_NAMES[service.type]
                  for service in self._extra_services()]
        units.append('scion-daemon@sd.service')
        units.append('scion-dispatcher.service')
        return units


class _ConfigGeneratorSupervisord(_ConfigGeneratorBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def generate(self):
        # build AS service config into gen/AS<AS_ID>
        config_builder = _ConfigBuilder(config_dir=self._as_dir(),
                                        log_dir='logs',
                                        var_dir=GEN_CACHE,
                                        tls_certs_dir=GEN_CERTS)
        self._write_as_config(config_builder)

        # the dispatcher directory is outside the AS subdirectory
        self.archive.write_toml((self._disp_dir(), 'disp.toml'),
                                config_builder.build_disp_conf())

        self._write_supervisord_file()

    def _write_supervisord_file(self):
        def _cmd(binary_name, config_dir, config_file):
            """ helper to create the command string for BR, CS, sciond and dispatcher """
            return f'bin/{binary_name} -config {config_dir}/{config_file}'

        as_dir = self._as_dir()
        config = configparser.ConfigParser()
        for router in self._routers():
            _add_supervisord_program_conf(
                config,
                router.instance_name,
                _cmd(CMDS[TYPE_BR], as_dir, router.instance_name + '.toml'),
                env=BORDER_ENV
            )
        for service in self._control_services():
            _add_supervisord_program_conf(
                config,
                service.instance_name,
                _cmd(CMDS[service.type], as_dir, service.instance_name + '.toml'),
                env=DEFAULT_ENV
            )

        sd_prog_id = "sd"
        _add_supervisord_program_conf(
            config,
            sd_prog_id,
            _cmd(CMDS[TYPE_SD], as_dir, 'sd.toml'),
            env=DEFAULT_ENV
        )

        prog_ids = [r.instance_name for r in self._routers()] + \
                   [s.instance_name for s in self._control_services()] + \
                   [sd_prog_id]
        _add_supervisord_group_conf(config, 'as%s' % self.AS.isd_as_path_str(), prog_ids)

        disp_prog_id = "dispatcher"
        _add_supervisord_program_conf(
            config,
            disp_prog_id,
            _cmd('godispatcher', self._disp_dir(), 'disp.toml'),
            env=DEFAULT_ENV,
            priority=50,
            startsecs=1
        )

        self.archive.write_config((GEN, 'supervisord.conf'), config)

    def _as_dir(self):
        return os.path.join(GEN, 'AS' + self.AS.as_path_str())

    def _disp_dir(self):
        return os.path.join(GEN, 'dispatcher')


class _ConfigBuilder:
    """
    Helper object for `_ConfigGenerator`
    Builds the *.toml-configuration for the SCION services.
    """
    def __init__(self, config_dir, log_dir, var_dir, tls_certs_dir):
        self.config_dir = config_dir
        self.log_dir = log_dir
        self.var_dir = var_dir
        self.tls_certs_dir = tls_certs_dir

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
        metrics_conf = self._build_metrics_conf(router.internal_port + BR_PROM_PORT_OFFSET)
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
                    'Propagation': os.path.join(self.config_dir, 'beacon_policy.yaml')
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
                'key_file':  os.path.join(self.tls_certs_dir, 'tls.key'),
                'cert_file': os.path.join(self.tls_certs_dir, 'tls.pem'),
                'resolution_fraction': 0.4,
            },
        })
        return conf

    def build_sciond_conf(self, host):
        instance_name = 'sd'

        general_conf = self._build_general_conf(instance_name)
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

    def _build_general_conf(self, instance_name):
        """ Builds the 'general' configuration section common to SD,CS and BR """
        return {
            'general': {
                'id': instance_name,
                'config_dir': self.config_dir,
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

    # TODO(matzf) drop this for nextversion (only console log)
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


def _add_supervisord_program_conf(config, program_id, cmd, env, priority=100, startsecs=5):
    config['program:' + program_id] = OrderedDict([
        ('autostart', 'false'),
        ('autorestart', 'true'),
        ('environment', ','.join(env)),
        ('stdout_logfile', '%s.log' % os.path.join('logs', program_id)),
        ('redirect_stderr', True),
        ('startretries', '0'),
        ('startsecs', str(startsecs)),
        ('priority', str(priority)),
        ('command',  cmd),
    ])


def _add_supervisord_group_conf(config, group_id, program_ids):
    config['group:' + group_id] = {'programs': ",".join(program_ids)}


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


def _chain_dicts(dict0, *dicts):
    """
    Combine / concatenate multiple dicts
    """
    r = dict(dict0.items())
    for dict_i in dicts:
        r.update(dict_i)
    return r
