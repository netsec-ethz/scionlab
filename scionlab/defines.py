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

import datetime


MAX_PORT = 2**16-1
""" Max value for ports """

MAX_INTERFACE_ID = 2**12-1

USER_AS_ID_BEGIN = 0xffaa00010001  # 'ffaa:1:1'
USER_AS_ID_END = 0xffaa0001ffff  # 'ffaa:1:ffff'

DEFAULT_PUBLIC_PORT = 50000    # 30042-30051 (suggested by scion/wiki/default-port-ranges)
DEFAULT_INTERNAL_PORT = 30042  # 30042-30051
DEFAULT_CONTROL_PORT = 30242   # 30242-30251
BR_PROM_PORT_OFFSET = 200  # offset from BR control port. E.g. 30242 + 200 = 30442

CS_PORT = 30254  # This is both a SCION/UDP (inter-AS) and TCP (intra-AS)
CS_QUIC_PORT = 30354  # SCION/UDP/QUIC port for inter-AS
CS_PROM_PORT = 30454
SD_TCP_PORT = 30255
SD_PROM_PORT = 30455
DISPATCHER_PORT = 30041
DISPATCHER_PROM_PORT = 30441
SIG_CTRL_PORT = 30256
SIG_DATA_PORT = 30056

BW_PORT = 40001
PP_PORT = 40002

DEFAULT_HOST_INTERNAL_IP = "127.0.0.1"
DEFAULT_LINK_MTU = 1500 - 20 - 8
DEFAULT_LINK_BANDWIDTH = 1000

PROPAGATE_TIME_CORE = 60  # lower beaconing frequency in cores to save resources
PROPAGATE_TIME_NONCORE = 5  # higher frequency in non-cores ASes to have quicker startup

SCION_CONFIG_DIR = "/etc/scion"
SCION_LOG_DIR = "/var/log/scion"
SCION_VAR_DIR = "/var/lib/scion"
OPENVPN_CONFIG_DIR = "/etc/openvpn"

# Default expiration time for keys; we currently only distinguish between core/non-core keys.
# Note: the expiration of the core keys also defines the expiration of the TRCs.
DEFAULT_EXPIRATION_AS_KEYS = datetime.timedelta(days=365)
DEFAULT_EXPIRATION_CORE_KEYS = datetime.timedelta(days=2*365)
DEFAULT_TRC_GRACE_PERIOD = datetime.timedelta(hours=6)
