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

DEFAULT_PUBLIC_PORT = 50000    # UDP/IP, public_ip:port (bound to bind_ip:port if bind_ip is set)
# Fixed port assignment scheme for routers: the internal/control/metrics ports
# are defined as base_port + instance_id.
# Note that this does not strictly adhere to the suggestions by scion/wiki/default-port-ranges.
# Notably, this scheme starts at lower numbers to allow up to 40 routers before collision with the
# range used for the dispatcher (30041).
BR_INTERNAL_PORT_BASE = 30000    # UDP/IP, internal_ip:port
BR_METRICS_PORT_BASE = 30400     # TCP/IP, 127.0.0.1:port

CS_PORT = 30254                  # UDP/SCION (inter-AS) *and* TCP/IP (intra-AS)
CS_QUIC_PORT = 30354             # QUIC/UDP/SCION port for inter-AS
CS_METRICS_PORT = 30454          # TCP/IP, 127.0.0.1:port

SD_TCP_PORT = 30255              # TCP/IP, 127.0.0.1:port, NOTE: also in scion-daemon.deb
SD_METRICS_PORT = 30455          # "                       ditto

DISPATCHER_PORT = 30041          # UDP/IP, 127.0.0.1:port, [::]:port, NOTE: fixed!
DISPATCHER_METRICS_PORT = 30441  # TCP/IP, 127.0.0.1:port, NOTE: also in scion-dispatcher.deb

SIG_CTRL_PORT = 30256
SIG_DATA_PORT = 30056

CO_PORT = 30257                  # QUIC/SCION (inter-AS) *and* TCP/IP (intra-AS)

BW_PORT = 40001
PP_PORT = 40002

OPENVPN_SERVER_PORT = 1194

DEFAULT_HOST_INTERNAL_IP = "127.0.0.1"
DEFAULT_LINK_MTU = 1500 - 20 - 8

PROPAGATE_TIME_CORE = 60  # lower beaconing frequency in cores to save resources
PROPAGATE_TIME_NONCORE = 5  # higher frequency in non-cores ASes to have quicker startup

SCION_CONFIG_DIR = "/etc/scion"
SCION_VAR_DIR = "/var/lib/scion"
OPENVPN_CONFIG_DIR = "/etc/openvpn"

# Default expiration time for keys; we currently only distinguish between core/non-core keys.
# Note: the expiration of the core keys also defines the expiration of the TRCs.
DEFAULT_EXPIRATION_AS_KEYS = datetime.timedelta(days=365)
DEFAULT_EXPIRATION_CORE_KEYS = datetime.timedelta(days=2*365)
DEFAULT_TRC_GRACE_PERIOD = datetime.timedelta(hours=6)
