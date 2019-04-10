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

MAX_PORT = 2**16-1
""" Max value for ports """

MAX_INTERFACE_ID = 2**12-1

USER_AS_ID_BEGIN = 0xffaa00010001  # 'ffaa:1:1'
USER_AS_ID_END = 0xffaa0001ffff  # 'ffaa:1:ffff'

DEFAULT_PUBLIC_PORT = 50000    # 30042-30051 (suggested by scion/wiki/default-port-ranges)
DEFAULT_INTERNAL_PORT = 31045  # 30242-30251
DEFAULT_CONTROL_PORT = 30045   # 30042-30051

DEFAULT_BS_PORT = 31041  # 30252
DEFAULT_PS_PORT = 31043  # 30253
DEFAULT_CS_PORT = 31042  # 30254
DEFAULT_ZK_PORT = 2181
DEFAULT_BW_PORT = 40001
DEFAULT_PP_PORT = 40002
DISPATCHER_PORT = 30041

DEFAULT_HOST_INTERNAL_IP = "127.0.0.1"
DEFAULT_LINK_MTU = 1500 - 20 - 8
DEFAULT_LINK_BANDWIDTH = 1000
