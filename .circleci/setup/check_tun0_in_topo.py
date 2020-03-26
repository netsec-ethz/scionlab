#!/usr/bin/env python
# Copyright 2020 ETH Zurich
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

import json
import subprocess
import sys


def check_tun0_ip_configured(topo):
    ip_show = subprocess.run(['ip', 'address', 'show', 'tun0'],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, check=True)
    tun0_ip_net = [e.strip().split(" ")[1] for e in ip_show.stdout.decode('utf-8').split("\n")
                   if "tun0" in e and "inet" in e]
    if len(tun0_ip_net) == 0:
        return -1
    if len(tun0_ip_net) != 1:
        return len(tun0_ip_net)
    tun0_ip = tun0_ip_net[0].split("/")[0]

    border_routers = [topo["BorderRouters"][border_routers]
                      for border_routers in topo["BorderRouters"]]
    interfaces = [border_router["Interfaces"][interface]
                  for border_router in border_routers
                  for interface in border_router["Interfaces"]]
    matches = [interface["PublicOverlay"]["Addr"]
               for interface in interfaces if interface["PublicOverlay"]["Addr"] == tun0_ip]
    return len(matches) == 0


def main(argv):
    topo_file = str(argv[1])
    with open(topo_file, 'r') as f:
        topo = json.load(f)
    ret = check_tun0_ip_configured(topo)
    sys.exit(ret)


if __name__ == '__main__':
    main(sys.argv)
