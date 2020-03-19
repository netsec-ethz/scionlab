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

"""
:mod: scripts.vpn_cleanup
=========================

Spring cleaning for VPN. This is intended to be used only once.

- Reset keys and certificates for VPN servers and clients (after resetting root CA)
- Assign sensible, non-overlapping 10.x.0.0/16 subnet to each VPN, re-assign server and client IPs
  in these subnets.

Run with python manage.py runscript vpn_cleanup
"""


import ipaddress

from scionlab.models.vpn import VPN, VPNClient


def run():
    recreate_keys_certs()
    reassign_subnets()
    reassign_client_ips()


def recreate_keys_certs():
    for v in VPN.objects.all():
        v.init_key()
        v.save()

    for c in VPNClient.objects.all():
        c.init_key()
        c.save()


def reassign_subnets():
    for i, v in enumerate(VPN.objects.all().order_by('pk')):
        subnet = ipaddress.ip_network('10.%i.0.0/16' % (i+1))
        server_vpn_ip = next(subnet.hosts())
        v.subnet = str(subnet)
        v.server_vpn_ip = str(server_vpn_ip)
        v.save()


def reassign_client_ips():
    for v in VPN.objects.all():
        subnet = ipaddress.ip_network(v.subnet)
        hosts_generator = subnet.hosts()
        server_vpn_ip = next(hosts_generator)  # skip server ip
        assert v.server_vpn_ip == str(server_vpn_ip)
        for c in v.clients.all().order_by('ip'):
            c.ip = str(next(hosts_generator))
            c.save()
