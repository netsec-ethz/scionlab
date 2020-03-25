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

from scionlab.models.core import Interface
from scionlab.models.vpn import VPN, VPNClient


def run():
    recreate_keys_certs()

    iface_vpn_rel = record_vpn_relations()
    reassign_subnets()
    reassign_client_ips()
    update_vpn_ip_usage(iface_vpn_rel)


def recreate_keys_certs():
    for v in VPN.objects.all():
        v.init_key()
        v.save()

    for c in VPNClient.objects.all():
        c.init_key()
        c.save()


def record_vpn_relations():
    """
    Before we change the ips of the VPN/VPNClient objects, we need to remember where these
    are used, as we don't have this relation directly in the DB -- only the IP address
    used tells us whether a link uses VPN.
    The VPN IPs are _only_ used as the public_ip of Interface-objects (i.e. not for Host.public_ip,
    nor for bind_ip or internal_ip). We only handle this case.

    As there can, in principle, be multiple matching VPNClient objects per Interface (overlapping
    subnets...) we try to resolve this ambiguity by checking if there is a related VPN on the
    opposite site of the Link.

    :returns: map from interface to the related VPN or VPNClient object
    """

    iface_vpn_rel = {}
    for iface in Interface.objects.all():
        vpn_rel = related_vpn_obj(iface)
        if vpn_rel:
            iface_vpn_rel[iface] = vpn_rel
    return iface_vpn_rel


def related_vpn_obj(iface):
    server = iface.host.vpn_servers.filter(server_vpn_ip=iface.public_ip).first()
    # note: first because no host has >1 VPN server
    if server:
        return server

    clients = iface.host.vpn_clients.filter(ip=iface.public_ip)
    if not clients:
        return None
    if len(clients) == 1:
        return clients[0]
    active_clients = list(c for c in clients if c.active)
    if len(active_clients) == 1:
        return active_clients[0]

    related_vpn = iface.remote_interface().host.vpn_servers.first()
    if related_vpn:
        matching_clients = list(c for c in clients if c.vpn == related_vpn)
        if matching_clients:
            return matching_clients[0]
    return clients[0]


def reassign_subnets():
    for i, v in enumerate(VPN.objects.all().order_by('pk')):
        subnet = ipaddress.ip_network('10.%i.0.0/16' % (i+1))
        server_vpn_ip = next(subnet.hosts())
        v.subnet = str(subnet)
        v.server_vpn_ip = str(server_vpn_ip)
        v.save()


def reassign_client_ips():
    # Update
    for v in VPN.objects.all():
        subnet = ipaddress.ip_network(v.subnet)
        hosts_generator = subnet.hosts()
        server_vpn_ip = next(hosts_generator)  # skip server ip
        assert v.server_vpn_ip == str(server_vpn_ip)
        for c in v.clients.all().order_by('ip'):
            c.ip = str(next(hosts_generator))
            c.save()


def update_vpn_ip_usage(iface_vpn_rel):
    for iface, vpn_rel in iface_vpn_rel.items():
        vpn_rel.refresh_from_db()
        if isinstance(vpn_rel, VPN):
            new_ip = vpn_rel.server_vpn_ip
        else:
            assert isinstance(vpn_rel, VPNClient)
            new_ip = vpn_rel.ip

        iface.update(public_ip=new_ip)
