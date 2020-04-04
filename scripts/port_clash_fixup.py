#!/usr/bin/env python3
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
:mod: scripts.port_clash_fixup
=========================

Prints existing port clashes and fixes them.
For every clash, the interface that was modified the first is kept, but
for all the other ones a new port is found, and the associated
AP's configuration version is bumped.
This is intended to be used only once.

Run with python manage.py runscript port_clash_fixup
"""


from collections import defaultdict
from scionlab.models.core import Host, Interface, LazyPortMap
from scionlab.defines import DEFAULT_PUBLIC_PORT


def run():
    # get the clashes:
    clashes = dict()
    for h in Host.objects.all():
        c = get_clashes(h)
        if len(c):
            clashes[h] = c
    # print them
    for k, v in clashes.items():
        print('host {host} has {clashes} clashes:'.format(
            host=k, clashes=len(v)))
        for c in v:
            print('\tsocket = {socket} IDs = {ids}'.format(socket=c[0], ids=c[1]))
    # fix them
    for clashes in clashes.values():
        for c in clashes:
            fix_clash(c[1])


def get_clashes(host):
    """
    returns a list of (socket,[list_of_ids])
    """
    sockets = defaultdict(list)
    for iface in Interface.objects.filter(host=host):
        socket = (iface.get_public_ip(), iface.public_port)
        sockets[socket].append(iface.pk)
    clashes = list()
    for k, v in sockets.items():
        if len(v) > 1:
            clashes.append((k, v))
    return clashes


def fix_clash(iface_ids):
    """
    sorts the interfaces by modification data of the user AS,
    keeps the interface for the oldest modified user AS, and for the remaining interfaces
    selects a new port and bumps the configuration for the user AS host
    """
    ifaces = Interface.objects.\
        filter(pk__in=iface_ids).\
        order_by('-link_as_interfaceA__interfaceB__AS__modified_date')
    # don't modify the AS that obtained that port the first
    ifaces = ifaces[:len(ifaces)-1]
    for iface in ifaces:
        portmap = LazyPortMap(iface.host.get_port_map)
        iface.public_port = portmap.get_port(iface.get_public_ip(), DEFAULT_PUBLIC_PORT)
        iface.save()
        iface.host.bump_config()
