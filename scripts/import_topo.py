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
:mod: scripts.import_topo
=========================


Run with python manage.py runscript import_topo --script-args <topo.yml>
"""

import yaml
import pathlib
from django.db import transaction
from scionlab.models.core import ISD, AS, Host, Service, BorderRouter, Interface, Link


class DryRunException(Exception):
    pass


def run(*args):
    if len(args) != 1:
        print("run with --script-args <topo-file.yml>")
        return
    filename = args[0]
    topo = yaml.safe_load(pathlib.Path(filename).read_text())
    dry_run = False
    try:
        import_topo(topo, dry_run)
    except DryRunException:
        print("Dry run complete, transaction rolled back")


@transaction.atomic
def import_topo(topo, dry_run):
    ases = topo['ases']
    links = topo['links']
    create_ases(ases)
    create_links(links)
    if dry_run:
        raise DryRunException()


def create_ases(ases):
    for ia, data in ases.items():
        as_ = create_as(ia, data)
        create_hosts(as_, data['hosts'])


def create_as(ia, data):
    isd_id, as_id = ia.split('-')
    isd = ISD.objects.filter(isd_id=isd_id).get()

    is_core = data.get('core', False)
    label = data['label']
    as_ = AS.objects.filter(as_id=as_id).first()
    if as_:
        as_.label = label
        as_.save()
        if as_.is_core != is_core:
            raise NotImplementedError("Cannot change AS is_core")
        as_.hosts.all().delete()
        print("Reset existing internal topology of AS", as_)
    else:
        as_ = AS.objects.create(isd=isd, as_id=as_id, label=label, is_core=is_core)
        print("Created AS", as_)
    return as_


def create_hosts(as_, hosts):
    for name, data in hosts.items():
        as_short_id = as_.as_id.split(':')[-1]
        ssh_host = 'scionlab-%s-%s' % (as_short_id, name)

        internal_ip = data['address']
        public_ip = data.get('public', None)
        Host.objects.create(
            AS=as_,
            public_ip=public_ip,
            bind_ip=None,
            internal_ip=internal_ip,
            ssh_host=ssh_host,
        )

    service_host = as_.hosts.first()
    Service.objects.create(host=service_host, type=Service.CS)


def create_links(links):
    for link, data in links.items():
        a, b = link.split('--')
        try:
            host_a = Host.objects.filter(ssh_host__endswith=a).get()
            host_b = Host.objects.filter(ssh_host__endswith=b).get()
        except Host.DoesNotExist as e:
            print("Skipping link", a, b, ":", e)
            continue

        create_link(host_a, host_b, data)


def create_link(host_a, host_b, data):
    public_a = data['src'].get('address', None) or None
    public_b = data['dst'].get('address', None) or None
    type = data.get('type', None)
    if type is None:
        if host_a.AS.is_core and host_b.AS.is_core:
            type = 'CORE'
        else:
            type = 'PROVIDER'

    # XXX(matzf): crappy input; fix obviously wrong link order
    if host_b.AS.is_core:
        host_a, host_b = host_b, host_a
        public_a, public_b = public_b, public_a
    Link.objects._check_link(type, host_a.AS, host_b.AS)

    br_a = BorderRouter.objects.first_or_create(host_a)
    br_b = BorderRouter.objects.first_or_create(host_b)
    interface_a = Interface.objects.create(border_router=br_a, public_ip=public_a)
    interface_b = Interface.objects.create(border_router=br_b, public_ip=public_b)
    link = Link.objects.create(type, interface_a, interface_b)
    print("Created link", link)
