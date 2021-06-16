# Copyright 2021 ETH Zurich
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
:mod: scripts.merge_ap_routers
=========================

Run with python manage.py runscript merge_ap_routers

For each attachment point, merge all border router instances such that only a single router is used.
This is a cleanup step.
Previously, we've automatically distributed the interfaces for attachment points over many router
instances with at most ~12 interfaces each (`AttachmentPoint.split_border_routers`). This was a
workaround for some issue in an old version of the router. Now, this is no longer necessary and
running many instances is harmful for the system's performance.
"""

from django.db import transaction

from scionlab.models.user_as import AttachmentPoint


@transaction.atomic
def run():
    for ap in AttachmentPoint.objects.all():
        merge_router_instances(ap.AS.hosts.get())


def merge_router_instances(host):
    chosen = host.border_routers.first()
    for iface in host.interfaces.all():
        iface.border_router = chosen
        iface.save()
    host.border_routers.exclude(pk=chosen.pk).delete()
