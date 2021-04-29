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
:mod: scripts.deactivate_dormant
=========================

Run with python manage.py runscript deactivate_dormant --script-args <list of inactive ases.txt>

Bulk deactivate inactive ASes for users who have not logged in for over a year.
Reads a list ASes  that have been inactive for a long time, created from data of the monitoring
system (by inspecting router_interface_up at the attachment points).
Expects newline separated AS ids, in the form "ffaa:1:abc".
"""

import datetime
import pathlib
from django.db import transaction
from django.db.models import Q

from scionlab.models.user_as import UserAS, AttachmentPoint

nologin_threshold = datetime.timedelta(days=365)


def run(*args):
    if len(args) != 1:
        print("run with --script-args <list of inactive user ases.txt>")
        return
    filename = args[0]
    as_ids = pathlib.Path(filename).read_text().splitlines()
    deactivate_dormant(as_ids)


@transaction.atomic
def deactivate_dormant(as_ids):
    last_login_before = datetime.datetime.utcnow() - nologin_threshold
    q = UserAS.objects.filter(
        Q(as_id__in=as_ids),
        Q(owner__last_login__lt=last_login_before) | Q(owner__last_login=None),
    )
    for user_as in q:
        print(user_as.as_id)
        user_as.update_active(False)

    # Fix-up distribution of user AS interfaces to router instances.
    for ap in AttachmentPoint.objects.all():
        ap.split_border_routers()
