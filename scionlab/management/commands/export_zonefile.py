# Copyright 2019 ETH Zurich
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

from collections import OrderedDict
from datetime import datetime
import json

from django.core.management.base import BaseCommand

from scionlab.models.core import Host
from scionlab.models.user_as import UserAS


class Command(BaseCommand):
    help = 'Creates a RAINS compatible zonefile containing all hosts'

    indent4 = "    "
    indent8 = indent4 + indent4
    indent12 = indent8 + indent4
    type_scion_ip4 = ":scionip4:"
    user_prefix = "user-"

    def add_arguments(self, parser):
        parser.add_argument('-z', '--zone', type=str, required=True)
        parser.add_argument('-c', '--context', type=str, required=True)
        parser.add_argument('-ap', '--ap_file', type=str, required=True)
        parser.add_argument('-o', '--out', type=str, required=True)

    def handle(self, *args, **options):

        record_dict = OrderedDict()

        # user ASes
        # We assume that every user AS runs on one host only
        for ua in UserAS.objects.all():
            host = ua.hosts.first()
            parts = ua.as_id.split(':')
            ip = ua.public_ip if ua.public_ip is not None else host.vpn_clients.first().ip
            record_dict[self.user_prefix + str(parts[2])] = str('%s,[%s]' %
                                                                (ua.isd_as_str(), ip))

        # Infrastructure
        # all hosts belonging to an AS without an owner
        for infr in Host.objects.filter(AS__owner=None):
            if infr.ssh_host is not None:
                record_dict[str(infr.ssh_host)] = str('%s,[%s]' %
                                                      (infr.AS.isd_as_str(), infr.internal_ip))

        # Attachment Points
        # add from static file
        with open(options['ap_file']) as f:
            aps = json.load(f)
            for key in aps:
                record_dict[key] = aps[key]

        # write zonefile
        zone_file = ":Z: %s %s [\n" % (options['zone'], options['context'])
        for k in sorted(record_dict.keys(), key=str.lower):
            zone_file += self.encodeAssertion(k, record_dict[k]) + "\n"
        zone_file += "]"

        with open(options['out'], 'w+') as f:
            f.write(zone_file)

        self.stdout.write(self.style.SUCCESS(
            "Zonefile successfully written to disk"))

    def encodeAssertion(self, subjectName, value):
        type_indent = self.type_scion_ip4 + \
            self.indent12[len(self.type_scion_ip4):]
        assertion = "%s:A: %s [ %s%s ]" % (
            self.indent4, subjectName, type_indent, value)
        return assertion
