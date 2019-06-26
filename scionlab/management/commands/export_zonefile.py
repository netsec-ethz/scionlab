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

from django.core.management.base import BaseCommand

from scionlab.models.core import Host
from scionlab.models.user_as import UserAS


class Command(BaseCommand):
    help = 'Creates a RAINS compatible zonefile containing all hosts'

    TYPE_SCION_IP4 = ":scionip4:"
    USER_PREFIX = "user-"

    def add_arguments(self, parser):
        parser.add_argument('-z', '--zone', type=str, required=True)
        parser.add_argument('-c', '--context', type=str, required=True)
        parser.add_argument('-o', '--out', type=str, required=True)

    def handle(self, *args, **options):

        record_dict = {}

        # user ASes
        for ua in UserAS.objects.all():
            host = ua.hosts.first()
            parts = ua.as_id.split(':')
            record_dict[self.USER_PREFIX + parts[2]] = host.scion_address()

        # Infrastructure
        # all hosts belonging to an AS without an owner
        for infra in Host.objects.filter(AS__owner=None).exclude(ssh_host=None):
            record_dict[infra.ssh_host] = infra.scion_address()

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
        assertion = "    :A: %s [ %s%s ]" % (
            subjectName, self.TYPE_SCION_IP4.ljust(12), value)
        return assertion
