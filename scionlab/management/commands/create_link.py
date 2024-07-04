# Copyright 2024 ETH Zurich
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

import sys

from django.core.management.base import BaseCommand, CommandParser

from scionlab.models.core import Host, Link


class Command(BaseCommand):
    help = 'Create Link between two hosts'

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument('-t', '--type', type=str, required=True,
                            choices=['core', 'provider', 'peer'],
                            help='Type of the link. If provider, host_a is parent, host_b is child.')
        parser.add_argument('host_a', type=str,
                            help='First host. If link is of type provider, this is the parent.')
        parser.add_argument('host_b', type=str,
                            help='Second host. If link is of type provider, this is the child.')

    def handle(self, *args, **kwargs):
        # Check the type is correct.
        type = None
        for t in Link.LINK_TYPES:
            if kwargs['type'].lower() == t[0].lower():
                type = t[0]
        if type is None:
            raise RuntimeError(f'logic error: link types have changed')
        
        # Find the hosts.
        host_a = self.find_host(kwargs['host_a'])
        host_b = self.find_host(kwargs['host_b'])

        # Create the link.
        self.create_link(type, host_a, host_b)
        
    def find_host(self, hostname):
        hosts = Host.objects.filter(label=hostname)
        if hosts.count() == 1:
            return hosts.get()
        if hosts.count() > 1:
            exit(f'more than one host with the same label "{hostname}"')

        # No host with that exact label found, try to find substrings.
        hosts = Host.objects.filter(label__contains=hostname)
        if hosts.count() == 0:
            exit(f'no host found with or containing label "{hostname}"')

        labels = [h.label for h in hosts]
        print(f'no host with exact label "{hostname}". Found similar:\n' + '\n'.join(labels))
        if len(labels) > 1:
            # More than one host found, bail and ask the user to be specific.
            exit('be more specific')

        # If only one matches the substring, use it.
        print(f'replacing "{hostname}" -> "{labels[0]}"')
        return hosts.get()

    def create_link(self, type, host_a, host_b):
        # The create_from_hosts method checks the validity of the type for those ASes.
        Link.objects.create_from_hosts(type, host_a, host_b)


def exit(msg: str):
    print(msg)
    sys.exit(1)
