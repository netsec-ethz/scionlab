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
import os

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from scionlab.util.openvpn_config import write_vpn_ca_config


class Command(BaseCommand):
    help = 'Generate root CA configuration'

    def handle(self, *args, **options):
        if os.path.exists(settings.VPN_CA_KEY_PATH) and os.path.exists(settings.VPN_CA_CERT_PATH):
            raise CommandError('Root CA files already generated. '
                               'To generate a new root CA configuration, remove the '
                               'key (%s) and certificate (%s) files first.' % (
                                    settings.VPN_CA_KEY_PATH, settings.VPN_CA_CERT_PATH))
        write_vpn_ca_config()
