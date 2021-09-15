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

from django.core.management.base import BaseCommand

from scionlab.models.core import ISD
from scionlab.scion.pkicommand import ScionPkiError


class Command(BaseCommand):
    help = 'Checks all certificates of all infrastructure ASes for their validity'

    def handle(self, *args, **kwargs):
        failed_isds = []
        failed_ases = []
        isds = ISD.objects.all()
        for isd in isds:
            try:
                num = isd.validate_crypto()
                print(f'ISD {isd.isd_id}: {isd.label} ; {num} TRCs.')
            except ScionPkiError as ex:
                failed_isds.append(isd)
                print(f'---------------------------\n'
                      f'ERROR: failed to verify ISD {isd.isd_id}: {ex}'
                      f'\n-----------------------------')
                continue
            ases = isd.ases.filter(owner=None)
            for as_ in ases:
                try:
                    num = as_.validate_crypto()
                    print(f'AS {as_.as_id}, core: {as_.is_core} ; {num} certs')
                except ScionPkiError as ex:
                    failed_ases.append(as_)
                    print(f'failed AS: {as_.as_id}: {ex}')

        print(f'summary; {len(failed_isds)} failed ISDs: '
              f'{[isd.isd_id for isd in failed_isds]}')
        print(f'summary; {len(failed_ases)} failed ASes: '
              f'{[as_.as_id for as_ in failed_ases]}')
