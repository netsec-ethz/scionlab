# Copyright 2018 ETH Zurich
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

from scionlab.models import ISD, AS


def create_scionlab_isds():
    ISD.objects.create(id=16, label='AWS')
    ISD.objects.create(id=17, label='Switzerland')
    ISD.objects.create(id=18, label='North America')
    ISD.objects.create(id=19, label='EU')
    ISD.objects.create(id=20, label='Korea')
    ISD.objects.create(id=21, label='Japan')
    ISD.objects.create(id=22, label='Taiwan')
    ISD.objects.create(id=23, label='Singapore')
    ISD.objects.create(id=24, label='Australia')
    ISD.objects.create(id=25, label='China')


def create_scionlab_ases_ch():
    isd17 = ISD.objects.get(id=17)
    AS.objects.create_with_default_services(isd=isd17, as_id='ffaa:0:1101', label='SCMN', is_core=True)
    AS.objects.create_with_default_services(isd=isd17, as_id='ffaa:0:1102', label='ETHZ')
    AS.objects.create_with_default_services(isd=isd17, as_id='ffaa:0:1103', label='SWTH')

