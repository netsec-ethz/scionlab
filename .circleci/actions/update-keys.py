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

""" Update AS keys for AS with given ids """

import os
import sys

import django


def main(argv):
    for as_id in argv[1:]:
        print("Update keys for AS %s" % as_id)
        update_keys(as_id)


def update_keys(as_id):
    from scionlab.models.core import AS

    as_ = AS.objects.filter(as_id=as_id).get()
    as_.update_keys()


if __name__ == '__main__':
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'scionlab.settings.development')
    django.setup()
    main(sys.argv)
