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

import argparse
import os

import django


def main():
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('as_ids', nargs='+')
    parser.add_argument('--core-keys', action='store_true',
                        help='update core keys (default: update AS keys)')

    args = parser.parse_args()

    if args.core_keys:
        print("Update keys for AS %s" % args.as_ids)
        update_keys(args.as_ids)
    else:
        print("Update core keys for %s" % args.as_ids)
        update_core_keys(args.as_ids)


def update_keys(as_ids):
    from scionlab.models.core import AS

    for as_ in AS.objects.filter(as_id__in=as_ids).iterator():
        as_.update_keys()


def update_core_keys(as_ids):
    from scionlab.models.core import AS

    ases = AS.objects.filter(as_id__in=as_ids)
    AS.update_core_as_keys(ases)


if __name__ == '__main__':
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'scionlab.settings.development')
    django.setup()
