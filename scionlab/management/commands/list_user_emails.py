# Copyright 2023 ETH Zurich
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

from scionlab.models.user import User


class Command(BaseCommand):
    help = 'List the unique emails of the users in alphabetical order'

    def handle(self, *args, **kwargs):
        # print active users emails:
        emails = User.objects.filter(
            is_active=True,
            ).values_list('email', flat=True).order_by('email').distinct()
        for email in emails:
            print(email)

        # report user stats:
        anon = []
        unauth = []
        inactive = []
        active = []
        for u in User.objects.all():
            if u.is_anonymous:
                anon.append(u)
            elif not u.is_authenticated:
                unauth.append(u)
            elif not u.is_active:
                inactive.append(u)
            else:
                active.append(u)
        print(f'====================================== anonymous: {len(anon)}')
        print(f'====================================== unauthorized: {len(unauth)}')
        print(f'====================================== inactive: {len(inactive)}')
        print(f'====================================== active: {len(active)}')
