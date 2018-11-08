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

from django.test import TestCase
from django.forms.models import modelform_factory
from scionlab.models import AS, Link
from scionlab.tests import utils
from scionlab.admin import ASCreationForm, LinkAdminForm


class ASAdminTests(TestCase):
    fixtures = ['scionlab-isds']

    def test_create_as_form(self):
        as_id = 'ff00:bad:f00d'
        form_data = {
            'isd': 17,
            'as_id': as_id,
            'label': 'Test'
        }
        # This mimicks what ModelAdmin does to create the form:
        form_factory = modelform_factory(AS, form=ASCreationForm, fields='__all__')
        form = form_factory(data=form_data)
        self.assertTrue(form.is_valid())
        form.save()

        as_ = AS.objects.get(as_id=as_id)
        self.assertEqual(as_.as_id, as_id)
        self.assertEqual(as_.isd.id, 17)
        self.assertEqual(as_.label, 'Test')
        utils.check_as_keys(self, as_)


class LinkAdminFormTests(TestCase):
    fixtures = ['scionlab-isds', 'scionlab-ases-ch']

    AS_SCMN = 'ffaa:0:1101'
    AS_ETHZ = 'ffaa:0:1102'
    AS_SWTH = 'ffaa:0:1103'

    def _as_a(self):
        return AS.objects.get(as_id=self.AS_SCMN)

    def _as_b(self):
        return AS.objects.get(as_id=self.AS_ETHZ)

    def test_render_create(self):
        form = LinkAdminForm()
        self.assertIsNotNone(form.as_table())

    def test_create_link(self):
        as_a = self._as_a()
        as_b = self._as_b()
        form_data = dict(
            type=Link.PROVIDER,
            from_host=as_a.hosts.first().id,
            to_host=as_b.hosts.first().id,
        )
        form = LinkAdminForm(data=form_data)
        self.assertTrue(form.is_valid())
        link = form.save()
        self.assertIsNotNone(link)

    def test_render_edit(self):
        as_a = self._as_a()
        as_b = self._as_b()
        link = Link.objects.create(as_a.hosts.first(), as_b.hosts.first(), Link.PROVIDER)
        form = LinkAdminForm(instance=link)
        self.assertIsNotNone(form.as_table())

    def test_edit_link(self):
        as_a = self._as_a()
        as_b = self._as_b()
        link = Link.objects.create(as_a.hosts.first(), as_b.hosts.first(), Link.PROVIDER)

        form_data = dict(
            type=Link.PROVIDER,
            from_host=as_a.hosts.first().id,
            to_host=as_b.hosts.first().id,
            from_public_ip='192.0.2.1',
            from_public_port=50000,
            to_public_ip='192.0.2.2',
            to_public_port=50001,
        )
        form = LinkAdminForm(instance=link, data=form_data)
        link = form.save()
        self.assertIsNotNone(link)
        self.assertEqual(link.interfaceA.public_ip, '192.0.2.1')
        self.assertEqual(link.interfaceA.public_port, 50000)
        self.assertEqual(link.interfaceB.public_ip, '192.0.2.2')
        self.assertEqual(link.interfaceB.public_port, 50001)
