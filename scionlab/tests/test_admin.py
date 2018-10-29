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
from scionlab.models import AS
from scionlab.tests import utils
from scionlab.admin import ASCreationForm


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
