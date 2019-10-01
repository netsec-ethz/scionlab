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
import yaml
from parameterized import parameterized

from django.test import TestCase

from scionlab.config_tar import generate_host_config_tar, generate_user_as_config_tar
from scionlab.fixtures.testuser import get_testuser
from scionlab.models.core import Host, Service
from scionlab.models.user_as import AttachmentPoint, UserAS
from scionlab.util.archive import DictWriter


_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_DATA_DIR = os.path.join(_TEST_DIR, 'data/test_config_tar/')


_RECREATE_TEST_DATA = os.getenv('RECREATE_TEST_DATA', False)


def _create_user_as(installation_type, use_vpn):
    return UserAS.objects.create(
        owner=get_testuser(),
        attachment_point=AttachmentPoint.objects.filter(vpn__isnull=False).first(),
        installation_type=installation_type,
        label="covfefe",
        use_vpn=use_vpn,
        public_ip='172.31.0.111',
        public_port=54321,
    )


class ConfigTarRegressionTests(TestCase):
    fixtures = ['testdata']

    def setUp(self):
        self.maxDiff = None

    def test_host_first(self):
        host = Host.objects.first()
        archive = DictWriter()
        generate_host_config_tar(host, archive)
        self._check_archive(archive)

    def test_host_extra(self):
        extra_srv = Service.objects.filter(type__in=[Service.PP, Service.BW]).first()
        host = extra_srv.host
        archive = DictWriter()
        generate_host_config_tar(host, archive)
        self._check_archive(archive)

    @parameterized.expand([(UserAS.VM, False,),
                           (UserAS.PKG, False,),
                           (UserAS.PKG, True,),
                           (UserAS.SRC, False)])
    def test_user_as(self, installation_type, use_vpn):
        return # XXX

        user_as = _create_user_as(installation_type, use_vpn)
        archive = DictWriter()
        generate_user_as_config_tar(user_as, archive)
        self._check_archive(archive)

    def _check_archive(self, archive):
        test_id = self.id().lstrip(__name__)
        test_data_file = os.path.join(_DATA_DIR, test_id + ".yml")
        if not _RECREATE_TEST_DATA:

            actual = archive.dict
            with open(test_data_file) as f:
                expected = yaml.load(f, Loader=yaml.SafeLoader)

            # Do comparison in two stages to be able to make sense of any diff
            # Check same set of files:
            self.assertListEqual(list(sorted(expected.keys())),
                                 list(sorted(actual.keys())))

            # Check all files identical:
            for f in sorted(expected.keys()):
                self.assertEqual(expected[f], actual[f],
                                 'File %s differs' % f)
        else:
            with open(test_data_file, 'w') as f:
                yaml.dump(_strs_as_literals(archive.dict), stream=f)


# Helper to dump strings in literal style, e.g. {'foo': 'bla\nbla'} becomes
#
#    foo: |
#       bla
#       bla
#
# Recursively wrap all strs contained in `x` into `_literal` to dump all strings in literal style
def _strs_as_literals(x):
    if isinstance(x, str):
        return _literal(x)
    elif isinstance(x, dict):
        return {k: _strs_as_literals(v) for k, v in x.items()}
    else:
        return x


# Dummy type to define a yaml "representer".
# See https://stackoverflow.com/a/8641732/4666991
class _literal(str):
    pass


# yaml representer for `_literal` that will dump a string in literal style
def _literal_representer(dumper, data):
    return dumper.represent_scalar(u'tag:yaml.org,2002:str', data, style='|')


yaml.add_representer(_literal, _literal_representer)
