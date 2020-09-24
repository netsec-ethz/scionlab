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
from scionlab.fixtures.testuser import get_testuser_exbert
from scionlab.models.core import Service
from scionlab.models.user_as import UserAS
from scionlab.util.archive import DictWriter, FileArchiveWriter


_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_DATA_DIR = os.path.join(_TEST_DIR, 'data/test_config_tar/')


# See scripts/recreate-test-results.sh
_RECREATE_TEST_RESULTS = os.getenv('RECREATE_TEST_RESULTS', False)


_HOWTO_RECREATE = """

This is a regression test; the actual result differs from the expected, checked-in ground truth
result in scionlab/tests/data/test_config_tar/.

If you're sure that the ground truth data is wrong, update the expected output. Either
- manually update the file, or
- recreate all using scripts/recreate-test-results.sh -- double check the resulting diff!
"""


class ConfigTarRegressionTests(TestCase):
    fixtures = ['testdata']

    def setUp(self):
        self.maxDiff = None

    def test_host(self):
        extra_srv = Service.objects.filter(type__in=[Service.BW]).first()
        host = extra_srv.host
        archive = DictWriter()
        generate_host_config_tar(host, archive)
        self._check_archive('host_%i' % host.id, archive)

    @parameterized.expand(list(zip(range(5))))
    def test_user_as(self, user_as_id):
        user_as = UserAS.objects.filter(owner=get_testuser_exbert()).order_by('pk')[user_as_id]
        archive = DictWriter()
        generate_user_as_config_tar(user_as, archive)

    def _check_archive(self, test_id, archive):

        unchecked_files = ["README.md"]
        # Ignore content for `unchecked_files`
        for fname in unchecked_files:
            if fname in archive.dict:
                archive.dict[fname] = "content_not_checked"

        test_data_file = os.path.join(_DATA_DIR, test_id + ".yml")
        if not _RECREATE_TEST_RESULTS:

            actual = archive.dict
            with open(test_data_file) as f:
                expected = yaml.load(f, Loader=yaml.SafeLoader)

            # Do comparison in two stages to be able to make sense of any diff
            # Check same set of files:
            self.assertListEqual(list(sorted(expected.keys())),
                                 list(sorted(actual.keys())),
                                 "The list of generated files differ from the expected result" +
                                 _HOWTO_RECREATE)

            # Check all files identical:
            for f in sorted(expected.keys()):
                self.assertEqual(expected[f], actual[f],
                                 'File %s differs from expected result' % f + _HOWTO_RECREATE)
        else:
            with open(test_data_file, 'w') as f:
                yaml.dump(_strs_as_literals(archive.dict), stream=f)
            print(test_data_file)


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
