# Copyright 2020 ETH Zurich
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

import importlib.util
import importlib.machinery
import io
import os
import pathlib
import sys
import tarfile
import tempfile
from collections import namedtuple
from contextlib import closing
from io import StringIO
from parameterized import parameterized
from unittest import TestCase
from unittest.mock import patch

from django.test import LiveServerTestCase

from scionlab import config_tar
from scionlab.models.core import Host
from scionlab.util.archive import TarWriter
from scionlab.tests import utils

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_BASE_DIR = os.path.dirname(os.path.dirname(_TEST_DIR))
_DATA_DIR = os.path.join(_TEST_DIR, 'data/test_scionlab-config/')
_SCIONLAB_CONFIG_PATH = os.path.join(_BASE_DIR, "scionlab/hostfiles/scionlab-config")

# import "scionlab-config" as a module "scionlab_config"
# (tiny bit of magic, https://stackoverflow.com/a/43602645/4666991)
spec = importlib.util.spec_from_loader(
    "scionlab_config",
    importlib.machinery.SourceFileLoader("scionlab_config", _SCIONLAB_CONFIG_PATH)
)
scionlab_config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scionlab_config)
sys.modules['scionlab_config'] = scionlab_config


def _expected_fetch_info(**kwargs):
    url = kwargs.get("url", "https://test.scionlab.org")
    version = kwargs.get("version", "12.345")
    return scionlab_config.FetchInfo('h1', 's1', url, version)


class ScionlabConfigLiveTests(LiveServerTestCase):
    """
    Use a "live" test server to test the API client functionality in the scionlab-config script
    """
    fixtures = ['testdata']

    def setUp(self):
        host = Host.objects.last()
        host.config_version = 1
        host.config_version_deployed = 1
        host.save()
        self.host = host
        self.fetch_info = scionlab_config.FetchInfo(
            host_id=host.uid,
            host_secret=host.secret,
            url=self.live_server_url,
            version='%i.1' % config_tar.CONFIG_GEN_VERSION,
        )

    def test_fetch_config_update(self):
        self.host.config_version += 1
        self.host.save()
        config = scionlab_config.fetch_config(self.fetch_info)
        tar = tarfile.open(mode='r', fileobj=io.BytesIO(config))
        self._check_tar(tar)

    def test_fetch_config_nop(self):
        config = scionlab_config.fetch_config(self.fetch_info)
        self.assertIs(config, scionlab_config._CONFIG_UNCHANGED)

    def test_fetch_config_force(self):
        config = scionlab_config.fetch_config(self.fetch_info._replace(version=None))
        self.assertIsInstance(config, bytes)
        tar = tarfile.open(mode='r', fileobj=io.BytesIO(config))
        self._check_tar(tar)

    def test_fetch_empty(self):
        self.host.AS.delete()  # Nothing left to do for this host
        config = scionlab_config.fetch_config(self.fetch_info)
        self.assertIs(config, scionlab_config._CONFIG_EMPTY)

    def test_fetch_fail_fatal(self):
        # requests that will result in unrecoverable errors:
        cases = [
            {'url': self.fetch_info.url + "/bad-url"},  # not found
            {'host_secret': 'badsecret'},  # not authorized
            {'version': 'bad'},  # bad request
        ]

        for case in cases:
            fetch_info = self.fetch_info._replace(**case)
            with self.assertRaises(SystemExit):
                scionlab_config.fetch_config(fetch_info)

    def test_fetch_fail_recoverable(self):
        # use a URL that will result in a "connection refused", which is considered a temporary
        # error
        fetch_info = self.fetch_info._replace(url='http://%s:0' % LiveServerTestCase.host)
        with self.assertRaises(scionlab_config.TemporaryError):
            scionlab_config.fetch_config(fetch_info)

    def test_confirm_deployed(self):
        self.host.config_version += 1
        self.host.save()
        confirm_info = self.fetch_info._replace(version=config_tar.fmt_config_version(self.host))
        with patch('scionlab_config._read_fetch_info', return_value=confirm_info):
            class MockArgs:
                url = None
            scionlab_config.confirm_deployed(MockArgs())

        self.host.refresh_from_db()
        self.assertEqual(self.host.config_version, self.host.config_version_deployed)

    @parameterized.expand([('good.json', _expected_fetch_info()),
                           ('no_url.json', _expected_fetch_info(
                               url=scionlab_config.DEFAULT_COORDINATOR_URL)),
                           ('no_version.json', _expected_fetch_info(version=None)),
                           ('old_version.json', _expected_fetch_info(version=None)),
                           ])
    def test_read_fetch_info_good(self, f, expected):
        path = os.path.join(_DATA_DIR, f)
        actual = scionlab_config._read_fetch_info(path)
        self.assertEqual(actual, expected)

    @parameterized.expand([('missing_id.json', ),
                           ('missing_secret.json', ),
                           ('does-not-exist.json', )])
    def test_read_fetch_info_bad(self, f):
        path = os.path.join(_DATA_DIR, f)
        with self.assertRaises(SystemExit):
            scionlab_config._read_fetch_info(path)

    def _check_tar(self, tar):
        self.assertIsInstance(tar, tarfile.TarFile)
        utils._check_tarball_etc_scion(self, tar, self.host)
        utils._check_tarball_info(self, tar, self.host)


class ScionlabConfigUnitTests(TestCase):

    def test_sanity_check_file_list(self):
        good = [
            "etc/scion/foo.toml",
            "etc/scion/topology.json",
            "etc/openvpn/foo.config",
        ]
        bad = [
            "/etc/scion/foo.toml",
            "etc/../usr/bin/sudo",
            "etc/scion/",
            "etc/scion",
            "usr/bin/sudo",
            "/usr/bin/sudo",
        ]

        def _check_good(files):
            scionlab_config._sanity_check_file_list(files)

        def _check_bad(files):
            with self.assertRaises(ValueError):
                scionlab_config._sanity_check_file_list(files)

        _check_good(good)  # all good
        for f in good:
            _check_good([f])  # individual good also pass

        _check_bad(bad)  # all bad fail
        _check_bad(good + bad)  # all bad with all good still fail
        for f in bad:
            _check_bad([f])  # individual bad fail
            _check_bad(good + [f])  # individual bad with good still fail

    def test_resolve_file_conflicts(self):
        # Test setup defines some files and their pseudo sha1 hashes:
        # foo: unchanged
        # fmo: modified locally, unchanged in update -> skip
        # bar: modified locally and in config -> prompt
        # boo: deleted in updated config -> ok
        # bmo: modified locally, deleted in config -> ok, no prompt
        # new: new in config -> ok
        # egg: existst locally, new in config -> prompt
        old_files = {
            "etc/scion/foo.toml": "sha1_foo",
            "etc/scion/fmo.toml": "sha1_fmo",
            "etc/scion/bar.toml": "sha1_bar_old",
            "etc/scion/boo.toml": "sha1_boo",
            "etc/scion/bmo.toml": "sha1_bmo",
        }
        new_files = {
            "etc/scion/foo.toml": "sha1_foo",
            "etc/scion/fmo.toml": "sha1_fmo",
            "etc/scion/bar.toml": "sha1_bar_new",
            "etc/scion/new.toml": "sha1_new",
            "etc/scion/egg.toml": "sha1_egg_new",
        }
        disk_files = {
            # note absolute path here
            "/etc/scion/foo.toml": "sha1_foo",
            "/etc/scion/fmo.toml": "sha1_fmo_local",
            "/etc/scion/bar.toml": "sha1_bar_local",
            "/etc/scion/boo.toml": "sha1_boo",
            "/etc/scion/bmo.toml": "sha1_bmo_local",
            "/etc/scion/egg.toml": "sha1_egg_local",
        }

        # define expected result, the list of files to be skipped, depending on
        # user input on prompt:
        expected_num_prompts = 2
        case = namedtuple('case', ['force', 'keep', 'prompt_reply', 'expected_skip',
                                   'expected_confnew', 'expected_backup'])
        case.__new__.__defaults__ = (False, False, None, None, None, None)
        cases = [
            case(
                force=True,
                expected_skip=[],
                expected_confnew=[],
                expected_backup=["etc/scion/fmo.toml", "etc/scion/bar.toml", "etc/scion/egg.toml"],
            ),
            case(
                prompt_reply="backup",
                expected_skip=["etc/scion/fmo.toml"],
                expected_confnew=[],
                expected_backup=["etc/scion/bar.toml", "etc/scion/egg.toml"],
            ),
            case(
                prompt_reply="keep",
                expected_skip=["etc/scion/fmo.toml"],
                expected_confnew=["etc/scion/bar.toml", "etc/scion/egg.toml"],
                expected_backup=[],
            ),
            case(
                keep=True,
                expected_skip=["etc/scion/fmo.toml"],
                expected_confnew=["etc/scion/bar.toml", "etc/scion/egg.toml"],
                expected_backup=[],
            ),
            case(
                prompt_reply="overwrite",
                expected_skip=["etc/scion/fmo.toml"],
                expected_confnew=[],
                expected_backup=[],
            ),
        ]

        def _mock_os_path_exists(path):
            return path in disk_files

        def _mock_sha1(path):
            return disk_files[path]

        for c in cases:
            with patch('scionlab_config._sha1', side_effect=_mock_sha1), \
                    patch('os.path.exists', side_effect=_mock_os_path_exists), \
                    patch('scionlab_config._prompt', return_value=c.prompt_reply) as mock_prompt:

                skip, confnew, backup = scionlab_config.resolve_file_conflicts(c.force, c.keep,
                                                                               old_files, new_files)

                doprompt = not c.force and not c.keep
                self.assertEqual(mock_prompt.call_count, expected_num_prompts if doprompt else 0, c)
                for call in mock_prompt.call_args_list:
                    self.assertEqual(call[1]["default"], "keep", call)

                self.assertEqual(sorted(skip), sorted(c.expected_skip), c)
                self.assertEqual(sorted(confnew), sorted(c.expected_confnew), c)
                self.assertEqual(sorted(backup), sorted(c.expected_backup), c)

    def test_prompt(self):
        context = "Darling, you got to let me know."
        question = "Should I stay or should I go?"
        options = ["stay", "go", "tease"]
        default = "tease"
        expected_prompt = " [s/g/T] "

        tests = [
            (['s'], 'stay'),
            (['x', 's'], 'stay'),
            (['g'], 'go'),
            (['G'], 'go'),
            (['go'], 'go'),
            (['goo', 'go now', 'go'], 'go'),
            (['tea'], 'tease'),
            ([''], 'tease'),
        ]
        for inputs, expected_result in tests:
            ret, term, prompts = self._patched_prompt(inputs, context, question,
                                                      options, default=default)

            self.assertEqual(len(prompts), len(inputs))  # matches expected number of question asked
            for prompt in prompts:
                self.assertEqual(prompt, expected_prompt)
            lines = term.splitlines()
            self.assertEqual(lines[0], context + " " + question + expected_prompt + inputs[0])
            for i in range(1, len(inputs)):
                self.assertEqual(lines[2*i-1], "Please respond with any of s/g/t.")
                self.assertEqual(lines[2*i], question + expected_prompt + inputs[i])
            self.assertTrue(ret, expected_result)

    def _patched_prompt(self, inputs, *prompt_args, **prompt_kwargs):
        """
        Run scionlab-config._prompt with patched input and sys.stdout
        Returns the value returned by prompt, the list of prompts given to `input` and the
        (approximated) view of the terminal (stdout + some).
        """

        term = StringIO()
        inputs_iter = iter(inputs)
        prompts = []

        def patched_input(prompt):
            prompts.append(prompt)
            user_input = next(inputs_iter)  # blows up if called too often (~intended)
            # user hits enter, so looks like a new line (even though not on stdout)
            term.write(prompt + user_input + "\n")
            return user_input

        with patch('builtins.input', side_effect=patched_input), patch('sys.stdout', new=term):
            ret = scionlab_config._prompt(*prompt_args, **prompt_kwargs)
            return ret, term.getvalue(), prompts

    def test_install_config_files(self):
        # Each testcase consists of a description of the initial file system (and configuration
        # info) state and the new configuration.
        # Each entry represents either a text file or a directory (None value).
        case = namedtuple('case', ['initial', 'files', 'skip', 'confnew'])
        cases = [
            case(
                initial={},
                files={
                    'etc/scion/bar/boo': 'boo',
                    'etc/scion/foo': 'foo',
                    'etc/scion/dir': None,
                },
                skip=[],
                confnew=[],
            ),
            case(
                initial={
                    'etc/scion/bar/boo': 'boo',
                    'etc/scion/same': 'same',
                },
                files={
                    'etc/scion/bar/boo': 'newboo',
                    'etc/scion/same': 'same',
                },
                skip=[],
                confnew=[],
            ),
            case(
                initial={
                    'etc/scion/bar/boo': 'boo',
                    'etc/scion/bar/hoo': 'hoo',
                    'etc/scion/same': 'same',
                },
                files={
                    'etc/scion/bar/boo': 'newboo',
                    'etc/scion/bar/hoo': 'newhoo',
                    'etc/scion/same': 'same',
                },
                skip=['etc/scion/bar/boo'],
                confnew=['etc/scion/bar/hoo']
            ),
            case(
                initial={
                    'etc/scion/dir': None,
                },
                files={
                    'etc/scion/dir': None,
                    'etc/scion/dir/stuff': 'stuff',
                },
                skip=[],
                confnew=[],
            ),
        ]

        for c in cases:
            with tempfile.TemporaryDirectory() as tmp:
                self._setup_initial_files(tmp, c.initial)

                def _tmproot(path):
                    return os.path.join(tmp, path)

                tar = self._to_tar(c.files)
                new_files = [f for f, content in c.files.items() if content is not None]
                old_files = [f for f, content in c.initial.items() if content is not None]

                with patch('scionlab_config._root', side_effect=_tmproot), \
                        patch('shutil.chown'):
                    scionlab_config.install_config_files(old_files, new_files,
                                                         c.skip, c.confnew, tar)

                expected = c.files.copy()
                for f in c.skip:
                    expected[f] = c.initial[f]
                for f in c.confnew:
                    expected[f] = c.initial[f]
                    expected[f + '.confnew'] = c.files[f]

                self._check_files(tmp, expected)

    def _to_tar(self, files):
        buf = io.BytesIO()
        with closing(tarfile.open(mode='w:gz', fileobj=buf)) as tar:
            archive = TarWriter(tar)
            for f, content in files.items():
                if content is None:
                    archive.add_dir(f)
                else:
                    archive.write_text(f, content)
            # Add config info file, to ensure this is ignored correctly
            archive.write_json('scionlab-config.json', {})

        buf.seek(0)
        return tarfile.open(mode='r:gz', fileobj=buf)

    def _setup_initial_files(self, tmp, files):
        for f, content in files.items():
            filepath = pathlib.Path(tmp, f)
            if content is None:
                filepath.mkdir(parents=True, exist_ok=True)
            else:
                filepath.parent.mkdir(parents=True, exist_ok=True)
                filepath.write_text(content)

    def _check_files(self, tmp, expected):
        actual = {}
        for root, dirs, files in os.walk(tmp):
            for d in dirs:
                filepath = pathlib.Path(root, d)
                actual[str(filepath.relative_to(tmp))] = None
            for f in files:
                filepath = pathlib.Path(root, f)
                actual[str(filepath.relative_to(tmp))] = filepath.read_text()

        # ok for some of the directories not to be listed in expected:
        dirs = [f for f, content in actual.items() if content is None]
        for d in dirs:
            if d not in expected:
                del actual[d]

        self.assertEqual(expected, actual)
