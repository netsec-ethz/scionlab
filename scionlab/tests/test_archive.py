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

import configparser
import hashlib
import pathlib
import tempfile

from django.test import TestCase

from scionlab.util.archive import DictWriter, HashedArchiveWriter, FileArchiveWriter

_TEST_DICT = {'foo': 'foo'}

_TEST_CONFIG = configparser.ConfigParser()
_TEST_CONFIG['foosection'] = {'foo': 'foo'}


class HashedArchiveWriterTests(TestCase):
    def test_undistorted(self):
        """ Check that base writer receives same content """
        base = DictWriter()
        self._add_stuff(base)

        adaptee = DictWriter()
        adapter = HashedArchiveWriter(adaptee)
        self._add_stuff(adapter)

        self.assertEqual(base.dict, adaptee.dict)

    def test_hash_set(self):
        """ Check that there is a hash for each file (excluding directories) """
        adaptee = DictWriter()
        hasher = HashedArchiveWriter(adaptee)
        self._add_stuff(hasher)

        self.assertEqual(sorted(path for path in adaptee.dict.keys() if not path.endswith('/')),
                         sorted(hasher.hashes.keys()))

    def test_file_hashes(self):
        """ Check that hashes for files written to disk match computed hashes """
        adaptee = DictWriter()
        hasher = HashedArchiveWriter(adaptee)
        self._add_stuff(hasher)

        with tempfile.TemporaryDirectory("scionlab_tests_test_archive") as tmpdir:
            filer = FileArchiveWriter(tmpdir)
            self._add_stuff(filer)

            # Get hashes from files on disk:
            hashes = {}
            for f in pathlib.Path(tmpdir).iterdir():
                if f.is_file():
                    hashes[f.name] = hashlib.sha1(f.read_bytes()).hexdigest()

            # Should be the same hashes:
            self.assertEqual(hasher.hashes, hashes)

    def _add_stuff(self, archive):
        archive.write_text("test.txt", "henlo")
        archive.write_json("test.json", _TEST_DICT)
        archive.write_toml("test.toml", _TEST_DICT)
        archive.write_yaml("test.yaml", _TEST_DICT)
        archive.write_config("test.ini", _TEST_CONFIG)
        archive.add("test.py", __file__)
        archive.add_dir("testdir")
