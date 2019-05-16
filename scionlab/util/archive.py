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
"""
:mod:`scionlab.util.archive`  Helper for writing files in a directory structure (i.e.  an "archive"
                              of files)
"""

import io
import json
import pathlib
import tarfile
import time
import toml
import yaml


class BaseArchiveWriter:
    """
    An archive writer helps to write files to a directory structure. This base class contains
    shared convenience methods convert content to formatted text and write it to a file.

    Note: for convenience, the `path` passed to any of the `write_`-methods can be:
        - a string
        - a pathlib.Path
        - or a tuple consisting of string/pathlib.Path that will be joined
    Don't use absolute paths.
    """

    def write_text(self, path, content):
        """
        Write content to file at given path.
        :param str content:
        """
        raise NotImplementedError()

    def write_json(self, path, content):
        """
        Format dict as json and write to file at given path.
        :param dict content:
        """
        self.write_text(path, json.dumps(content, indent=2, sort_keys=True))

    def write_toml(self, path, content):
        """
        Format dict as toml and write to file at given path.
        :param dict content:
        """
        self.write_text(path, toml.dumps(content))

    def write_yaml(self, path, content):
        """
        Format dict as yaml and write to file at given path.
        :param dict content:
        """
        self.write_text(path, yaml.dump(content, default_flow_style=False))

    def write_config(self, path, config):
        """
        Write ConfigParser to file at given path.
        :param configparser.ConfigParser config:
        """
        f = io.StringIO()
        config.write(f)
        self.write_text(path, f.getvalue())

    def _normalize_path(self, path):
        if isinstance(path, tuple):
            return str(pathlib.PurePosixPath(*path))
        else:
            return str(path)


class FileArchiveWriter(BaseArchiveWriter):
    """
    Implementation of an archive writer that actually writes files to the OS filesystem, relative
    to an initially defined root directory.
    """

    def __init__(self, root):
        self.root = root

    def write_text(self, path, content):
        filepath = pathlib.Path(self.root, self._normalize_path(path))
        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.write_text(content)


class TarWriter(BaseArchiveWriter):
    """
    Implementation of an archive writer that writes files to a `tarfile.TarFile` "tape archive".
    If the tarfile is opened writing to an in-memory filelike object, the OS filesystem is bypassed.
    """

    def __init__(self, tar):
        """
        :param tarfile.TarFile tar: the tar-file to write to.
        """
        self.tar = tar

    def write_text(self, path, content):
        path = self._normalize_path(path)
        tar_add_textfile(self.tar, path, content)


def tar_add_textfile(tar, path, content):
    """
    Helper for tarfile: add a text-file at `path` with the given `content` to a tarfile `tar`.
    :param TarFile tar: an open tarfile.TarFile
    :param str path: name/path for the file in the tarfile
    :param str content: file content
    """
    m = tarfile.TarInfo(path)
    content_bytes = content.encode()
    m.size = len(content_bytes)
    m.mtime = time.time()
    tar.addfile(m, io.BytesIO(content_bytes))


def tar_add_dir(tar, path, mode=0o755):
    """
    Add an explicit entry for a directory at `path` to the tarfile `tar`.
    This can be used e.g. to add an empty directory.
    :param TarFile tar: an open tarfile.TarFile
    :param str path: name/path for the directory in the tarfile
    :param int mode: optional, permission bits
    """
    m = tarfile.TarInfo(path)
    m.type = tarfile.DIRTYPE
    m.mode = mode
    m.mtime = time.time()
    tar.addfile(m)
