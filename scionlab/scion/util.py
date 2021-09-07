# Copyright 2021 ETH Zurich
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
:mod:`scionlab.scion.util` --- scion-pki execution
==================================================
"""

import subprocess

from django.conf import settings


def run_scion_pki(*args, cwd=None, check=True):
    try:
        return subprocess.run([settings.SCION_PKI_COMMAND, *args],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              encoding='utf-8',
                              check=check,
                              cwd=cwd)
    except subprocess.CalledProcessError as e:
        raise ScionPkiError(e) from None


class ScionPkiError(subprocess.CalledProcessError):
    """
    Wrapper for CalledProcessError (raised by subprocess.run on returncode != 0 if check=True),
    that includes the process output (stdout) in the __str__.
    """
    def __init__(self, e):
        super().__init__(e.returncode, e.cmd, e.output, e.stderr)

    def __str__(self):
        s = super().__str__()
        if self.output:
            s += "\n\n"
            s += self.output
        return s
