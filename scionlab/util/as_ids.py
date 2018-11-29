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

import re

REGEX = re.compile(r"^([0-9a-fA-F]{1,4}):([0-9a-fA-F]{1,4}):([0-9a-fA-F]{1,4})$")


def format(as_id_int):
    """
    Format an AS-identifier given as a (48-bit) integer as a string
    of the form [0-ffff]:[0-ffff]:[0-ffff]
    :param str as_id_int: AS-identifier to format
    :returns: AS-identifier as string
    :raises: ValueError if `as_id_int` not in the valid range for an AS-identifier
    """
    if as_id_int < 0 or as_id_int >= 2**48:
        raise ValueError('Invalid AS-ID')
    low = as_id_int & 0xffff
    mid = (as_id_int >> 16) & 0xffff
    hig = (as_id_int >> 32) & 0xffff
    return "%x:%x:%x" % (hig, mid, low)


def parse(as_id_str):
    """
    Parse an AS-identifier of the form [0-ffff]:[0-ffff]:[0-ffff]
    and return the corresponding (48-bit) integer representation.
    :param str as_id_str: AS-identifier to parse
    :returns: AS-identifier as integer
    """
    match = REGEX.match(as_id_str)
    if not match:
        raise ValueError('Invalid AS-ID')
    low = int(match.group(3), 16)
    mid = int(match.group(2), 16)
    hig = int(match.group(1), 16)
    return hig << 32 | mid << 16 | low
