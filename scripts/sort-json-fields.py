#!/usr/bin/env python3
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

"""
Desperate script to load the yaml data-dump, load jsonfields and re-serialise them with sort_keys.

Invoked from scripts/create-fixture-testdata.sh
"""

import sys
import yaml
import json
from collections import OrderedDict

JSONFIELDS = ['trc', 'trc_priv_keys', 'certificate_chain', 'core_certificate']


# See: https://stackoverflow.com/a/21912744/4666991
def ordered_load(stream, Loader=yaml.SafeLoader, object_pairs_hook=OrderedDict):
    class OrderedLoader(Loader):
        pass

    def construct_mapping(loader, node):
        loader.flatten_mapping(node)
        return object_pairs_hook(loader.construct_pairs(node))
    OrderedLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        construct_mapping)
    return yaml.load(stream, OrderedLoader)


def ordered_dump(data, stream=None, Dumper=yaml.SafeDumper, **kwds):
    class OrderedDumper(Dumper):
        pass

    def _dict_representer(dumper, data):
        return dumper.represent_mapping(
            yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
            data.items())
    OrderedDumper.add_representer(OrderedDict, _dict_representer)
    return yaml.dump(data, stream, OrderedDumper, **kwds)


def main(argv):
    filename = argv[1]
    with open(filename) as f:
        data = ordered_load(f)

    for obj in data:
        fields = obj['fields']
        for k, v in fields.items():
            if k in JSONFIELDS and v:
                try:
                    d = json.loads(v)
                    fields[k] = json.dumps(d, sort_keys=True)
                except json.JSONDecodeError:
                    continue

    with open(filename, 'w') as f:
        ordered_dump(data, stream=f)


if __name__ == '__main__':
    main(sys.argv)
