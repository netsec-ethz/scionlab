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

""" Update AS keys and trigger re-deployment """

import sys
import time
from django.db import transaction

from scionlab.models.core import AS, Host
import scionlab.tasks


def main(argv):
    as_id = argv[1]
    print("Update keys for AS %s" % as_id)
    update_keys(as_id)

    print("Await confirmation that AS %s has been deployed" % as_id)
    wait_until_deployed(as_id)
    print("Deployment of AS %s confirmed." % as_id)


@transaction.atomic
def update_keys(as_id):
    as_ = AS.objects.filter(as_id=as_id).get()
    as_.update_keys()

    for h in as_.hosts.iterator():
        assert h.managed
        assert h.ssh_host
        scionlab.tasks.deploy_host_config(h)


def wait_until_deployed(as_id):
    while Host.objects.needs_config_deployment().filter(AS__as_id=as_id).exists():
        time.sleep(1)


if __name__ == '__main__':
    main(sys.argv)
