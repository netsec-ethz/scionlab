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
import sys
import time

import django

TIMEOUT = 60


def main(argv):
    as_ids = argv[1:]
    trigger_deployment(as_ids)
    print("Await confirmation that AS %s have been deployed" % as_ids)
    wait_until_deployed(as_ids)


def trigger_deployment(as_ids):
    import scionlab.tasks

    for h in _needs_deployment(as_ids):
        assert h.managed
        assert h.ssh_host
        scionlab.tasks.deploy_host_config(h)
        print("Deployment enqueued for %s", h)


def wait_until_deployed(as_ids):
    timeout = time.time() + TIMEOUT
    left = _needs_deployment(as_ids)
    while time.time() < timeout and left:
        time.sleep(1)

    if left:
        print("Timout while waiting for confirmation of deployment from hosts:\n", "\n".join(left))
    else:
        print("Deployment successful")


def _needs_deployment(as_ids):
    from scionlab.models.core import Host
    return list(Host.objects.needs_config_deployment().filter(AS__as_id__in=as_ids))


if __name__ == '__main__':
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'scionlab.settings.development')
    django.setup()
    main(sys.argv)
