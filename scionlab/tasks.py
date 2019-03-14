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
Huey tasks config for scionlab project.
"""

import logging
import subprocess
import time
import huey.contrib.djhuey as huey


# TODO(matzf) remove
def echo_task(message, sleep_time):
    """
    Simple echo task for testing.
    """
    # De-dupe using lock_task.
    with huey.lock_task(message):
        print(message)
        time.sleep(sleep_time)
        print(message, 'done')


def deploy_host_config(host):
    """
    Trigger configuration deployment for a managed scionlab host.
    """
    assert host.managed
    # Double check that this is not a no-op:
    # Note that we could defer this check by passing the local version
    # to the GET config request, but this is obviously cheaper.
    if not host.needs_config_deployment():
        return
    _deploy_host_config(host.management_ip,
                        host.pk,
                        host.secret)


@huey.task()
def _deploy_host_config(ssh_host, host_id, host_secret):
    """
    Task to deploy configuration to a managed scionlab host.
    Ensures that only one such task is executing per host.

    Note: parameters are passed individually instead of as the full host object,
    because the parameters are serialised by huey.

    :param str ssh_host: name to ssh to host
    :param str host_id: id (primary key) of the Host object
    :param str host_secret: secret to authenticate request for this Host object
    """
    try:
        with huey.lock_task(str(host_id)):
            _invoke_ssh_scionlab_config(ssh_host, host_id, host_secret)
    except huey.exceptions.TaskLockedException:
        pass


def _invoke_ssh_scionlab_config(ssh_host, host_id, host_secret):
    command = ('scionlab-config'
               ' --host-id {host_id}'
               ' --host-secret {host_secret}'
               ' --url "{url}"').format(
                  host_id=host_id,
                  host_secret=host_secret,
                  url='localhost:8080')  # TODO(matzf)

    logging.info("ssh %s '%s'" % (ssh_host, command))
    subprocess.call(['ssh', ssh_host, command])
