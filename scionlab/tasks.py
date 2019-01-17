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
import os
import time
from huey.contrib.djhuey import task, lock_task
from huey.exceptions import TaskLockedException

SSH_CONNECT_TIMEOUT_SECONDS = 5

# TODO(matzf) remove
@task()
def echo_task(message, sleep_time):
    """
    Simple echo task for testing.
    """
    # De-dupe using lock_task.
    try:
        with lock_task(message):
            print(message)
            time.sleep(sleep_time)
            print(message, 'done')
    except TaskLockedException:
        pass


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
                        host.ssh_port,
                        'scion',
                        host.pk,
                        host.secret)


@task()
def _deploy_host_config(ip, ssh_port, ssh_user, host_id, host_secret):
    """
    Task to deploy configuration to a managed scionlab host.
    Ensures that only one such task is executing per host.

    Note: parameters are passed individually instead of the entire host object, because the
    parameters are serialised (by huey).
    """
    try:
        with lock_task(str(host_id)):
            _invoke_ssh_scionlab_config(ip, ssh_port, ssh_user, host_id, host_secret)
    except TaskLockedException:
        pass


def _invoke_ssh_scionlab_config(ip, ssh_port, ssh_user, host_id, host_secret):
    command = ('scionlab-config'
               ' --force'
               ' --host-id {host_id}'
               ' --host-secret {host_secret}'
               ' --url "{url}"').format(
                  host_id=host_id,
                  host_secret=host_secret,
                  url='localhost:8080')  # TODO(matzf)

    # TODO or rather only define a hostname and define the other settings in ssh-config?
    ssh_command = "ssh -p {port} {user}@{host} -o ConnectTimeout={timeout} '{command}'".format(
                    port=ssh_port,
                    user=ssh_user,
                    host=ip,
                    timeout=SSH_CONNECT_TIMEOUT_SECONDS,
                    command=command)

    logging.info(ssh_command)
    os.system(ssh_command)
