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
import huey.contrib.djhuey as huey
from scionlab.models import Host


def deploy_host_config(host, delay=None):
    """
    Trigger configuration deployment for a managed scionlab host.

    Ensures that only one such task is executing per host.

    The deployment is run asynchronously, so that will actually be deployed could be any version
    later than the current version.

    Note that if a delay is specified, all subsequently triggered tasks will wait for this delay,
    even if don't have a delay specified.

    :param Host host:
    :param int delay: optional delay in seconds. Number of seconds to wait until execution starts.
    """
    assert host.managed

    # Double check that this is not a no-op:
    if not host.needs_config_deployment():
        return

    # Custom trickery with hueys key-value store:
    # ensure only one task per host is in the queue or executing at any time.
    if _put_if_empty(_key_deploy_host_running(host.pk), True):
        _deploy_host_config.schedule(args=(host.management_ip, host.pk, host.secret), delay=delay)
    else:
        # Mark as re-triggered to ensure that the task will re-run if necessary.
        _put_if_empty(_key_deploy_host_retriggered(host.pk), True)


@huey.task()
def _deploy_host_config(ssh_host, host_id, host_secret):
    """
    Task to deploy configuration to a managed scionlab host.

    Note: parameters are passed individually instead of as the full host object,
    because the parameters are serialised by huey.

    :param str ssh_host: name to ssh to host
    :param str host_id: id (primary key) of the Host object
    :param str host_secret: secret to authenticate request for this Host object
    """
    try:
        while True:
            _invoke_ssh_scionlab_config(ssh_host, host_id, host_secret)
            retriggered = huey.HUEY.get(_key_deploy_host_retriggered(host_id))
            if not retriggered or not _check_host_needs_config_deployment(host_id):
                break
    finally:
        huey.HUEY.get(_key_deploy_host_running(host_id))


def _check_host_needs_config_deployment(host_id):
    return Host.objects.get(id=host_id).needs_config_deployment()


# this wrapper is missing from huey.api
def _put_if_empty(key, value):
    import pickle
    return huey.HUEY.storage.put_if_empty(key,
                                          pickle.dumps(value, pickle.HIGHEST_PROTOCOL))


def _key_deploy_host_running(host_id):
    return 'scionlab_deploy_host_ongoing_' + str(host_id)


def _key_deploy_host_retriggered(host_id):
    return 'scionlab_deploy_host_version_retriggered' + str(host_id)


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
