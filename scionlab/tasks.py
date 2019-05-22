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
import shlex
import subprocess
import huey.contrib.djhuey as huey

from django.conf import settings


def deploy_host_config(host):
    """
    Initiates the configuration deployment for a managed scionlab host.

    Ensures that a task is only triggered when the configuration change requires a deployment.

    The deployment is run asynchronously, the version that will be deployed can be any version newer
    than the current one.

    :param Host host:
    """
    assert host.managed

    # Double check that this is not a no-op:
    if not host.needs_config_deployment():
        return

    _queue_or_trigger(host.ssh_host, host.uid, host.secret)


def _queue_or_trigger(ssh_host, host_id, host_secret):
    """
    Queues and/or sets the trigger for the configuration deployment of a managed scionlab host.

    Ensures that only one such task is executing per host by enforcing that
    at most one deploy task per host is in the queue.

    The deployment is run asynchronously, the version that will be deployed can be any version newer
    than the current one.

    :param str ssh_host: name to ssh to host
    :param str host_id: unique id of the Host object
    :param str host_secret: secret to authenticate request for this Host object
    """
    # Set the trigger for the task to run/re-run it if necessary.
    _put_if_empty(_key_deploy_host_triggered(host_id), True)

    # Custom trickery with hueys key-value store:
    # ensure only one task per host is in the queue or executing at any time.
    if _put_if_empty(_key_deploy_host_running(host_id), True):
        _deploy_host_config(ssh_host, host_id, host_secret)


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
        triggered = huey.HUEY.get(_key_deploy_host_triggered(host_id))
        # Check that the task was triggered since its last execution and it still needs deployment
        if triggered and _check_host_needs_config_deployment(host_id):
            # The task was triggered and needs execution, run it
            _invoke_ssh_scionlab_config(ssh_host, host_id, host_secret)

            # Schedule the task to be rerun no sooner than after the delay
            _deploy_host_config.schedule(args=(ssh_host, host_id, host_secret),
                                         delay=settings.DEPLOYMENT_PERIOD)
            return
    except Exception as e:
        logging.error("Huey task _deploy_host_config failed with %s" % e)

    # task was not run or failed to run, release lock
    huey.HUEY.get(_key_deploy_host_running(host_id))


def _check_host_needs_config_deployment(host_id):
    from scionlab.models.core import Host
    return Host.objects.get(uid=host_id).needs_config_deployment()


# this wrapper is missing from huey.api
def _put_if_empty(key, value):
    import pickle
    return huey.HUEY.storage.put_if_empty(key,
                                          pickle.dumps(value, pickle.HIGHEST_PROTOCOL))


def _key_deploy_host_running(host_id):
    return 'scionlab_deploy_host_ongoing_' + host_id


def _key_deploy_host_triggered(host_id):
    return 'scionlab_deploy_host_triggered_' + host_id


def _invoke_ssh_scionlab_config(ssh_host, host_id, host_secret):
    """
    Calls the actual ssh command to deploy the configuration to a managed scionlab host.

    :param str ssh_host: name to ssh to host
    :param str host_id: id (primary key) of the Host object
    :param str host_secret: secret to authenticate request for this Host object
    """
    command = ('scionlab-config'
               ' --host-id {host_id}'
               ' --host-secret {host_secret}'
               ' --url "{url}"').format(
                  host_id=host_id,
                  host_secret=host_secret,
                  url=settings.SCIONLAB_SITE)

    args = ['ssh', '-F', settings.SSH_CONFIG_PATH, ssh_host, command]
    logging.info(' '.join(shlex.quote(a) for a in args))
    subprocess.call(args)
