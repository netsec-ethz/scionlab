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

import ipaddress
import logging
import time
from threading import Thread
from unittest.mock import patch

import huey as huey_internal
import huey.contrib.djhuey as huey
from django.conf import settings
from django.test import TestCase
from django.urls import reverse

from scionlab.fixtures.testuser import get_testuser
from scionlab.models.core import Host
from scionlab.models.user_as import AttachmentPoint, UserAS
from scionlab import tasks
from scionlab.tasks import _put_if_empty, _key_deploy_host_running
from scionlab.tests import utils
from scionlab.tests.utils import basic_auth

execution_log = []
task_pre_check = {}
task_post_check = {}

# Some test data:
test_public_ip = '172.31.0.111'
test_public_port = 54321

smaller_test_delay = 3


@huey.task()
def add(a, b):
    # dummy task
    return a + b


@huey.pre_execute()
def mock_preexecute_hook(task):
    global task_pre_check
    task_pre_check = {'name': task.name,

                      'args': task.args}


@huey.post_execute()
def mock_postexecute_hook(task, task_value, exception):
    global task_post_check
    task_post_check = {'name': task.name,
                       'args': task.args}


@huey.HUEY.signal(huey_internal.signals.SIGNAL_CANCELED)
def task_canceled_handler(signal, task, exc=None):
    # This handler will be called when the task is cancelled, showing that the task was aborted
    logging.info('[%s] %s - not executed' % (signal, task.id))


def _fake_invoke_ssh_scionlab_config(ssh_host, host_id, host_secret):
    task_running = huey.HUEY.get('scionlab_deploy_host_ongoing_'
                                 + str(host_id), peek=True) is not None
    assert (task_running)
    retriggered = huey.HUEY.get('scionlab_deploy_host_version_retriggered'
                                + str(host_id), peek=True) is not None
    command = ('scionlab-config'
               ' --host-id {host_id}'
               ' --host-secret {host_secret}'
               ' --url "{url}"').format(
                  host_id=host_id,
                  host_secret=host_secret,
                  url='localhost:8080')

    logging.info("ssh %s '%s'" % (ssh_host, command))
    logging.info("Task info: task running %s, task retriggered %s" % (task_running, retriggered))
    execution = "ssh %s %s" % (ssh_host, command)
    execution_log.append(execution)

    # Mock the client side call to notify success to the coordinator
    client = TestCase.client_class()
    deployed_config_version = Host.objects.get(id=host_id).config_version
    post_url = reverse('api_post_deployed_version', kwargs={'pk': host_id})
    auth_headers = basic_auth(host_id, host_secret)
    response = client.post(
        post_url,
        {'version': deployed_config_version},
        **auth_headers
    )
    logging.info("Status code"
                 " of posting version %s to API endpoint %s: %s" % (deployed_config_version,
                                                                    post_url,
                                                                    response.status_code))


def consume():
    consumer = huey.HUEY.create_consumer()
    # disable signal handling for mock consumer, since signal only works in main thread
    with patch('signal.signal') as mock_signals:
        logging.debug("Mocking: %s" % (mock_signals,))
        t = Thread(target=consumer.run)
        t.start()
        logging.info("Consumer started.")
        t.join(timeout=1.0)
        consumer.stop()
        logging.info("Consumer stopped.")


class DeployHostConfigTests(TestCase):
    fixtures = ['testuser', 'testtopo-ases-links']

    def setUp(self):
        # Ensure we start the test with a clean queue
        huey.HUEY.storage.flush_results()
        huey.HUEY.storage.flush_queue()
        self.assertEqual(len(huey.HUEY.pending()), 0)
        # Avoid duplication, get this info here:
        self.host = None
        self.url = "localhost:8080"
        # add some state config
        huey.HUEY.immediate = True
        settings.ATTACHMENT_POINT_DEPLOYMENT_PERIOD = None
        self.fake_needs_config_deployment = False
        global task_pre_check, task_post_check
        task_pre_check = {}
        task_post_check = {}

    @classmethod
    def tearDownClass(cls):
        huey.HUEY.immediate = False
        super().tearDownClass()

    def test_dummy(self):
        # Tests that the queue setup works
        # test dummy task
        dress = add(2, 3)
        self.assertEqual(len(huey.HUEY.pending()), 0)
        logging.info('2 + 3 = %s' % dress.get(blocking=True))
        # done with dummy

    def test_host_noop_update(self):
        attachment_point = AttachmentPoint.objects.first()
        huey.HUEY.immediate = False
        with patch('subprocess.call',
                   side_effect=utils.subprocess_call_log) as mock_subprocess_call:
            logging.debug("Mocking: %s" % (mock_subprocess_call,))
            self.assertEqual(len(huey.HUEY.pending()), 0)
            # Trigger an initial deployment and fake deployed config version
            attachment_point.trigger_deployment()
            consume()
            ap_host = attachment_point.AS.hosts.first()
            ap_host.config_version_deployed = ap_host.config_version
            ap_host.save()
            # Create change that does not require a redeployment on the AP
            attachment_point.AS.hosts.first().update(label="New label")
            attachment_point.trigger_deployment()
            self.assertEqual(len(huey.HUEY.pending()), 0)

    def test_enqueing(self):
        attachment_point = AttachmentPoint.objects.first()
        hosts_pending_before = set(Host.objects.needs_config_deployment())
        with patch('scionlab.tasks._invoke_ssh_scionlab_config',
                   side_effect=_fake_invoke_ssh_scionlab_config) as mock_remote_ssh:
            logging.debug("Mocking: %s" % (mock_remote_ssh,))
            self.assertEqual(len(huey.HUEY.pending()), 0)
            _put_if_empty(_key_deploy_host_running(attachment_point.AS.hosts.first().pk), True)
            user_as = UserAS.objects.create(
                owner=get_testuser(),
                attachment_point=attachment_point,
                installation_type=UserAS.DEDICATED,
                label="Some label",
                use_vpn=False,
                public_ip=test_public_ip,
                public_port=test_public_port,
            )
            # Check AS needs_config_deployment:
            self.assertSetEqual(
                hosts_pending_before | set(user_as.hosts.all() |
                                           attachment_point.AS.hosts.all()),
                set(Host.objects.needs_config_deployment())
            )
            self.host = user_as.attachment_point.AS.hosts.first()
            self.assertTrue(huey.HUEY.get('scionlab_deploy_host_ongoing_' + str(self.host.pk),
                                          peek=True))

            executions = len(execution_log)
            huey.HUEY.get(_key_deploy_host_running(self.host.pk))
            user_as.attachment_point.trigger_deployment()
            self.assertFalse(huey.HUEY.get('scionlab_deploy_host_ongoing_' + str(self.host.pk),
                                           peek=True))
            self.assertEqual("%s%s" % (task_pre_check['name'], task_pre_check['args']),
                             "_deploy_host_config('%s', %s, '%s')" % (self.host.management_ip,
                                                                      self.host.pk,
                                                                      self.host.secret))
            self.assertEqual(execution_log[-1],
                             "ssh %s scionlab-config --host-id %s "
                             "--host-secret %s --url \"%s\"" % (
                                 self.host.management_ip,
                                 self.host.pk,
                                 self.host.secret,
                                 self.url))
            self.assertTrue(len(execution_log) > executions)
            self.assertNotEqual(execution_log, [])

    def test_dequeuing(self):
        attachment_point = AttachmentPoint.objects.first()
        huey.HUEY.immediate = False
        settings.ATTACHMENT_POINT_DEPLOYMENT_PERIOD = smaller_test_delay
        with patch('subprocess.call',
                   side_effect=utils.subprocess_call_log) as mock_subprocess_call:
            logging.debug("Mocking: %s" % (mock_subprocess_call,))
            self.assertEqual(len(huey.HUEY.pending()), 0)
            user_as = UserAS.objects.create(
                owner=get_testuser(),
                attachment_point=attachment_point,
                installation_type=UserAS.DEDICATED,
                label="Some label",
                use_vpn=False,
                public_ip=test_public_ip,
                public_port=test_public_port,
            )
            self.host = user_as.attachment_point.AS.hosts.first()
            deploy_task = huey.HUEY.pending()[0]
            self.assertEqual("%s%s" % (deploy_task.name, deploy_task.args),
                             "_deploy_host_config('%s', %s, '%s')" % (self.host.management_ip,
                                                                      self.host.pk,
                                                                      self.host.secret))
            time.sleep(smaller_test_delay+1)
            consume()
            self.assertEqual(len(huey.HUEY.pending()), 0)
        settings.ATTACHMENT_POINT_DEPLOYMENT_PERIOD = None

    def test_canceled(self):
        # The current use of the huey taskqueue does not make use of revoked task
        # Remove this test if no future feature makes use of revoked tasks
        attachment_point = AttachmentPoint.objects.first()
        huey.HUEY.immediate = False
        with patch('subprocess.call',
                   side_effect=utils.subprocess_call_log) as mock_subprocess_call:
            logging.debug("Mocking: %s" % (mock_subprocess_call,))
            self.assertEqual(len(huey.HUEY.pending()), 0)
            user_as = UserAS.objects.create(
                owner=get_testuser(),
                attachment_point=attachment_point,
                installation_type=UserAS.DEDICATED,
                label="Some label",
                use_vpn=False,
                public_ip=str(ipaddress.ip_address(test_public_ip)+1),
                public_port=test_public_port,
            )
            self.host = user_as.attachment_point.AS.hosts.first()
            deploy_task = huey.HUEY.pending()[0]
            huey.HUEY._emit(huey_internal.signals.SIGNAL_CANCELED, deploy_task)
            tasks._deploy_host_config.revoke()
            self.assertEqual("%s%s" % (deploy_task.name, deploy_task.args),
                             "_deploy_host_config('%s', %s, '%s')" % (self.host.management_ip,
                                                                      self.host.pk,
                                                                      self.host.secret))
            consume()
            self.assertEqual(len(huey.HUEY.pending()), 0)
            # check task was not executed
            self.assertEqual(task_pre_check, {})

    def test_double_trigger_update(self):
        attachment_point = AttachmentPoint.objects.first()
        huey.HUEY.immediate = False
        with patch('subprocess.call',
                   side_effect=utils.subprocess_call_log) as mock_subprocess_call:
            logging.debug("Mocking: %s" % (mock_subprocess_call,))
            self.assertEqual(len(huey.HUEY.pending()), 0)
            attachment_point.trigger_deployment()
            attachment_point.trigger_deployment()
            self.assertEqual(len(huey.HUEY.pending()), 1)
            consume()
            self.assertEqual(len(huey.HUEY.pending()), 0)

    def test_empty(self):
        huey.HUEY.immediate = False
        self.assertEqual(len(huey.HUEY.pending()), 0)
        # reading from empty queue should not affect later execution
        consume()
        self.assertEqual(len(huey.HUEY.pending()), 0)
        huey.HUEY.immediate = True

        attachment_point = AttachmentPoint.objects.first()
        with patch('subprocess.call',
                   side_effect=utils.subprocess_call_log) as mock_subprocess_call:
            logging.debug("Mocking: %s" % (mock_subprocess_call,))
            self.assertEqual(len(huey.HUEY.pending()), 0)
            user_as = UserAS.objects.create(
                owner=get_testuser(),
                attachment_point=attachment_point,
                installation_type=UserAS.DEDICATED,
                label="Some label",
                use_vpn=False,
                public_ip=str(ipaddress.ip_address(test_public_ip)+2),
                public_port=test_public_port,
            )
            self.host = user_as.attachment_point.AS.hosts.first()
            self.assertEqual("%s%s" % (task_pre_check['name'], task_pre_check['args']),
                             "_deploy_host_config('%s', %s, '%s')" % (self.host.management_ip,
                                                                      self.host.pk,
                                                                      self.host.secret))
