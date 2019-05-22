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
import signal
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
from scionlab.tasks import _deploy_host_config
from scionlab.tests import utils
from scionlab.tests.utils import basic_auth


task_pre_check = {}
execution_log = []

# Some test data:
test_public_ip = '172.31.0.111'
test_public_port = 54321
deployment_required = True

_TEST_DEPLOYMENT_PERIOD = 3
_SLEEP_PERIOD = 0.01


@huey.task()
def add(a, b):
    # dummy task
    return a + b


@huey.pre_execute()
def mock_preexecute_hook(task):
    global task_pre_check
    task_pre_check = {'name': task.name,
                      'args': task.args}


@huey.HUEY.signal(huey_internal.signals.SIGNAL_CANCELED)
def task_canceled_handler(signal, task, exc=None):
    # This handler will be called when the task is cancelled, showing that the task was aborted
    logging.info('[%s] %s - not executed' % (signal, task.id))


def _peek_deploy_host_ongoing(host_id):
    return huey.HUEY.get('scionlab_deploy_host_ongoing_' + host_id, peek=True) is not None


def _peek_deploy_host_triggered(host_id):
    return huey.HUEY.get('scionlab_deploy_host_triggered_' + host_id, peek=True) is not None


def _fake_invoke_ssh_scionlab_config(ssh_host, host_id, host_secret):
    task_running = _peek_deploy_host_ongoing(host_id)
    assert (task_running)
    triggered = _peek_deploy_host_triggered(host_id)
    command = ('scionlab-config'
               ' --host-id {host_id}'
               ' --host-secret {host_secret}'
               ' --url "{url}"').format(
                  host_id=host_id,
                  host_secret=host_secret,
                  url='localhost:8080')

    logging.info("ssh %s '%s'" % (ssh_host, command))
    logging.info("Task info: task running %s, task retriggered %s" % (task_running, triggered))
    execution = "ssh %s %s" % (ssh_host, command)
    execution_log.append(execution)


def _fake_check_deployment_required(host_id):
    return deployment_required


def _fake_notify_deploy_success(host_id, host_secret):
    # Mock the client side call to notify success to the coordinator
    client = TestCase.client_class()
    deployed_config_version = Host.objects.get(uid=host_id).config_version
    post_url = reverse('api_post_deployed_version', kwargs={'uid': host_id})
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
    global deployment_required
    deployment_required = False


class TestingConsumer:
    def __init__(self):
        self.consumer = huey.HUEY.create_consumer()
        self.thread = Thread(target=self.consumer.run)

    def start(self):
        # disable signal handling for mock consumer, since signal only works in main thread
        signal.signal = patch('signal.signal')
        signal.signal.start()
        self.thread.start()
        signal.signal.stop()
        logging.info("Consumer started.")

    def stop(self):
        if self.thread.is_alive():
            self.thread.join(timeout=1.0)
        self.consumer.stop()
        logging.info("Consumer stopped.")

    @staticmethod
    def drain_queue():
        while len(huey.HUEY.scheduled()) > 0 or len(huey.HUEY.pending()) > 0:
            time.sleep(_SLEEP_PERIOD)
        time.sleep(_SLEEP_PERIOD)

    def drain_and_stop(self):
        self.drain_queue()
        self.stop()


def pending_tasks_by_name(name):
    return len([t for t in huey.HUEY.pending() if t.name == name])


def scheduled_tasks_by_name(name):
    return len([t for t in huey.HUEY.scheduled() if t.name == name])


class DeployHostConfigTests(TestCase):
    fixtures = ['testuser', 'testtopo-ases-links']

    def setUp(self):
        # Ensure we start the test with a clean queue
        huey.HUEY.storage.flush_results()
        huey.HUEY.storage.flush_queue()
        self.assertEqual(len(huey.HUEY.scheduled()), 0)
        self.assertEqual(len(huey.HUEY.pending()), 0)
        # Avoid duplication, get this info here:
        self.host = None
        self.url = "localhost:8080"
        self.attachment_point = AttachmentPoint.objects.first()
        assert(self.attachment_point)

        # add some state config
        huey.HUEY.immediate = False
        settings.DEPLOYMENT_PERIOD = _TEST_DEPLOYMENT_PERIOD
        self.consumer = TestingConsumer()
        global task_pre_check
        task_pre_check = {}

    def tearDown(self):
        self.consumer.stop()

    @classmethod
    def tearDownClass(cls):
        huey.HUEY.immediate = False
        super().tearDownClass()

    def test_dummy(self):
        huey.HUEY.immediate = True
        # Tests that the queue setup works
        # test dummy task
        dress = add(2, 3)
        self.assertEqual(len(huey.HUEY.pending()), 0)
        logging.info('2 + 3 = %s' % dress.get(blocking=True))
        # done with dummy

    def test_host_noop_update(self):
        with patch('subprocess.call',
                   side_effect=utils.subprocess_call_log) as mock_subprocess_call:
            logging.debug("Mocking: %s" % (mock_subprocess_call,))
            self.consumer.start()
            # Trigger an initial deployment and fake deployed config version
            self.attachment_point.trigger_deployment()
            self.consumer.drain_and_stop()
            ap_host = self.attachment_point.AS.hosts.first()
            ap_host.config_version_deployed = ap_host.config_version
            ap_host.save()
            # Create change that does not require a redeployment on the AP
            self.attachment_point.AS.hosts.first().update(label="New label")
            self.attachment_point.trigger_deployment()
            self.assertEqual(len(huey.HUEY.pending()), 0)

    def test_enqueing(self):
        hosts_pending_before = set(Host.objects.needs_config_deployment())
        with patch('scionlab.tasks._invoke_ssh_scionlab_config',
                   side_effect=_fake_invoke_ssh_scionlab_config) as mock_remote_ssh:
            global deployment_required
            deployment_required = True
            logging.debug("Mocking: %s" % (mock_remote_ssh,))
            with patch('scionlab.tasks._check_host_needs_config_deployment',
                       side_effect=_fake_check_deployment_required) as mock_requires_deployment:
                logging.debug("Mocking: %s" % (mock_requires_deployment,))
                self.assertEqual(len(huey.HUEY.pending()), 0)
                executions = len(execution_log)
                self.consumer.start()
                user_as = UserAS.objects.create(
                    owner=get_testuser(),
                    attachment_point=self.attachment_point,
                    installation_type=UserAS.DEDICATED,
                    label="Some label",
                    use_vpn=False,
                    public_ip=test_public_ip,
                    public_port=test_public_port,
                )
                self.host = user_as.attachment_point.AS.hosts.first()
                # Check trigger was consumed
                while _peek_deploy_host_triggered(self.host.uid):
                    time.sleep(_SLEEP_PERIOD)
                # Check AS needs_config_deployment:
                all_user_as_hosts = user_as.hosts.all()
                all_attachment_point_hosts = self.attachment_point.AS.hosts.all()
                hosts_requiring_deployment = Host.objects.needs_config_deployment()
                self.assertSetEqual(
                    hosts_pending_before | set(all_user_as_hosts | all_attachment_point_hosts),
                    set(hosts_requiring_deployment)
                )
                _fake_notify_deploy_success(user_as.attachment_point.AS.hosts.first().uid,
                                            user_as.attachment_point.AS.hosts.first().secret)

                self.consumer.drain_queue()
                self._verify_deploy_task(self.host, task_pre_check['name'], task_pre_check['args'])
                self._check_execution_log(self.host)
                self.assertTrue(len(execution_log) > executions)
                self.assertFalse(_peek_deploy_host_ongoing(self.host.uid))

                deployment_required = True
                last_ap = AttachmentPoint.objects.last()
                user_as2 = UserAS.objects.create(
                    owner=get_testuser(),
                    attachment_point=last_ap,
                    installation_type=UserAS.DEDICATED,
                    label="Some other label",
                    use_vpn=False,
                    public_ip=str(ipaddress.ip_address(test_public_ip)+1),
                    public_port=test_public_port,
                )
                self.host = user_as2.attachment_point.AS.hosts.first()
                # Check trigger was consumed
                while _peek_deploy_host_triggered(self.host.uid):
                    time.sleep(_SLEEP_PERIOD)
                self.consumer.drain_and_stop()
                self._verify_deploy_task(self.host, task_pre_check['name'], task_pre_check['args'])
                self._check_execution_log(self.host)
                self.assertFalse(_peek_deploy_host_ongoing(self.host.uid))

    def test_dequeuing(self):
        with patch('subprocess.call',
                   side_effect=utils.subprocess_call_log) as mock_subprocess_call:
            logging.debug("Mocking: %s" % (mock_subprocess_call,))
            self.assertEqual(len(huey.HUEY.pending()), 0)
            user_as = UserAS.objects.create(
                owner=get_testuser(),
                attachment_point=self.attachment_point,
                installation_type=UserAS.DEDICATED,
                label="Some label",
                use_vpn=False,
                public_ip=test_public_ip,
                public_port=test_public_port,
            )
            self.host = user_as.attachment_point.AS.hosts.first()
            deploy_task = huey.HUEY.pending()[0]
            self._verify_deploy_task(self.host, deploy_task.name, deploy_task.args)
            self.consumer.start()
            self.consumer.drain_and_stop()
            self.assertEqual(len(huey.HUEY.pending()), 0)

    def test_canceled(self):
        # The current use of the huey taskqueue does not make use of revoked task
        # Remove this test if no future feature makes use of revoked tasks
        with patch('subprocess.call',
                   side_effect=utils.subprocess_call_log) as mock_subprocess_call:
            logging.debug("Mocking: %s" % (mock_subprocess_call,))
            self.assertEqual(len(huey.HUEY.pending()), 0)
            user_as = UserAS.objects.create(
                owner=get_testuser(),
                attachment_point=self.attachment_point,
                installation_type=UserAS.DEDICATED,
                label="Some label",
                use_vpn=False,
                public_ip=str(ipaddress.ip_address(test_public_ip)+1),
                public_port=test_public_port,
            )
            self.host = user_as.attachment_point.AS.hosts.first()
            deploy_task = [t for t in huey.HUEY.pending() if t.name == '_deploy_host_config'][0]
            huey.HUEY._emit(huey_internal.signals.SIGNAL_CANCELED, deploy_task)
            _deploy_host_config.revoke()
            self._verify_deploy_task(self.host, deploy_task.name, deploy_task.args)

            self.consumer.start()
            self.consumer.drain_and_stop()
            self.assertEqual(len(huey.HUEY.pending()), 0)
            # check task was not executed
            self.assertEqual(task_pre_check, {})

    def test_double_trigger_update(self):
        with patch('subprocess.call',
                   side_effect=utils.subprocess_call_log) as mock_subprocess_call:
            logging.debug("Mocking: %s" % (mock_subprocess_call,))
            self.assertEqual(len(huey.HUEY.pending()), 0)
            self.attachment_point.trigger_deployment()
            self.attachment_point.trigger_deployment()
            self.assertEqual(pending_tasks_by_name('_deploy_host_config'), 1)
            self.consumer.start()
            self.consumer.drain_and_stop()
            self.assertEqual(pending_tasks_by_name('_deploy_host_config'), 0)

    def test_empty(self):
        with patch('subprocess.call',
                   side_effect=utils.subprocess_call_log) as mock_subprocess_call:
            self.assertEqual(len(huey.HUEY.pending()), 0)
            self.assertEqual(len(huey.HUEY.scheduled()), 0)
            # reading from empty queue should not affect later execution
            self.consumer.start()
            self.assertEqual(len(huey.HUEY.pending()), 0)

            logging.debug("Mocking: %s" % (mock_subprocess_call,))
            self.assertEqual(len(huey.HUEY.pending()), 0)
            user_as = UserAS.objects.create(
                owner=get_testuser(),
                attachment_point=self.attachment_point,
                installation_type=UserAS.DEDICATED,
                label="Some label",
                use_vpn=False,
                public_ip=str(ipaddress.ip_address(test_public_ip)+2),
                public_port=test_public_port,
            )
            self.host = user_as.attachment_point.AS.hosts.first()
            self.consumer.drain_and_stop()
            self._verify_deploy_task(self.host, task_pre_check['name'], task_pre_check['args'])

    def _verify_deploy_task(self, host, task_name, task_args):
        self.assertEqual(task_name, "_deploy_host_config")
        self.assertEqual(task_args, (host.ssh_host, host.uid, host.secret))

    def _check_execution_log(self, host):
        self.assertEqual(execution_log[-1],
                         "ssh %s scionlab-config --host-id %s "
                         "--host-secret %s --url \"%s\"" % (
                                host.ssh_host,
                                host.uid,
                                host.secret,
                                self.url))
