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


from unittest import TestCase
from parameterized import parameterized
from scionlab.util.portmap import PortMap

_PARAMETERIZED_TEST_IPS = [('127.0.0.1',), (None,)]


class PortMapTests(TestCase):
    @parameterized.expand(_PARAMETERIZED_TEST_IPS)
    def test_add(self, ip):
        port = 30000
        portmap = PortMap()
        portmap.add(ip, port)
        self.assertTrue(portmap.is_used(ip, port))
        self.assertTrue(portmap.is_used(None, port))

    @parameterized.expand(_PARAMETERIZED_TEST_IPS)
    def test_empty(self, ip):
        port = PortMap().get_port(ip, min=30000)
        self.assertEqual(port, 30000)
        port = PortMap().get_port(ip, min=30000, max=31000)
        self.assertEqual(port, 30000)
        port = PortMap().get_port(ip, min=30000, max=31000, preferred=30100)
        self.assertEqual(port, 30100)
        port = PortMap().get_port(ip, min=30000, max=31000, preferred=12345)  #
        self.assertEqual(port, 12345)

    @parameterized.expand(_PARAMETERIZED_TEST_IPS)
    def test_used_after_get(self, ip):
        min_port = 30000

        portmap = PortMap()
        self.assertTrue(portmap.is_free(ip, min_port))
        port = portmap.get_port(ip, min_port)
        self.assertEqual(port, min_port)
        self.assertTrue(portmap.is_used(ip, port))
        self.assertTrue(portmap.is_used(None, port))

    @parameterized.expand(_PARAMETERIZED_TEST_IPS)
    def test_sequential(self, ip):
        min_port = 30000

        portmap = PortMap()
        port1 = portmap.get_port(ip, min_port)
        port2 = portmap.get_port(ip, min_port)
        port3 = portmap.get_port(ip, min_port, preferred=port1)  # ignored preferred

        self.assertEqual([port1, port2, port3], [min_port, min_port+1, min_port+2])

        with self.assertRaises(RuntimeError):
            portmap.get_port(ip, min=min_port, max=port3)
