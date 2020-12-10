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
import os
import pathlib
import re
from io import StringIO
from unittest.mock import patch


from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa
from django.core.management import CommandError
from django.core.management import call_command
from django.test import TestCase, SimpleTestCase, override_settings
from django.conf import settings

from scionlab.fixtures.testuser import get_testuser
from scionlab.models.user_as import AttachmentPoint, UserAS, AttachmentConf
from scionlab.models.vpn import VPN
from scionlab.openvpn_config import write_vpn_ca_config, generate_vpn_client_config, \
    load_ca_cert, _generate_private_key, load_ca_key, _generate_root_ca_cert, \
    generate_vpn_server_config, ccd_config, _truncated_unique_name

test_public_port = 54321

TEST_CA_KEY_PATH = os.path.join(settings.BASE_DIR, 'run', 'test_root_ca_key.pem')
TEST_CA_CERT_PATH = os.path.join(settings.BASE_DIR, 'run', 'test_root_ca_cert.pem')


def _setup_vpn_attachment_point():
    """ Setup VPN for the first AP """
    ap = AttachmentPoint.objects.first()
    ap.vpn = VPN.objects.create(server=ap.AS.hosts.first(),
                                subnet='10.0.8.0/24',
                                server_vpn_ip='10.0.8.1',
                                server_port=4321)
    ap.save()


def create_user_as(ap, label='Some label'):
    user_as = UserAS.objects.create(
        owner=get_testuser(),
        installation_type=UserAS.VM,
        isd=ap.AS.isd,
        label=label,
    )
    att_conf = AttachmentConf(ap,
                              use_vpn=True,
                              public_port=test_public_port)
    user_as.update_attachments([att_conf])
    return user_as


@override_settings(VPN_CA_KEY_PATH=TEST_CA_KEY_PATH, VPN_CA_CERT_PATH=TEST_CA_CERT_PATH)
class RootCASetupTests(TestCase):
    def tearDown(self):
        # cleanup test files
        os.remove(TEST_CA_KEY_PATH)
        os.remove(TEST_CA_CERT_PATH)

    def test_initialization(self):
        out = StringIO()
        call_command('initialize_root_ca', stderr=out)

        # Check that calling again gives appropriate warning
        with self.assertRaises(CommandError) as rcm:
            call_command('initialize_root_ca', stderr=out)
        self.assertIn('Root CA files already generated.', str(rcm.exception))

    def test_generating_ca_cert__existing_key(self):
        call_command('initialize_root_ca')

        # remove cert
        stored_ca_cert = load_ca_cert()
        os.remove(TEST_CA_CERT_PATH)

        # call command again with existing key
        call_command('initialize_root_ca')
        new_ca_cert = load_ca_cert()
        self.assertEqual(stored_ca_cert.public_key().public_bytes(
                             encoding=serialization.Encoding.PEM,
                             format=serialization.PublicFormat.PKCS1).decode(),
                         new_ca_cert.public_key().public_bytes(
                             encoding=serialization.Encoding.PEM,
                             format=serialization.PublicFormat.PKCS1).decode())

    def test_loading_ca_key(self):
        ca_key = _generate_private_key()
        with patch('scionlab.openvpn_config._generate_private_key', return_value=ca_key):
            call_command('initialize_root_ca')
        stored_ca_key = load_ca_key()
        self.assertEqual(ca_key.private_bytes(
                             encoding=serialization.Encoding.PEM,
                             format=serialization.PrivateFormat.TraditionalOpenSSL,
                             encryption_algorithm=serialization.NoEncryption()).decode(),
                         stored_ca_key.private_bytes(
                             encoding=serialization.Encoding.PEM,
                             format=serialization.PrivateFormat.TraditionalOpenSSL,
                             encryption_algorithm=serialization.NoEncryption()).decode())

        # replace with wrong key type
        wrong_key = dsa.generate_private_key(
            key_size=3072,
        )

        pathlib.Path(TEST_CA_KEY_PATH).write_bytes(
            wrong_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(
                    settings.VPN_CA_KEY_PASSWORD.encode('utf-8'))
            )
        )

        # detect wrong key type
        with self.assertRaises(TypeError):
            load_ca_key()

    def test_loading_ca_cert(self):
        ca_key = _generate_private_key()
        ca_cert = _generate_root_ca_cert(ca_key)
        with patch('scionlab.openvpn_config._generate_root_ca_cert', return_value=ca_cert):
            call_command('initialize_root_ca')
        stored_ca_cert = load_ca_cert()
        self.assertEqual(ca_cert.public_bytes(serialization.Encoding.PEM).decode(),
                         stored_ca_cert.public_bytes(serialization.Encoding.PEM).decode())


@override_settings(VPN_CA_KEY_PATH=TEST_CA_KEY_PATH, VPN_CA_CERT_PATH=TEST_CA_CERT_PATH)
class VPNCertsTests(TestCase):
    fixtures = ['testdata']

    def setUp(self):
        write_vpn_ca_config()
        _setup_vpn_attachment_point()

    def tearDown(self):
        # cleanup test files
        os.remove(TEST_CA_KEY_PATH)
        os.remove(TEST_CA_CERT_PATH)

    def test_generate_certs(self):
        attachment_point = AttachmentPoint.objects.first()

        user_as = create_user_as(attachment_point)

        vpn_client = user_as.hosts.first().vpn_clients.first()
        config = generate_vpn_client_config(vpn_client)

        # check ca cert
        ca_cert_string_match = re.findall('<ca>\n(.*?)\n</ca>', config, flags=re.DOTALL)
        self.assertTrue(len(ca_cert_string_match) == 1)
        ca_cert = ca_cert_string_match[0]
        config_ca_cert = x509.load_pem_x509_certificate(ca_cert.encode())
        self.assertEqual(load_ca_cert().public_bytes(serialization.Encoding.PEM).decode(),
                         config_ca_cert.public_bytes(serialization.Encoding.PEM).decode())

        # check client cert
        client_cert_string_match = re.findall('<cert>\n(.*?)\n</cert>', config, flags=re.DOTALL)
        self.assertTrue(len(client_cert_string_match) == 1)
        client_cert = client_cert_string_match[0]
        config_client_cert = x509.load_pem_x509_certificate(client_cert.encode())
        self.assertEqual(vpn_client.cert,
                         config_client_cert.public_bytes(serialization.Encoding.PEM).decode())

        # check client key
        client_key_string_match = re.findall('<key>\n(.*?)\n</key>', config, flags=re.DOTALL)
        self.assertTrue(len(client_key_string_match) == 1)
        client_key = client_key_string_match[0]
        config_client_key = serialization.load_pem_private_key(client_key.encode(),
                                                               password=None)
        self.assertEqual(vpn_client.private_key,
                         config_client_key.private_bytes(
                             encoding=serialization.Encoding.PEM,
                             format=serialization.PrivateFormat.TraditionalOpenSSL,
                             encryption_algorithm=serialization.NoEncryption()).decode()
                         )

        # check public key for private key matches public key in certificate
        self.assertEqual(config_client_cert.public_key().public_bytes(
                             encoding=serialization.Encoding.PEM,
                             format=serialization.PublicFormat.PKCS1).decode(),
                         config_client_key.public_key().public_bytes(
                             encoding=serialization.Encoding.PEM,
                             format=serialization.PublicFormat.PKCS1).decode())

    def test_generate_server_config(self):
        attachment_point = AttachmentPoint.objects.first()
        vpn = attachment_point.vpn
        server_config = generate_vpn_server_config(vpn)
        ifconfig_string_match = re.findall('ifconfig ([0-9.:]*) ([0-9.:]*)',
                                           server_config)
        self.assertEqual(len(ifconfig_string_match), 1)
        server_ip, netmask = ifconfig_string_match[0]
        route_string_match = re.findall('route ([0-9.:/]*) ([0-9.:]*)',
                                        server_config)
        self.assertEqual(len(route_string_match), 1)
        subnet, route_netmask = route_string_match[0]
        self.assertEqual(route_netmask, netmask)

        vpn_network = ipaddress.ip_network(vpn.subnet)

        # Check VPN IPs valid
        self.assertEqual(str(vpn_network.netmask), netmask)
        self.assertEqual(str(vpn_network), subnet)
        self.assertTrue(ipaddress.ip_address(server_ip) in vpn_network.hosts())

        # Check CCD
        user_as = create_user_as(attachment_point)

        vpn_client = user_as.hosts.first().vpn_clients.first()
        ccd_filename, ccd_config_entry = ccd_config(vpn_client)
        self.assertEqual(ccd_filename,
                         vpn_client.host.AS.owner.email+"_"+user_as.as_path_str())
        ccd_string_match = re.findall(r'ifconfig-push (\S*) (\S*)', ccd_config_entry)
        self.assertTrue(len(ccd_string_match) == 1)
        client_ip, netmask = ccd_string_match[0]
        self.assertEqual(str(vpn_client.ip), client_ip)
        self.assertEqual(str(vpn_network.netmask), netmask)


@override_settings(VPN_CA_KEY_PATH=TEST_CA_KEY_PATH, VPN_CA_CERT_PATH=TEST_CA_CERT_PATH)
class VPNCertsMissingCATests(TestCase):
    fixtures = ['testdata']

    def tearDown(self):
        # cleanup test files
        try:
            os.remove(TEST_CA_KEY_PATH)
            os.remove(TEST_CA_CERT_PATH)
        except FileNotFoundError:
            pass

    def test_generate_client_cert(self):
        write_vpn_ca_config()
        _setup_vpn_attachment_point()
        attachment_point = AttachmentPoint.objects.first()

        # remove CA key material
        os.remove(TEST_CA_KEY_PATH)

        with self.assertRaises(RuntimeError) as rcm:
            create_user_as(attachment_point, 'Some label2')
        self.assertIn('Missing CA root configuration.', str(rcm.exception))

        # remove CA cert material
        os.remove(TEST_CA_CERT_PATH)

        with self.assertRaises(RuntimeError) as rcm:
            create_user_as(attachment_point, 'Some label3')
        self.assertIn('Missing CA root configuration.', str(rcm.exception))


class TruncatedNameTests(SimpleTestCase):
    def test_pass_through(self):
        cases = ['short', 'a'*63, 'b'*64]
        for name in cases:
            self.assertLessEqual(len(name), 64, "Sanity check for test input")
            expected = name
            actual = _truncated_unique_name(name)
            self.assertEqual(expected, actual)

    def test_shorten(self):
        cases = [
            'spam_ham_eggs_foo_bar_boo_raboof_fubar_fnord_lorem_ipsum_dolor_sit',
            'a'*65,
        ]

        for name in cases:
            self.assertGreater(len(name), 64, "Sanity check for test input")
            results = []
            for _ in range(20):
                shortened = _truncated_unique_name(name)
                self.assertEqual(len(shortened), 64)
                self.assertEqual(shortened[:32], name[:32])
                results.append(shortened)

            self.assertEqual(len(results), len(set(results)), "Expected unique names")
