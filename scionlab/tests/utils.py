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

import re
import base64
import lib.crypto.asymcrypto
from collections import namedtuple, Counter, OrderedDict
from scionlab.models import AS, Host, Service, Link, MAX_PORT


def check_topology(testcase):
    """
    Run all sanity checks for the current state of the models in the DB.
    """
    for as_ in AS.objects.iterator():
        check_as_services(testcase, as_)
        check_as_keys(testcase, as_)
        if as_.is_core:
            check_as_core_keys(testcase, as_)
    for host in Host.objects.iterator():
        check_host_ports(testcase, host)
    for link in Link.objects.iterator():
        check_link(testcase, link)


def check_as_services(testcase, as_):
    """
    Check that all the AS has all required services configured.
    """
    counter = Counter(service.type for service in as_.services.iterator())
    testcase.assertGreaterEqual(counter[Service.BS], 1)
    testcase.assertGreaterEqual(counter[Service.PS], 1)
    testcase.assertGreaterEqual(counter[Service.CS], 1)
    testcase.assertEqual(counter[Service.ZK], 1)


def check_host_ports(testcase, host):
    """
    Check that no port on the given host is used twice.
    """
    ports_used = {}

    def _add_port(ip, port):
        _check_port(testcase, port)
        ip_port_counter = ports_used.setdefault(ip, Counter())
        ip_port_counter[port] += 1

    for interface in host.interfaces.iterator():
        _add_port(interface.get_public_ip(), interface.public_port)
        _add_port(interface.host.internal_ip, interface.internal_port)
        if interface.get_bind_ip():
            _add_port(interface.get_bind_ip(), interface.bind_port)

    for service in host.services.iterator():
        _add_port(service.host.internal_ip, service.port)

    clashes = []
    for ip, ip_port_counter in ports_used.items():
        for port, count in ip_port_counter.items():
            if count > 1:
                clashes.append(dict(ip=ip, port=port, count=count))

    testcase.assertEqual(clashes, [], "Ports clashing on host %s" % host)


_dont_care = object()
LinkDescription = namedtuple('LinkDescription', [
    'type',
    'from_as_id',
    'from_public_ip',
    'from_public_port',
    'from_bind_ip',
    'from_bind_port',
    'from_internal_ip',
    'from_internal_port',
    'to_as_id',
    'to_public_ip',
    'to_public_port',
    'to_bind_ip',
    'to_bind_port',
    'to_internal_ip',
    'to_internal_port',
])
# little hack: from future-3.7 import namedtuple(defaults=...)
LinkDescription.__new__.__defaults__ = (_dont_care,) * len(LinkDescription._fields)


def check_links(testcase, link_descriptions):
    """
    Check that the system contains exactly the links described.
    :param TestCase testcase: for assertions
    :param [LinkDescription] link_descriptions: the expected state of the links
    """
    for link in Link.objects.iterator():
        check_link(testcase, link)
    actual_link_descs = [_describe_link(testcase, l) for l in Link.objects.iterator()]
    testcase.assertEqual(sorted(actual_link_descs), sorted(link_descriptions))


def check_link(testcase, link, link_desc=None):
    """
    Check that link is in a sane state.
    If a LinkDescription is provided, check that the current state of the link corresponds to the
    expected state.
    :param TestCase testcase: for assertions
    :param Link link: link to be checked
    :param LinkDescription link_desc: optional, the expected state of the link
    """
    testcase.assertIsNotNone(link)
    testcase.assertIsNotNone(link.interfaceA)
    testcase.assertIsNotNone(link.interfaceB)
    testcase.assertEqual(link.interfaceA.AS, link.interfaceA.host.AS)
    testcase.assertEqual(link.interfaceB.AS, link.interfaceB.host.AS)
    _check_port(testcase, link.interfaceA.public_port)
    _check_port(testcase, link.interfaceA.internal_port)
    if link.interfaceA.get_bind_ip():
        _check_port(testcase, link.interfaceA.bind_port)
    else:
        testcase.assertIsNone(link.interfaceA.bind_port)    # No harm, but this seems cleaner
    _check_port(testcase, link.interfaceB.public_port)
    _check_port(testcase, link.interfaceB.internal_port)
    if link.interfaceB.get_bind_ip():
        _check_port(testcase, link.interfaceB.bind_port)
    else:
        testcase.assertIsNone(link.interfaceB.bind_port)    # ditto

    if link_desc:
        actual_link_desc = _describe_link(link)
        diff = _diff_link_description(link_desc, actual_link_desc)
        testcase.assertFalse(bool(diff), diff)


def _describe_link(link):
    """
    Helper for checks. Return the LinkDescription describing the current state of the link.
    """
    return LinkDescription(
        type=link.type,
        from_as_id=link.interfaceA.AS.as_id,
        from_public_ip=link.interfaceA.get_public_ip(),
        from_public_port=link.interfaceA.public_port,
        from_bind_ip=link.interfaceA.get_bind_ip(),
        from_bind_port=link.interfaceA.bind_port,
        from_internal_ip=link.interfaceA.host.internal_ip,
        from_internal_port=link.interfaceA.internal_port,
        to_as_id=link.interfaceB.AS.as_id,
        to_public_ip=link.interfaceB.get_public_ip(),
        to_public_port=link.interfaceB.public_port,
        to_bind_ip=link.interfaceB.get_bind_ip(),
        to_bind_port=link.interfaceB.bind_port,
        to_internal_ip=link.interfaceB.host.internal_ip,
        to_internal_port=link.interfaceB.internal_port,
    )


def _diff_link_description(link_desc, actual_link_desc):
    diff = OrderedDict()
    for field, expected in link_desc._asdict().items():
        actual = actual_link_desc._asdict()[field]
        if expected is not _dont_care and expected != actual:
            diff[field] = dict(expcted=expected, actual=actual)
    return diff


def _check_port(testcase, port):
    """
    Check that this looks like a valid port.
    """
    testcase.assertIsNotNone(port)
    testcase.assertTrue(1024 < port <= MAX_PORT, port)


def check_as_keys(testcase, as_):
    """
    Check that keys of AS `as_` have been properly initialised
    :param unittest.TestCase testcase: The testcase to call assert on
    :param scionlab.models.AS as_: The AS with the key-pairs to check
    """
    testcase.assertIsNotNone(as_)
    _check_sig_keypair(testcase, as_.sig_pub_key, as_.sig_priv_key)
    _check_enc_keypair(testcase, as_.enc_pub_key, as_.enc_priv_key)
    testcase.assertIsNotNone(as_.master_as_key)
    _sanity_check_base64(testcase, as_.master_as_key)


def check_as_core_keys(testcase, as_):
    """
    Check that core AS keys of AS `as_` have been properly initialised
    :param unittest.TestCase testcase: The testcase to call assert on
    :param scionlab.models.AS as_: The AS with the key-pairs to check
    """
    testcase.assertIsNotNone(as_)
    _check_sig_keypair(testcase, as_.core_sig_pub_key, as_.core_sig_priv_key)
    _check_sig_keypair(testcase, as_.core_online_pub_key, as_.core_online_priv_key)
    _check_sig_keypair(testcase, as_.core_offline_pub_key, as_.core_offline_priv_key)


def _check_sig_keypair(testcase, sig_pub_key_b64, sig_priv_key_b64):
    """
    Check that this signing keypair was correctly created
    """
    testcase.assertIsNotNone(sig_pub_key_b64)
    testcase.assertIsNotNone(sig_priv_key_b64)
    _sanity_check_base64(testcase, sig_pub_key_b64)
    _sanity_check_base64(testcase, sig_priv_key_b64)

    m = "message".encode()

    # Sign a message and verify
    sig_pub_key = base64.b64decode(sig_pub_key_b64.encode())
    sig_priv_key = base64.b64decode(sig_priv_key_b64.encode())
    s = lib.crypto.asymcrypto.sign(m, sig_priv_key)
    testcase.assertTrue(lib.crypto.asymcrypto.verify(m, s, sig_pub_key))


def _check_enc_keypair(testcase, enc_pub_key_b64, enc_priv_key_b64):
    """
    Check that this encryption keypair was correctly created
    """
    testcase.assertIsNotNone(enc_pub_key_b64)
    testcase.assertIsNotNone(enc_priv_key_b64)
    _sanity_check_base64(testcase, enc_pub_key_b64)
    _sanity_check_base64(testcase, enc_priv_key_b64)

    m = "message".encode()

    # Encode and decode a message for myself
    enc_pub_key = base64.b64decode(enc_pub_key_b64.encode())
    enc_priv_key = base64.b64decode(enc_priv_key_b64.encode())
    c = lib.crypto.asymcrypto.encrypt(m, enc_priv_key, enc_pub_key)
    d = lib.crypto.asymcrypto.decrypt(c, enc_priv_key, enc_pub_key)
    testcase.assertEqual(m, d)


def _sanity_check_base64(testcase, s):
    """
    Check that string s looks like base64 encoded data
    """
    base64_pattern = re.compile(
        r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"
    )
    testcase.assertTrue(base64_pattern.match(s))
