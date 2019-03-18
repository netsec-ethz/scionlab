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

import base64
import io
import os
import pathlib
import re
import tarfile
import lib.crypto.asymcrypto
from collections import namedtuple, Counter, OrderedDict
from scionlab.models import AS, Service, Interface, Link, UserAS, MAX_PORT


def check_topology(testcase):
    """
    Run all sanity checks for the current state of the models in the DB.
    """
    for as_ in AS.objects.iterator():
        check_as(testcase, as_)
    for link in Link.objects.iterator():
        check_link(testcase, link)
    check_no_dangling_interfaces(testcase)


def check_as(testcase, as_):
    # TODO: generalize (topo checks)
    for interface in as_.interfaces.iterator():
        link = interface.link()
        if link.type == Link.PROVIDER and link.interfaceB == interface:
            parent_as = link.interfaceA.AS
            testcase.assertEqual(parent_as.isd, as_.isd)

    check_as_services(testcase, as_)
    check_as_keys(testcase, as_)
    if as_.is_core:
        check_as_core_keys(testcase, as_)

    testcase.assertIsNotNone(as_.certificate_chain)
    if as_.is_core:
        testcase.assertIsNotNone(as_.core_certificate)

    for host in as_.hosts.iterator():
        check_host_ports(testcase, host)


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

    for router in host.border_routers.iterator():
        _add_port(router.host.internal_ip, router.internal_port)
        _add_port(router.host.internal_ip, router.control_port)
        for interface in router.interfaces.iterator():
            _add_port(interface.get_public_ip(), interface.public_port)
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
    'from_control_port',
    'to_as_id',
    'to_public_ip',
    'to_public_port',
    'to_bind_ip',
    'to_bind_port',
    'to_internal_ip',
    'to_internal_port',
    'to_control_port',
])
# little hack: the `defaults` parameter for namedtuple will only be introduced in python-3.7.
# As a simple workaround we manually provide the desired default value (_dont_care) for all
# positional arguments by overwriting the magic __defaults__ field of the constructor function.
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
    _check_port(testcase, link.interfaceA.border_router.internal_port)
    _check_port(testcase, link.interfaceA.border_router.control_port)
    if link.interfaceA.get_bind_ip():
        _check_port(testcase, link.interfaceA.bind_port)
    else:
        testcase.assertIsNone(link.interfaceA.bind_port)    # No harm, but this seems cleaner
    _check_port(testcase, link.interfaceB.public_port)
    _check_port(testcase, link.interfaceB.border_router.internal_port)
    _check_port(testcase, link.interfaceB.border_router.control_port)
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
        from_internal_port=link.interfaceA.border_router.internal_port,
        from_control_port=link.interfaceA.border_router.control_port,
        to_as_id=link.interfaceB.AS.as_id,
        to_public_ip=link.interfaceB.get_public_ip(),
        to_public_port=link.interfaceB.public_port,
        to_bind_ip=link.interfaceB.get_bind_ip(),
        to_bind_port=link.interfaceB.bind_port,
        to_internal_ip=link.interfaceB.host.internal_ip,
        to_internal_port=link.interfaceB.border_router.internal_port,
        to_control_port=link.interfaceB.border_router.control_port,
    )


def _diff_link_description(link_desc, actual_link_desc):
    diff = OrderedDict()
    for field, expected in link_desc._asdict().items():
        actual = actual_link_desc._asdict()[field]
        if expected is not _dont_care and expected != actual:
            diff[field] = dict(expected=expected, actual=actual)
    return diff


def _check_port(testcase, port):
    """
    Check that this looks like a valid port.
    """
    testcase.assertIsNotNone(port)
    testcase.assertTrue(1024 < port <= MAX_PORT, port)


def check_no_dangling_interfaces(testcase):
    testcase.assertFalse(
        Interface.objects.filter(
            link_as_interfaceA=None,
            link_as_interfaceB=None
        ).exists())


def check_as_keys(testcase, as_):
    """
    Check that keys of AS `as_` have been properly initialised
    :param unittest.TestCase testcase: The testcase to call assert on
    :param scionlab.models.AS as_: The AS with the key-pairs to check
    """
    testcase.assertIsNotNone(as_)
    check_sig_keypair(testcase, as_.sig_pub_key, as_.sig_priv_key)
    check_enc_keypair(testcase, as_.enc_pub_key, as_.enc_priv_key)
    testcase.assertIsNotNone(as_.master_as_key)
    _sanity_check_base64(testcase, as_.master_as_key)


def check_as_core_keys(testcase, as_):
    """
    Check that core AS keys of AS `as_` have been properly initialised
    :param unittest.TestCase testcase: The testcase to call assert on
    :param scionlab.models.AS as_: The AS with the key-pairs to check
    """
    testcase.assertIsNotNone(as_)
    check_sig_keypair(testcase, as_.core_sig_pub_key, as_.core_sig_priv_key)
    check_sig_keypair(testcase, as_.core_online_pub_key, as_.core_online_priv_key)
    check_sig_keypair(testcase, as_.core_offline_pub_key, as_.core_offline_priv_key)


def check_sig_keypair(testcase, sig_pub_key_b64, sig_priv_key_b64):
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


def check_enc_keypair(testcase, enc_pub_key_b64, enc_priv_key_b64):
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


def check_tarball_user_as(testcase, response, user_as):
    """
    Check the http-response for downloading a UserAS-config tar-ball.
    """
    tar = _check_open_tarball(testcase, response)
    files = ['README.md']
    if user_as.installation_type == UserAS.VM:
        files += ["Vagrantfile", "scion-viz.service", "scion.service", "scionupgrade.service",
                  "scionupgrade.timer", "run.sh", "scionupgrade.sh"]
    testcase.assertTrue(sorted(['gen'] + files), _tar_ls(tar, ''))
    _check_tarball_gen(testcase, tar, user_as.hosts.get())

    if user_as.installation_type == UserAS.VM:
        # appropriate README?
        readme = tar.extractfile('README.md').read().decode()
        testcase.assertTrue(readme.startswith('# SCIONLabVM'))

        # Vagrantfile template expanded correctly?
        vagrantfile = tar.extractfile('Vagrantfile')
        lines = [l.decode() for l in vagrantfile]
        name_lines = [l.strip() for l in lines if l.strip().startswith('vb.name')]
        testcase.assertEqual(name_lines, ['vb.name = "SCIONLabVM-%s"' % user_as.as_id])
    else:
        readme = tar.extractfile('README.md').read().decode()
        testcase.assertTrue(readme.startswith('# SCIONLab Dedicated'))


def check_tarball_host(testcase, response, host):
    """
    Check the http-response for downloading a host-config tar-ball.
    """
    tar = _check_open_tarball(testcase, response)
    testcase.assertTrue(['gen'], _tar_ls(tar, ''))
    _check_tarball_gen(testcase, tar, host)


def _check_open_tarball(testcase, response):
    """
    Check http-response headers and open tar ball from content.
    """
    testcase.assertTrue(re.search(r'attachment;\s*filename="[^"]*.tar.gz"',
                                  response['Content-Disposition']))
    testcase.assertEqual(response['Content-Type'], 'application/gzip')
    testcase.assertEqual(int(response['Content-Length']), len(response.content))

    tar = tarfile.open(mode='r:gz', fileobj=io.BytesIO(response.content))
    return tar


def _check_tarball_gen(testcase, tar, host):
    """
    Basic sanity checks for the gen/ folder contained in the tar.
    """
    isd_str = 'ISD%i' % host.AS.isd.isd_id
    as_str = 'AS%s' % host.AS.as_path_str()

    testcase.assertEqual([isd_str, 'dispatcher', 'scionlab-config.json'], _tar_ls(tar, 'gen'))
    testcase.assertEqual([as_str], _tar_ls(tar, os.path.join('gen', isd_str)))

    as_gen_dir = os.path.join('gen', isd_str, as_str)
    topofiles = [f for f in tar.getnames() if
                 pathlib.PurePath(f).match(as_gen_dir + "/*/topology.json")]
    testcase.assertTrue(topofiles)


def _tar_ls(tar, path):
    """
    Helper function: "ls" the given path in the tar, i.e. list files/subdirectories
    contained in the given path.
    :param str path: the subdirectory which should be listed. Empty refers to the root of the tar.
    :returns: sorted list of file-names/subdirectory-names
    """
    # Note: intermediate dirs are only included in `getnames` when they explicitly are a member of
    # the tar -- depending on how the tar was created, this may or may not be the case.
    filenames = tar.getnames()
    re_path = re.compile(re.escape(os.path.join(path, '')) + r'([^/]+)')
    s = set()
    for f in filenames:
        m = re_path.match(f)
        if m:
            s.add(m.group(1))
    return list(sorted(s))
