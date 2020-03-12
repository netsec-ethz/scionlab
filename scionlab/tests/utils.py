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

import logging

from collections import namedtuple, Counter, OrderedDict
from scionlab.defines import MAX_PORT
from scionlab.models.core import ISD, AS, Service, Interface, Link
from scionlab.models.pki import Key, Certificate, TRC
from scionlab.models.user_as import UserAS

from scionlab.scion import keys, jws


def check_topology(testcase):
    """
    Run all sanity checks for the current state of the models in the DB.
    """
    for isd in ISD.objects.iterator():
        check_trc(testcase, isd)
    for as_ in AS.objects.iterator():
        check_as(testcase, as_)
    for link in Link.objects.iterator():
        check_link(testcase, link)
    check_interfaces(testcase)


def check_as(testcase, as_):
    # TODO: generalize (topo checks)
    for interface in as_.interfaces.iterator():
        link = interface.link()
        # Check if the link is active, otherwise the ISD can be different
        if link.type == Link.PROVIDER and link.interfaceB == interface and link.active:
            parent_as = link.interfaceA.AS
            testcase.assertEqual(parent_as.isd, as_.isd)

    check_as_services(testcase, as_)
    check_as_keys(testcase, as_)
    check_cert_chains(testcase, as_)
    if as_.is_core:
        check_as_core_keys(testcase, as_)
        check_issuer_certs(testcase, as_)

    for host in as_.hosts.iterator():
        check_host_ports(testcase, host)


def check_as_services(testcase, as_):
    """
    Check that all the AS has all required services configured.
    """
    counter = Counter(service.type for service in as_.services.iterator())
    testcase.assertEqual(counter[Service.CS], 1)


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
        for interface in filter(lambda iface: iface.link().active, router.interfaces.iterator()):
            _add_port(interface.get_public_ip(), interface.public_port)
            if interface.get_bind_ip():
                _add_port(interface.get_bind_ip(), interface.bind_port)

    for service in host.services.iterator():
        _add_port(service.host.internal_ip, service.port())

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


def check_interfaces(testcase):
    # Check that each interface is referenced by exactly one link
    links = Link.objects.iterator()
    ifacesA, ifacesB = zip(*((link.interfaceA_id, link.interfaceB_id) for link in links))
    counter = Counter(ifacesA + ifacesB)
    testcase.assertTrue(all(counter[iface.pk] == 1 for iface in Interface.objects.iterator()))


def check_as_keys(testcase, as_):
    """
    Check that keys of AS `as_` have been properly initialised
    :param unittest.TestCase testcase: The testcase to call assert on
    :param scionlab.models.AS as_: The AS with the key-pairs to check
    """
    testcase.assertIsNotNone(as_)

    _check_keys_for_usage(testcase, as_, Key.SIGNING)
    _check_keys_for_usage(testcase, as_, Key.DECRYPT)

    testcase.assertIsNotNone(as_.master_as_key)
    _sanity_check_base64(testcase, as_.master_as_key)


def check_as_core_keys(testcase, as_):
    """
    Check that core AS keys of AS `as_` have been properly initialised
    :param unittest.TestCase testcase: The testcase to call assert on
    :param scionlab.models.AS as_: The AS with the key-pairs to check
    """
    testcase.assertIsNotNone(as_)
    _check_keys_for_usage(testcase, as_, Key.CERT_SIGNING)
    _check_keys_for_usage(testcase, as_, Key.TRC_ISSUING_GRANT)
    _check_keys_for_usage(testcase, as_, Key.TRC_VOTING_ONLINE)
    _check_keys_for_usage(testcase, as_, Key.TRC_VOTING_OFFLINE)


def _check_keys_for_usage(testcase, as_, key_usage):
    """
    Helper: check that key exists and versions are numbered 1...N
    """
    ks = as_.keys.filter(usage=key_usage).order_by('version')
    testcase.assertGreaterEqual(len(ks), 1)
    for i, key in enumerate(ks):
        testcase.assertEqual(key.version, i+1)
        testcase.assertGreater(len(key.key), 0)
        testcase.assertIsNotNone(keys.Base64StringEncoder.decode(key.key))


def _sanity_check_base64(testcase, s):
    """
    Check that string s looks like base64 encoded data
    """
    base64_pattern = re.compile(
        r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"
    )
    testcase.assertTrue(base64_pattern.match(s))


def check_trc_and_certs(testcase, isd_id, expected_core_ases=None, expected_version=None):
    """
    Check the ISD's TRC and return it as a TRC object.
    Check that the current TRC can be verified with `prev_trc`.
    Check the certificates for all ASes in the ISD.

    :param int isd_id:
    :param [str] expected_core_ases: ISD-AS strings for all core ases
    :param int expected_version: optional, expected version for current TRC.
    """
    isd = ISD.objects.get(isd_id=isd_id)
    check_trc(testcase, isd, expected_core_ases, expected_version)
    for as_ in isd.ases.iterator():
        check_cert_chain(testcase, as_.certificates.latest(Certificate.CHAIN))
        if as_.is_core:
            check_issuer_cert(testcase, as_.certificates.latest(Certificate.ISSUER),
                              expected_trc_version=expected_version)


def check_trc(testcase, isd, expected_core_ases=None, expected_version=None):
    """
    Check the ISD's latest TRC
    :param ISD isd:
    :param [str] expected_core_ases: optional, ISD-AS strings for all core ases
    :param int expected_version: optional, expected version for current TRC.
    """
    if expected_core_ases is None:
        expected_core_ases = set(as_.as_id for as_ in isd.ases.filter(is_core=True))

    trc = isd.trcs.latest_or_none()
    if len(expected_core_ases) > 0:
        testcase.assertIsNotNone(trc)
    if expected_version is not None:
        testcase.assertEqual(trc.version, expected_version)
    if trc is None:
        return

    trc_pld = jws.decode_payload(trc.trc)
    testcase.assertEqual(trc_pld['trc_version'], trc.version)
    testcase.assertEqual(set(trc_pld['primary_ases'].keys()), set(expected_core_ases))

    if trc.version > 1:
        # Check that TRC update is valid
        prev_trc = isd.trcs.get(version=trc.version-1)
        prev_trc_pld = jws.decode_payload(prev_trc.trc)
        # Minimal check:
        voters = set(trc_pld['votes'].keys())
        allowed_voters = set(prev_trc_pld['primary_ases'].keys())
        testcase.assertTrue(voters.issubset(allowed_voters))
        testcase.assertGreaterEqual(len(trc_pld['votes']), prev_trc_pld['voting_quorum'])
        # TODO(matzf): how to verify votes & signatures without re-implementing the logic?
        # Would be nice to use `scion-pki trcs verify` for this. But how?


def check_core_as_certs(testcase, isd):
    """
    Check all certificates for the core ASes.
    """


def check_noncore_as_certs(testcase, isd):
    """
    Check all certificates for the non-core ASes.
    """
    for as_ in isd.ases.filter(is_core=False).iterator():
        check_cert_chains(testcase, as_)


def check_issuer_certs(testcase, as_):
    """
    Check that the AS's issuer certificates can be verified with a TRC.
    Check that the latest issuer certificate was issued by the latest TRC version.
    """
    issuer_certs = as_.certificates.filter(type=Certificate.ISSUER).order_by('version')
    testcase.assertGreaterEqual(len(issuer_certs), 1)
    for i, issuer_cert in enumerate(issuer_certs):
        testcase.assertEqual(issuer_cert.version, i+1)
        if i < len(issuer_certs)-1:
            check_issuer_cert(testcase, issuer_cert)
        else:
            expected_trc_version = as_.isd.trcs.latest().version
            check_issuer_cert(testcase, issuer_cert, expected_trc_version)


def check_issuer_cert(testcase, issuer_cert, expected_trc_version=None):
    """
    Check that the issuer certificate can be verified with a TRC.
    Check that the certificate is issued by the expected_trc_version, if set.
    """
    testcase.assertIsNotNone(issuer_cert)

    cert = issuer_cert.certificate
    cert_pld = jws.decode_payload(cert)

    testcase.assertEqual(cert_pld["version"], issuer_cert.version)
    testcase.assertEqual(cert_pld["subject"], issuer_cert.AS.isd_as_str())

    subject_ia = cert_pld["subject"]
    subject_as = subject_ia.split('-')[1]
    trc_version = cert_pld["issuer"]["trc_version"]
    if expected_trc_version is not None:
        testcase.assertEqual(trc_version, expected_trc_version)

    trc = TRC.objects.get(isd=issuer_cert.AS.isd, version=trc_version)
    trc_pld = jws.decode_payload(trc.trc)
    issuing_grant_pub_key = trc_pld["primary_ases"][subject_as]["keys"]["issuing_grant"]["key"]
    sig_valid = jws.verify(cert["payload"], cert["protected"], cert["signature"],
                           issuing_grant_pub_key)

    testcase.assertTrue(sig_valid)


def check_cert_chains(testcase, as_):
    """
    Check that the AS has an AS certificate (-chain) and that all existing certificate chains
    can be verified with the issuer certificate.
    """
    cert_chains = as_.certificates.filter(type=Certificate.CHAIN).order_by('version')
    testcase.assertGreaterEqual(len(cert_chains), 1)
    first_version = cert_chains[0].version
    testcase.assertGreaterEqual(first_version, 1)  # Sequence starts at >1 when AS changed ISD
    for i, cert_chain in enumerate(cert_chains):
        testcase.assertEqual(cert_chain.version, first_version + i)
        check_cert_chain(testcase, cert_chain)


def check_cert_chain(testcase, cert_chain):
    """
    Check that the AS's certificate chain can be verified with the issuer certificate.
    """
    testcase.assertIsNotNone(cert_chain)

    leaf = cert_chain.certificate[1]
    leaf_pld = jws.decode_payload(leaf)

    testcase.assertEqual(leaf_pld["version"], cert_chain.version)
    testcase.assertEqual(leaf_pld["subject"], cert_chain.AS.isd_as_str())

    issuer = leaf_pld["issuer"]
    issuer_ia = issuer["isd_as"]
    issuer_as = issuer_ia.split('-')[1]
    issuer_ver = issuer["certificate_version"]

    # Check that the issuer certificate in the chain is identical to the issuer cert in the DB:
    issuer_cert = Certificate.objects.get(type=Certificate.ISSUER,
                                          AS__as_id=issuer_as,
                                          version=issuer_ver)
    testcase.assertEqual(issuer_cert.certificate, cert_chain.certificate[0])

    # Verify the signature
    issuer_pld = jws.decode_payload(issuer_cert.certificate)
    issuer_pub_key = issuer_pld["keys"]["issuing"]["key"]
    sig_valid = jws.verify(leaf["payload"], leaf["protected"], leaf["signature"], issuer_pub_key)
    testcase.assertTrue(sig_valid)

    # Note: not checking issuer cert, assume that we check that separately.


def check_tarball_user_as(testcase, response, user_as):
    """
    Check the http-response for downloading a UserAS-config tar-ball.
    Return the tar for further inspection.
    """
    tar = _check_open_tarball(testcase, response)

    if user_as.installation_type == UserAS.VM:
        testcase.assertEquals(sorted(['README.md', 'Vagrantfile']),
                              tar_ls(tar, ''))
        # appropriate README?
        readme = tar.extractfile('README.md').read().decode()
        testcase.assertTrue(readme.startswith('# SCIONLab VM'))
        # Vagrantfile template expanded correctly?
        vagrantfile = tar.extractfile('Vagrantfile')
        lines = [l.decode() for l in vagrantfile]
        name_lines = [l.strip() for l in lines if l.strip().startswith('vb.name')]
        testcase.assertEqual(name_lines, ['vb.name = "SCIONLabVM-%s"' % user_as.as_path_str()])
    else:
        testcase.assertEquals(sorted(['README.md', 'gen']),
                              tar_ls(tar, ''))
        # check the full content of gen/
        _check_tarball_gen(testcase, tar, user_as.hosts.get())
        readme = tar.extractfile('README.md').read().decode()
        testcase.assertTrue(readme.startswith('# SCIONLab Dedicated'))
    return tar


def check_tarball_host(testcase, response, host):
    """
    Check the http-response for downloading a host-config tar-ball.
    Return the tar for further inspection.
    """
    tar = _check_open_tarball(testcase, response)

    top_dir = tar_ls(tar, '')
    testcase.assertTrue('gen' in top_dir)
    _check_tarball_gen(testcase, tar, host)

    testcase.assertTrue('scionlab-services.txt' in top_dir)
    _check_tarball_services(testcase, tar, host)
    return tar


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

    testcase.assertEqual([isd_str, 'dispatcher', 'scionlab-config.json'], tar_ls(tar, 'gen'))
    testcase.assertEqual([as_str, 'trcs'], tar_ls(tar, os.path.join('gen', isd_str)))

    as_gen_dir = os.path.join('gen', isd_str, as_str)
    topofiles = [f for f in tar.getnames() if
                 pathlib.PurePath(f).match(as_gen_dir + "/*/topology.json")]
    testcase.assertTrue(topofiles)


def _check_tarball_services(testcase, tar, host):
    services = tar_cat(tar, 'scionlab-services.txt').decode().split('\n')

    br = ["scion-border-router@%s.service" % str(br).replace('br-', '')
          for br in host.border_routers.all()]
    cs = ["scion-control-service@%s.service" % str(s).replace('cs-', '')
          for s in host.services.filter(type=Service.CS)]
    bw = ["scion-bwtestserver.service"
          for _ in host.services.filter(type=Service.BW)]

    expected_services = br + cs + bw + [
        "scion-daemon@%s.service" % host.AS.isd_as_path_str(),
        "scion-dispatcher.service",
    ]

    testcase.assertEqual(sorted(services), sorted(expected_services))


def tar_ls(tar, path):
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


def tar_cat(tar, path):
    """
    Reads file and returns content as bytes
    """
    mem = tar.getmember(path)
    with tar.extractfile(mem) as f:
        return f.read()


def basic_auth(username, password):
    uname_pwd = '%s:%s' % (username, password)
    uname_pwd_encoded = base64.b64encode(uname_pwd.encode('utf-8')).decode('ascii')
    return {"HTTP_AUTHORIZATION": "Basic %s" % uname_pwd_encoded}


def subprocess_call_log(*popenargs, timeout=None, **kwargs):
    logging.info("Command: %s; shell args: %s" % (" ".join(*popenargs), str(kwargs)))
