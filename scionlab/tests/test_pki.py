# Copyright 2020 ETH Zurich
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

from datetime import datetime
from django.test import TestCase

from scionlab.models.core import ISD, AS
from scionlab.models.pki import Key, Certificate
from scionlab.models.trc import TRC
from scionlab.defines import (
    DEFAULT_EXPIRATION_AS_KEYS,
)
from scionlab.scion import as_ids


class KeyTests(TestCase):

    def setUp(self):
        self.isd = ISD.objects.create(isd_id=1, label='Test')
        self.AS = _create_AS(self.isd, 'ff00:0:110')

    def test_generate_regular_as_key(self):
        k = Key.objects.create(AS=self.AS, usage=Key.CP_AS)
        self.assertIsNotNone(k)
        self.assertEqual(k.AS_id, self.AS.pk)
        self.assertEqual(k.version, 1)
        self.assertEqual(k.usage, Key.CP_AS)
        self.assertEqual(k.not_after - k.not_before, DEFAULT_EXPIRATION_AS_KEYS)

    def test_create_core_keys(self):
        self.assertEqual(Key.objects.count(), 0)
        keys = Key.objects.create_core_keys(self.AS)
        self.assertEqual(Key.objects.count(), 4)
        self.assertEqual([*Key.objects.all()], keys)
        expected = {Key.TRC_VOTING_SENSITIVE,
                    Key.TRC_VOTING_REGULAR,
                    Key.ISSUING_ROOT,
                    Key.ISSUING_CA}
        self.assertEqual({k.usage for k in keys}, expected)

    def test_latest(self):
        for as_ in [self.AS,
                    _create_AS(self.isd, 'ff00:0:111'),
                    _create_AS(self.isd, 'ff00:0:112')]:
            Key.objects.create(AS=as_, usage=Key.CP_AS)
        self.assertEqual(Key.objects.exclude(version=1).count(), 0)
        k = Key.objects.create(AS=self.AS, usage=Key.CP_AS)
        self.assertEqual(Key.objects.exclude(version=1).get(), k)

    def test_key_format(self):
        k = Key.objects.create(AS=self.AS, usage=Key.CP_AS)
        first_line = k.key.splitlines()[0]
        self.assertEqual(first_line, '-----BEGIN PRIVATE KEY-----')

    def test_delete_as(self):
        # sensitive, regular, root, and ca keys and certificates:
        Key.objects.create_core_keys(self.AS)
        Certificate.objects.create_core_certs(self.AS)
        # just the cp as key and certificate:
        Key.objects.create(self.AS, Key.CP_AS)
        Certificate.objects.create_cp_as_cert(self.AS, issuer=self.AS)

        k_as = Key.objects.get(usage=Key.CP_AS)
        k_ca = Key.objects.get(usage=Key.ISSUING_CA)
        k_root = Key.objects.get(usage=Key.ISSUING_ROOT)
        k_regular = Key.objects.get(usage=Key.TRC_VOTING_REGULAR)
        k_sensitive = Key.objects.get(usage=Key.TRC_VOTING_SENSITIVE)

        AS2 = _create_AS(self.isd, 'ff00:0:111', is_core=True)
        Key.objects.create_core_keys(AS2)
        Certificate.objects.create_core_certs(AS2)

        trc = _create_TRC(self.isd, 1, 1)
        trc.add_core_as(self.AS)
        self.AS.delete()

        self.assertFalse(Key.objects.filter(pk=k_as.pk).exists())    # Delete should cascade here,
        self.assertFalse(Key.objects.filter(pk=k_ca.pk).exists())    # ... and here too.
        self.assertFalse(Key.objects.filter(pk=k_root.pk).exists())  # ... and here too.
        self.assertFalse(Key.objects.filter(pk=k_regular.pk).exists())   # ... and here too.
        self.assertTrue(Key.objects.filter(pk=k_sensitive.pk).exists())  # Should still exist!
        self.assertFalse(AS.objects.filter(pk=self.AS.pk).exists())      # the AS was removed.

        # the keys and certs for the other AS are removed
        old_certs = Certificate.objects.filter(key__AS=AS2).values_list('pk', flat=True)
        AS2.delete()
        self.assertFalse(Certificate.objects.filter(pk__in=old_certs).exists())
        self.assertEqual(Certificate.objects.count(), 1)
        self.assertEqual(Key.objects.count(), 1)


class CertificateTests(TestCase):
    def setUp(self):
        self.isd = ISD.objects.create(isd_id=1, label='Test')
        self.AS = _create_AS(self.isd, 'ff00:0:110', is_core=True)

    def test_latest(self):
        Key.objects.create_all_keys(self.AS)
        Certificate.objects.create_all_certs(self.AS)
        root = Certificate.objects.get(key__usage=Key.ISSUING_ROOT)
        latest = Certificate.objects.latest(usage=Key.ISSUING_ROOT)  # without AS
        self.assertEqual(latest, root)
        # create another AS
        as2 = _create_AS(self.isd, 'ff00:0:111', is_core=True)
        Key.objects.create(AS=as2, usage=Key.ISSUING_ROOT)
        root2 = Certificate.objects.create_issuer_root_cert(subject=as2)
        latest = Certificate.objects.latest(usage=Key.ISSUING_ROOT, AS=as2)
        self.assertEqual(latest, root2)
        root3 = Certificate.objects.create_issuer_root_cert(subject=as2)
        latest = Certificate.objects.latest(usage=Key.ISSUING_ROOT, AS=as2)
        self.assertEqual(latest, root3)
        # manager on the keys
        latest = as2.keys.latest(Key.ISSUING_ROOT).certificates.latest(Key.ISSUING_ROOT)
        self.assertEqual(latest, root3)
        # query the first AS again
        latest = Certificate.objects.latest(usage=Key.ISSUING_ROOT, AS=self.AS)
        self.assertEqual(latest, root)

    def test_create_voting_sensitive_cert(self):
        k = Key.objects.create(AS=self.AS, usage=Key.TRC_VOTING_SENSITIVE,
                               not_before=datetime.fromtimestamp(10),
                               not_after=datetime.fromtimestamp(12))
        cert = Certificate.objects.create_voting_sensitive_cert(
            subject=self.AS,
            not_before=datetime.fromtimestamp(11),
            not_after=datetime.fromtimestamp(13))
        self.assertEqual(cert.key, k)
        self.assertEqual(cert.ca_cert, cert)  # self signed
        self.assertEqual(cert.not_before, datetime.fromtimestamp(11))  # valid intersection
        self.assertEqual(cert.not_after, datetime.fromtimestamp(12))

    def test_create_voting_regular_cert(self):
        k = Key.objects.create(AS=self.AS, usage=Key.TRC_VOTING_REGULAR,
                               not_before=datetime.fromtimestamp(10),
                               not_after=datetime.fromtimestamp(12))
        cert = Certificate.objects.create_voting_regular_cert(
            subject=self.AS,
            not_before=datetime.fromtimestamp(11),
            not_after=datetime.fromtimestamp(13))
        self.assertEqual(cert.key, k)
        self.assertEqual(cert.ca_cert, cert)  # self signed
        self.assertEqual(cert.not_before, datetime.fromtimestamp(11))  # valid intersection
        self.assertEqual(cert.not_after, datetime.fromtimestamp(12))

    def test_create_issuer_root_cert(self):
        k = Key.objects.create(AS=self.AS, usage=Key.ISSUING_ROOT,
                               not_before=datetime.fromtimestamp(10),
                               not_after=datetime.fromtimestamp(12))
        cert = Certificate.objects.create_issuer_root_cert(
            subject=self.AS,
            not_before=datetime.fromtimestamp(11),
            not_after=datetime.fromtimestamp(13))
        self.assertEqual(cert.key, k)
        self.assertEqual(cert.ca_cert, cert)  # self signed
        self.assertEqual(cert.not_before, datetime.fromtimestamp(11))  # valid intersection
        self.assertEqual(cert.not_after, datetime.fromtimestamp(12))

    def test_create_issuer_ca_cert(self):
        Key.objects.create(
            AS=self.AS, usage=Key.ISSUING_ROOT,
            not_before=datetime.fromtimestamp(10),
            not_after=datetime.fromtimestamp(12))
        self.assertRaises(Key.DoesNotExist,  # no CA key
                          Certificate.objects.create_issuer_ca_cert,
                          subject=self.AS,
                          not_before=datetime.fromtimestamp(11),
                          not_after=datetime.fromtimestamp(16))
        key_ca = Key.objects.create(
            AS=self.AS,
            usage=Key.ISSUING_CA,
            not_before=datetime.fromtimestamp(11),
            not_after=datetime.fromtimestamp(16))
        self.assertRaises(Certificate.DoesNotExist,  # no ROOT certificate
                          Certificate.objects.create_issuer_ca_cert,
                          subject=self.AS,
                          not_before=datetime.fromtimestamp(11),
                          not_after=datetime.fromtimestamp(16))
        cert_root = Certificate.objects.create_issuer_root_cert(
            subject=self.AS,
            not_before=datetime.fromtimestamp(10),
            not_after=datetime.fromtimestamp(12))
        cert_ca = Certificate.objects.create_issuer_ca_cert(
            subject=self.AS,
            not_before=datetime.fromtimestamp(11),
            not_after=datetime.fromtimestamp(16))
        self.assertEqual(cert_ca.ca_cert, cert_root)
        self.assertEqual(cert_ca.key, key_ca)
        self.assertEqual(cert_ca.not_before, datetime.fromtimestamp(11))
        self.assertEqual(cert_ca.not_after, datetime.fromtimestamp(12))

    def test_create_cp_as_cert(self):
        Key.objects.create(
            AS=self.AS, usage=Key.ISSUING_ROOT,
            not_before=datetime.fromtimestamp(10),
            not_after=datetime.fromtimestamp(12))
        Certificate.objects.create_issuer_root_cert(
            subject=self.AS,
            not_before=datetime.fromtimestamp(10),
            not_after=datetime.fromtimestamp(12))

        subject_key = Key.objects.create(
            AS=self.AS,
            usage=Key.CP_AS,
            not_before=datetime.fromtimestamp(11),
            not_after=datetime.fromtimestamp(12))
        self.assertRaises(Key.DoesNotExist,  # no CA key
                          Certificate.objects.create_cp_as_cert,
                          self.AS, self.AS, datetime.fromtimestamp(11), datetime.fromtimestamp(12))
        Key.objects.create(
            AS=self.AS, usage=Key.ISSUING_CA,
            not_before=datetime.fromtimestamp(10),
            not_after=datetime.fromtimestamp(12))
        self.assertRaises(Certificate.DoesNotExist,  # no CA cert
                          Certificate.objects.create_cp_as_cert,
                          self.AS, self.AS, datetime.fromtimestamp(11), datetime.fromtimestamp(12))

        cert_ca = Certificate.objects.create_issuer_ca_cert(
            subject=self.AS,
            not_before=datetime.fromtimestamp(10),
            not_after=datetime.fromtimestamp(12))
        cert = Certificate.objects.create_cp_as_cert(
            subject=self.AS,
            issuer=self.AS,
            not_before=datetime.fromtimestamp(11),
            not_after=datetime.fromtimestamp(12))
        self.assertEqual(cert.key, subject_key)
        self.assertEqual(cert.ca_cert, cert_ca)
        self.assertEqual(Certificate.objects.get(pk=cert.pk).ca_cert, cert_ca)

    def test_cp_as_certificate_another_issuer(self):
        Key.objects.create(
            AS=self.AS, usage=Key.ISSUING_ROOT,
            not_before=datetime.fromtimestamp(10),
            not_after=datetime.fromtimestamp(12))
        Certificate.objects.create_issuer_root_cert(
            subject=self.AS,
            not_before=datetime.fromtimestamp(10),
            not_after=datetime.fromtimestamp(12))
        Key.objects.create(
            AS=self.AS, usage=Key.ISSUING_CA,
            not_before=datetime.fromtimestamp(10),
            not_after=datetime.fromtimestamp(12))
        cert_ca = Certificate.objects.create_issuer_ca_cert(
            subject=self.AS,
            not_before=datetime.fromtimestamp(10),
            not_after=datetime.fromtimestamp(12))
        subject = _create_AS(self.isd, 'ff00:0:111')
        subject_key = Key.objects.create(
            AS=subject,
            usage=Key.CP_AS,
            not_before=datetime.fromtimestamp(11),
            not_after=datetime.fromtimestamp(12))
        cert = Certificate.objects.create_cp_as_cert(
            subject=subject,
            issuer=self.AS,
            not_before=datetime.fromtimestamp(11),
            not_after=datetime.fromtimestamp(12))
        self.assertEqual(cert.key, subject_key)
        self.assertEqual(cert.ca_cert, cert_ca)

    def test_create_core_certs(self):
        self.assertEqual(Certificate.objects.count(), 0)
        Key.objects.create_core_keys(self.AS)
        Certificate.objects.create_core_certs(self.AS)
        self.assertEqual(Certificate.objects.count(), 4)

    def test_create_all_certs(self):
        self.assertEqual(Certificate.objects.count(), 0)
        self.assertTrue(self.AS.is_core)
        Key.objects.create_all_keys(self.AS)
        self.assertEqual(Key.objects.count(), 5)
        Certificate.objects.create_all_certs(self.AS)
        self.assertEqual(Certificate.objects.count(), 5)

    def test_certificate_format(self):
        Key.objects.create(AS=self.AS, usage=Key.ISSUING_ROOT)
        cert = Certificate.objects.create_issuer_root_cert(
            subject=self.AS,
            not_before=datetime.utcnow(),
            not_after=datetime.utcnow())
        self.assertEqual(cert.certificate.splitlines()[0], '-----BEGIN CERTIFICATE-----')  # PEM
        self.assertEqual(cert.certificate.count('-----BEGIN CERTIFICATE-----'), 1)
        # AS certificates should contain a chain, with the subject certificate first,
        # and the CA second. The rest is only one certificate.
        Key.objects.create(self.AS, Key.ISSUING_CA)
        cert_ca = Certificate.objects.create_issuer_ca_cert(
            self.AS, datetime.utcnow(), datetime.utcnow())
        self.assertEqual(cert_ca.certificate.count('-----BEGIN CERTIFICATE-----'), 1)
        Key.objects.create(self.AS, Key.CP_AS)
        cert = Certificate.objects.create_cp_as_cert(
            self.AS, self.AS, datetime.utcnow(), datetime.utcnow())
        output = cert.format_certfile()
        self.assertEqual(output.count('-----BEGIN CERTIFICATE-----'), 2)  # own cert and issuer
        index = output.find('-----BEGIN CERTIFICATE-----', 1)
        self.assertEqual(output[0:index], cert.certificate)  # own certificate
        self.assertEqual(output[index:], cert_ca.certificate)  # issuer

    def test_delete_key_cascades(self):
        k = Key.objects.create(AS=self.AS, usage=Key.ISSUING_ROOT)
        Certificate.objects.create_issuer_root_cert(
            subject=self.AS,
            not_before=datetime.utcnow(),
            not_after=datetime.utcnow())
        self.assertEqual(Key.objects.count(), 1)
        self.assertEqual(Certificate.objects.count(), 1)
        k.delete()
        self.assertEqual(Key.objects.count(), 0)
        self.assertEqual(Certificate.objects.count(), 0)


def _create_AS(isd, as_id, is_core=False):
    # bypass ASManager.create to avoid initializing keys
    as_ = AS(isd=isd, as_id=as_id, as_id_int=as_ids.parse(as_id), is_core=is_core)
    as_.save()
    return as_


def _create_TRC(isd, serial, base):
    # avoid using the create methods from the TRCManager
    trc = TRC(isd=isd, not_before=datetime.utcnow(), not_after=datetime.utcnow(),
              base_version=base, serial_version=serial)
    trc.save()
    return trc
