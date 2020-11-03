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

import copy
import os
import re
from datetime import datetime, timedelta

from scionlab.models.core import ISD, AS
from scionlab.models.pki import Key, Certificate, TRC
from scionlab.defines import (
    DEFAULT_EXPIRATION_AS_KEYS,
    DEFAULT_EXPIRATION_CORE_KEYS,
    DEFAULT_TRC_GRACE_PERIOD,
)

from scionlab.scion import as_ids, keys, trcs, jws

from django.test import TestCase


class TryTest(TestCase):
    def test_thing(self):
        pass


class KeyTests(TestCase):

    def setUp(self):
        self.isd = ISD.objects.create(isd_id=1, label='Test')
        # bypass ASManager.create to avoid initializing keys
        self.AS = _create_AS(self.isd, 'ff00:0:110')

    def test_generate_regular_as_key(self):
        k = Key.objects.create(AS=self.AS, usage=Key.CP_AS)
        self.assertIsNotNone(k)
        self.assertEqual(k.AS_id, self.AS.pk)
        self.assertEqual(k.version, 1)
        self.assertEqual(k.usage, Key.CP_AS)
        self.assertEqual(k.not_after - k.not_before, DEFAULT_EXPIRATION_AS_KEYS)

    def test_latest(self):
        for as_ in [self.AS,
                    _create_AS(self.isd, "ff00:0:111"),
                    _create_AS(self.isd, "ff00:0:112")]:
            Key.objects.create(AS=as_, usage=Key.CP_AS)
        self.assertEqual(Key.objects.exclude(version=1).count(), 0)
        k = Key.objects.create(AS=self.AS, usage=Key.CP_AS)
        self.assertEqual(Key.objects.exclude(version=1).get(), k)

    def test_key_format(self):
        k = Key.objects.create(AS=self.AS, usage=Key.CP_AS)
        self.assertEqual(k.format_keyfile(), k.key)
        first_line = k.key.splitlines()[0]
        self.assertEqual(first_line, "-----BEGIN EC PRIVATE KEY-----")

    def test_delete_as(self):
        k_as = Key.objects.create(AS=self.AS, usage=Key.CP_AS)
        k_ca = Key.objects.create(AS=self.AS, usage=Key.ISSUING_CA)
        k_regular = Key.objects.create(AS=self.AS, usage=Key.TRC_VOTING_REGULAR)
        k_sensitive = Key.objects.create(AS=self.AS, usage=Key.TRC_VOTING_SENSITIVE)

        self.AS.delete()

        self.assertFalse(Key.objects.filter(pk=k_as.pk).exists())  # Delete should cascade here, ...
        self.assertFalse(Key.objects.filter(pk=k_ca.pk).exists())  # ... and here too.
        self.assertFalse(Key.objects.filter(pk=k_regular.pk).exists())  # ... and here too.
        self.assertTrue(Key.objects.filter(pk=k_sensitive.pk).exists())   # This one should still exist!


class CertificateTests(TestCase):
    def setUp(self):
        self.isd = ISD.objects.create(isd_id=1, label='Test')
        # bypass ASManager.create to avoid initializing keys
        self.AS = _create_AS(self.isd, 'ff00:0:110')

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

    def test_create_as_cert(self):
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
                          Certificate.objects.create_as_cert,
                          self.AS, self.AS, datetime.fromtimestamp(11), datetime.fromtimestamp(12))
        Key.objects.create(
            AS=self.AS, usage=Key.ISSUING_CA,
            not_before=datetime.fromtimestamp(10),
            not_after=datetime.fromtimestamp(12))
        self.assertRaises(Certificate.DoesNotExist,  # no CA cert
                          Certificate.objects.create_as_cert,
                          self.AS, self.AS, datetime.fromtimestamp(11), datetime.fromtimestamp(12))

        cert_ca = Certificate.objects.create_issuer_ca_cert(
            subject=self.AS,
            not_before=datetime.fromtimestamp(10),
            not_after=datetime.fromtimestamp(12))
        cert = Certificate.objects.create_as_cert(
            subject=self.AS,
            issuer=self.AS,
            not_before=datetime.fromtimestamp(11),
            not_after=datetime.fromtimestamp(12))
        self.assertEqual(cert.key, subject_key)
        self.assertEqual(cert.ca_cert, cert_ca)

    def test_as_certificate_another_issuer(self):
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
        subject = _create_AS(self.isd, "ff00:0:111")
        subject_key = Key.objects.create(
            AS=subject,
            usage=Key.CP_AS,
            not_before=datetime.fromtimestamp(11),
            not_after=datetime.fromtimestamp(12))
        cert = Certificate.objects.create_as_cert(
            subject=subject,
            issuer=self.AS,
            not_before=datetime.fromtimestamp(11),
            not_after=datetime.fromtimestamp(12))
        self.assertEqual(cert.key, subject_key)
        self.assertEqual(cert.ca_cert, cert_ca)

    def test_certificate_format(self):
        Key.objects.create(AS=self.AS, usage=Key.ISSUING_ROOT)
        cert = Certificate.objects.create_issuer_root_cert(
            subject=self.AS,
            not_before=datetime.utcnow(),
            not_after=datetime.utcnow())
        self.assertEqual(cert.certificate.splitlines()[0], "-----BEGIN CERTIFICATE-----")  # PEM
        self.assertEqual(cert.certificate.count("-----BEGIN CERTIFICATE-----"), 1)
        # AS certificates should contain a chain, with the subject certificate first,
        # and the CA second. The rest is only one certificate.
        Key.objects.create(self.AS, Key.ISSUING_CA)
        cert_ca = Certificate.objects.create_issuer_ca_cert(
            self.AS, datetime.utcnow(), datetime.utcnow())
        self.assertEqual(cert_ca.certificate.count("-----BEGIN CERTIFICATE-----"), 1)
        Key.objects.create(self.AS, Key.CP_AS)
        cert = Certificate.objects.create_as_cert(
            self.AS, self.AS, datetime.utcnow(), datetime.utcnow())
        output = cert.format_certfile()
        self.assertEqual(output.count("-----BEGIN CERTIFICATE-----"), 2)  # own cert and issuer
        index = output.find("-----BEGIN CERTIFICATE-----", 1)
        self.assertEqual(output[0:index], cert.certificate)  # own certificate
        self.assertEqual(output[index:], cert_ca.certificate)  # issuer


class ScionTests(TestCase):
    def test_trc_configure(self):
        kwargs = self._args_dict()
        conf = trcs.TRCConf(**kwargs)
        temp_dir_name = ""
        with conf.configure() as trc:
            # there is a temporary dir created, with the certificate files
            temp_dir_name = trc._temp_dir.name
            self.assertTrue(os.path.isdir(temp_dir_name))
            for fn, c in conf.certificates.items():
                self.assertTrue(os.path.isfile(fn))
                with open(fn) as f:
                    self.assertEqual(f.read(), c)
        self.assertFalse(os.path.exists(temp_dir_name))
        # absolute paths not allowed:
        kwargs["certificates"] = {"/tmp/mock-certificate.crt": "no-content"}
        self.assertRaises(ValueError, trcs.TRCConf, **kwargs)
        # anything but a filename is not allowed
        kwargs["certificates"] = {"../mock-certificate.crt": "no-content"}
        self.assertRaises(ValueError, trcs.TRCConf, **kwargs)
        kwargs["certificates"] = {"": "no-content"}
        self.assertRaises(ValueError, trcs.TRCConf, **kwargs)

    def test_validate(self):
        kwargs = self._args_dict()
        trcs.TRCConf(**kwargs)  # doesn't raise
        kwargs["isd_id"] = 0
        self.assertRaises(ValueError, trcs.TRCConf, **kwargs)
        kwargs = self._args_dict()
        kwargs["not_after"] = kwargs["not_before"]
        self.assertRaises(ValueError, trcs.TRCConf, **kwargs)
        kwargs = self._args_dict()


    def _args_dict(self):
        return {"isd_id": 1, "base": 1, "serial": 1, "grace_period": None,
                "not_before": datetime.utcnow(), "not_after": datetime.utcnow() + timedelta(days=1),
                "authoritative": ["1-ff00:0:110"], "core": ["1-ff00:0:110"],
                "certificates": {"mock-certificate.crt": "no-content"}}


_ASID_1 = 'ff00:0:1'
_ASID_2 = 'ff00:0:2'
_ASID_3 = 'ff00:0:3'


class TRCTests(TestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.isd1 = ISD.objects.create(isd_id=1, label='Test')

    def test_version_base_serial(self):
        self.assertEqual(TRC.next_version_base(), 1)
        self.assertEqual(TRC.next_version_serial(), 1)
        k_2_2 = _create_TRC(self.isd1, 2, 2)
        self.assertEqual(TRC.objects.latest(), k_2_2)
        self.assertEqual(TRC.next_version_base(), 3)
        self.assertEqual(TRC.next_version_serial(), 3)

        _create_TRC(self.isd1, 1, 1)
        self.assertEqual(TRC.objects.latest(), k_2_2)
        self.assertEqual(TRC.next_version_base(), 3)
        self.assertEqual(TRC.next_version_serial(), 3)

        k_2_3 = _create_TRC(self.isd1, 2, 3)
        self.assertEqual(TRC.objects.latest(), k_2_3)
        self.assertEqual(TRC.next_version_base(), 3)
        self.assertEqual(TRC.next_version_serial(), 4)
        self.assertEqual(TRC.objects.count(), 3)

    def gen_trc_v1(self):
        """
        Helper: create initial version of TRC
        @returns trc, primary_ases, voting_offline
        """
        primary_ases = {
            _ASID_1: trcs.CoreKeys(
                issuing_grant=_gen_key(1),
                voting_online=_gen_key(1),
                voting_offline=_gen_key(1),
            ),
            _ASID_2: trcs.CoreKeys(
                issuing_grant=_gen_key(1),
                voting_online=_gen_key(1),
                voting_offline=_gen_key(1),
            ),
        }

        voting_offline = {as_id: keys.voting_offline for as_id, keys in primary_ases.items()}

        not_before = datetime(2020, 2, 20)
        not_after = not_before + DEFAULT_EXPIRATION_CORE_KEYS

        trc = trcs.generate_trc(self.isd1, 1, DEFAULT_TRC_GRACE_PERIOD, not_before, not_after,
                                primary_ases, None, None)

        return trc, primary_ases, voting_offline

    def gen_trc_update(self, primary_ases, prev_trc, prev_voting_offline):
        """
        Helper: create update TRC
        """

        # decode prev payload to find next version number
        # we dont need to do this in production, but here it serves as a little sanity check for
        # the payload.
        prev = jws.decode_payload(prev_trc)
        prev_version = prev["trc_version"]
        self.assertGreaterEqual(1, prev_version)
        version = prev_version + 1

        # define validity time with arbitrary time offset from previous validity start.
        # key lifetime is not extended, so validty end is the same
        # Just for "fun", not really relevant.
        prev_not_before = datetime.utcfromtimestamp(prev['validity']['not_before'])
        prev_not_after = datetime.utcfromtimestamp(prev['validity']['not_after'])
        not_before = prev_not_before + timedelta(days=31)
        not_after = prev_not_after

        trc = trcs.generate_trc(self.isd1, version, DEFAULT_TRC_GRACE_PERIOD, not_before, not_after,
                                primary_ases, prev_trc, prev_voting_offline)

        return trc

    def test_generate_initial(self):
        trc, primary_ases, _ = self.gen_trc_v1()

        # initial version, is signed by _all_ keys (as proof of possession)
        votes = []
        pops = [
            (as_id, usage, key)
            for as_id, keys in primary_ases.items()
            for usage, key in keys._asdict().items()
        ]
        self.assertTrue(trcs.test_verify(trc, votes, pops))

        # sanity check: if we mess with one of the signatures, it will not verify:
        trc_bad = copy.deepcopy(trc)
        trc_bad['signatures'][0]['signature'] = 'forged'
        self.assertFalse(trcs.test_verify(trc_bad, votes, pops))

    def test_update_offline(self):
        trc_v1, primary_ases_v1, voting_offline_v1 = self.gen_trc_v1()

        primary_ases_v2 = copy.deepcopy(primary_ases_v1)
        primary_ases_v2[_ASID_1] = primary_ases_v1[_ASID_1]._replace(voting_offline=_gen_key(2))

        trc_v2 = self.gen_trc_update(primary_ases_v2, trc_v1, voting_offline_v1)

        # Updating offline keys is a sensitive update and must be signed with previous offline keys
        # and all updated keys (proof of possession).
        k_asid1_v2 = primary_ases_v2[_ASID_1]
        votes = [
            (as_id, 'voting_offline', k.voting_offline) for as_id, k in primary_ases_v1.items()
        ]
        pops = [
            (_ASID_1, 'voting_offline', k_asid1_v2.voting_offline),
        ]
        self.assertTrue(trcs.test_verify(trc_v2, votes, pops))

    def test_remove_as(self):
        trc_v1, primary_ases_v1, voting_offline_v1 = self.gen_trc_v1()

        primary_ases_v2 = copy.deepcopy(primary_ases_v1)
        del primary_ases_v2[_ASID_2]

        trc_v2 = self.gen_trc_update(primary_ases_v2, trc_v1, voting_offline_v1)

        # Modifying the set of primary ASese is a sensitive update and must be signed with
        # previous offline keys.
        # Note: because we use quorum == len(ases), the removed AS must cast a vote.
        votes = [
            (as_id, 'voting_offline', k.voting_offline) for as_id, k in primary_ases_v1.items()
        ]
        pops = []
        self.assertTrue(trcs.test_verify(trc_v2, votes, pops))

    def test_add_as(self):
        trc_v1, primary_ases_v1, voting_offline_v1 = self.gen_trc_v1()

        primary_ases_v2 = copy.deepcopy(primary_ases_v1)
        primary_ases_v2[_ASID_3] = trcs.CoreKeys(
            issuing_grant=_gen_key(1),
            voting_online=_gen_key(1),
            voting_offline=_gen_key(1),
        )

        trc_v2 = self.gen_trc_update(primary_ases_v2, trc_v1, voting_offline_v1)

        # Modifying the set of primary ASese is a sensitive update and must be signed with
        # previous offline keys and all keys for the added AS (proof of possession).
        votes = [
            (as_id, 'voting_offline', k.voting_offline) for as_id, k in primary_ases_v1.items()
        ]
        pops = [
            (_ASID_3, usage, key) for usage, key in primary_ases_v2[_ASID_3]._asdict().items()
        ]
        self.assertTrue(trcs.test_verify(trc_v2, votes, pops))

    def test_update_online(self):
        trc_v1, primary_ases_v1, voting_offline_v1 = self.gen_trc_v1()

        primary_ases_v2 = copy.deepcopy(primary_ases_v1)
        primary_ases_v2[_ASID_1] = primary_ases_v1[_ASID_1]._replace(voting_online=_gen_key(2))

        trc_v2 = self.gen_trc_update(primary_ases_v2, trc_v1, voting_offline_v1)

        # Updating online keys is a regular update
        # Votes are cast with offline keys for ASes with changed online key, and online key for
        # all others.
        k_asid1_v2 = primary_ases_v2[_ASID_1]
        k_asid2_v2 = primary_ases_v2[_ASID_2]
        votes = [
            (_ASID_1, 'voting_offline', k_asid1_v2.voting_offline),
            (_ASID_2, 'voting_online', k_asid2_v2.voting_online),
        ]
        pops = [
            (_ASID_1, 'voting_online', k_asid1_v2.voting_online),
        ]
        self.assertTrue(trcs.test_verify(trc_v2, votes, pops))

    def test_update_issuing(self):
        trc_v1, primary_ases_v1, voting_offline_v1 = self.gen_trc_v1()

        primary_ases_v2 = copy.deepcopy(primary_ases_v1)
        primary_ases_v2[_ASID_1] = primary_ases_v1[_ASID_1]._replace(issuing_grant=_gen_key(2))

        trc_v2 = self.gen_trc_update(primary_ases_v2, trc_v1, voting_offline_v1)

        # Updating issuing grant keys is a regular update and is signed with online keys and all
        # updated keys (proof of possession).
        k_asid1_v2 = primary_ases_v2[_ASID_1]
        votes = [
            (as_id, 'voting_online', k.voting_online)
            for as_id, k in primary_ases_v1.items()
        ]
        pops = [
            (_ASID_1, 'issuing_grant', k_asid1_v2.issuing_grant),
        ]
        self.assertTrue(trcs.test_verify(trc_v2, votes, pops))


def _gen_key(version):
    """
    Generate a new signing key and return it as a trcs.Key info object.
    """
    priv = keys.generate_sign_key()
    pub = keys.public_sign_key(priv)
    return trcs.Key(version=version, priv_key=priv, pub_key=pub)


def _create_AS(isd, as_id):
    as_ = AS(isd=isd, as_id=as_id, as_id_int=as_ids.parse(as_id))
    as_.save()
    return as_


def _create_TRC(isd, base, serial):
    trc = TRC(isd=isd, not_before=datetime.utcnow(), not_after=datetime.utcnow(),
              version_base=base, version_serial=serial)
    trc.save()
    return trc
