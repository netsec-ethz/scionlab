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

from datetime import datetime, timedelta
from django.db import transaction
from django.test import TestCase

from scionlab.scion import as_ids, certs, trcs, pkicommand
from scionlab.models.core import ISD, AS
from scionlab.models.pki import Key, Certificate
from scionlab.models.trc import TRC, _coreas_certificates

_ASID_1 = 'ff00:0:1'
_ASID_2 = 'ff00:0:2'
_ASID_3 = 'ff00:0:3'


class TRCTests(TestCase):
    def setUp(self):
        self.isd1 = ISD.objects.create(isd_id=1, label='Test')

    def test_get_previous(self):
        trc1 = _create_TRC(self.isd1, 1, 1)
        self.assertEqual(trc1.predecessor_trc_or_none(), trc1)
        trc2 = _create_TRC(self.isd1, 2, 1)
        self.assertEqual(trc2.predecessor_trc_or_none(), trc1)
        trc4 = _create_TRC(self.isd1, 4, 1)
        self.assertIsNone(trc4.predecessor_trc_or_none())

    def test_get_voters_indices(self):
        as110 = _create_AS(self.isd1, 'ff00:0:110', is_core=True)
        Key.objects.create_core_keys(as110)
        Certificate.objects.create_core_certs(as110)
        prev = _create_TRC(self.isd1, 1, 1)
        c0 = Certificate.objects.create_voting_regular_cert(as110)
        c1 = Certificate.objects.create_voting_regular_cert(as110)
        c2 = Certificate.objects.create_voting_regular_cert(as110)
        c3 = Certificate.objects.create_voting_regular_cert(as110)
        c4 = Certificate.objects.create_voting_regular_cert(as110)
        prev.certificates.add(c0, c1, c2, c3, c4)
        prev.save()
        trc = _create_TRC(self.isd1, 2, 1)
        trc.certificates.add(c0, c1, c2, c3, c4)
        trc.votes.add(c1)
        self.assertEqual(_get_voters_indices(trc), [1])
        trc.votes.add(c4)
        self.assertEqual(_get_voters_indices(trc), [1, 4])
        # insert votes in a different order
        trc.votes.clear()
        trc.votes.add(c3)
        trc.votes.add(c4)
        trc.votes.add(c1)
        self.assertEqual(_get_voters_indices(trc), [1, 3, 4])

    def test_certificates_indices_after_delete(self):
        as110 = _create_AS(self.isd1, 'ff00:0:110', is_core=True)
        as210 = _create_AS(self.isd1, 'ff00:0:210', is_core=True)
        Key.objects.create_core_keys(as110)
        Key.objects.create_core_keys(as210)
        Certificate.objects.create_core_certs(as110)
        Certificate.objects.create_core_certs(as210)

        prev = _create_TRC(self.isd1, 1, 1)
        c0 = Certificate.objects.create_voting_sensitive_cert(as110)
        c1 = Certificate.objects.create_voting_regular_cert(as110)
        c2 = Certificate.objects.create_issuer_root_cert(as110)
        c3 = Certificate.objects.create_voting_sensitive_cert(as210)
        c4 = Certificate.objects.create_voting_regular_cert(as210)
        c5 = Certificate.objects.create_issuer_root_cert(as210)
        prev.certificates.add(c0, c1, c2, c3, c4, c5)
        prev.save()

        trc = _create_TRC(self.isd1, 2, 1)
        trc.certificates.add(c0, c1, c2, c3, c4)
        trc.votes.add(c0, c1, c3, c4)
        trc.save()
        self.assertEqual(_get_voters_indices(trc), [0, 1, 3, 4])  # normal
        for c in [c0, c1, c2, c3, c4, c5]:
            with transaction.atomic():  # transaction of the test would be broken otherwise
                self.assertRaises(RuntimeError, c.delete)
        # and the indices of the voters never changed
        self.assertEqual(_get_voters_indices(trc), [0, 1, 3, 4])
        prev.delete()
        c5.delete()  # does not raise exception, not part of a TRC anymore


class TRCUpdateTests(TestCase):
    def setUp(self):
        self.isd1 = ISD.objects.create(isd_id=1, label='Test')

    def test_update_regular_possible(self):
        trc1 = _create_TRC(self.isd1, 1, 1)
        self.assertIsNotNone(trc1.check_regular_update_error())  # no previous TRC
        self.assertIn('no previous', trc1.check_regular_update_error())
        as1 = _create_AS(self.isd1, 'ff00:0:110', is_core=True)
        Key.objects.create_core_keys(as1)
        Certificate.objects.create_core_certs(as1)
        self._reset_core_ases(trc1)
        trc2 = TRC(isd=self.isd1, not_before=datetime.utcnow(), not_after=datetime.utcnow(),
                   base_version=1, serial_version=2)
        trc2.save()
        self._reset_core_ases(trc2)
        self.assertIsNone(trc2.check_regular_update_error())
        # create new voter
        as2 = _create_AS(self.isd1, 'ff00:0:210', is_core=True)
        Key.objects.create_core_keys(as2)
        Certificate.objects.create_core_certs(as2)
        self._reset_core_ases(trc2)
        self.assertIsNotNone(trc2.check_regular_update_error())  # quorum changed
        self.assertIn('quorum', trc2.check_regular_update_error())
        trc2.quorum = trc1.quorum  # force quorum to be the same
        trc2.save()
        self.assertIsNotNone(trc2.check_regular_update_error())  # core section changed
        self.assertIn('core section', trc2.check_regular_update_error())
        trc2.quorum += 1  # reinstate the correct quorum
        trc2.save()
        # sanity check
        trc3 = TRC(isd=self.isd1, not_before=datetime.utcnow(), not_after=datetime.utcnow(),
                   base_version=1, serial_version=3)
        trc3.save()
        self._reset_core_ases(trc3)
        self.assertIsNone(trc3.check_regular_update_error())
        # change sensitive voting cert (only the cert suffices)
        Certificate.objects.create_voting_sensitive_cert(as1)
        trc4 = TRC(isd=self.isd1, not_before=datetime.utcnow(), not_after=datetime.utcnow(),
                   base_version=1, serial_version=4)
        trc4.save()
        self._reset_core_ases(trc4)
        self.assertIsNotNone(trc4.check_regular_update_error())  # sensitive voting different
        self.assertIn('sensitive vote', trc4.check_regular_update_error())
        # sanity check
        trc5 = TRC(isd=self.isd1, not_before=datetime.utcnow(), not_after=datetime.utcnow(),
                   base_version=1, serial_version=5)
        trc5.save()
        self._reset_core_ases(trc5)
        self.assertIsNone(trc5.check_regular_update_error())
        # change number of included certificates
        trc6 = TRC(isd=self.isd1, not_before=datetime.utcnow(), not_after=datetime.utcnow(),
                   base_version=1, serial_version=6)
        trc6.save()
        self._reset_core_ases(trc6)
        trc6.certificates.remove(trc6.certificates.filter(key__usage=Key.ISSUING_ROOT).last())
        self.assertIsNotNone(trc6.check_regular_update_error())
        self.assertIn('different number', trc6.check_regular_update_error())
        # change regular voting certificate, not part of voters
        self._reset_core_ases(trc6)
        trc7 = TRC(isd=self.isd1, not_before=datetime.utcnow(), not_after=datetime.utcnow(),
                   base_version=1, serial_version=7)
        trc7.save()
        self._reset_core_ases(trc7)
        self.assertIsNone(trc7.check_regular_update_error())
        cert = trc7.certificates.filter(key__usage=Key.TRC_VOTING_REGULAR).last()
        trc7.certificates.remove(cert)
        as_ = cert.key.AS
        trc7.certificates.add(Certificate.objects.create_voting_regular_cert(as_))
        trc7.save()
        self.assertIsNotNone(trc7.check_regular_update_error())
        self.assertIn('regular voting certificate', trc7.check_regular_update_error())
        self.assertIn('not part of voters', trc7.check_regular_update_error())
        # change regular voting certificate, make it part of voters
        trc7.votes.add(cert)
        self.assertIsNone(trc7.check_regular_update_error())

        # change root certificate, not part of voters
        trc8 = TRC(isd=self.isd1, not_before=datetime.utcnow(), not_after=datetime.utcnow(),
                   base_version=1, serial_version=8)
        trc8.save()
        self._reset_core_ases(trc8)
        self.assertIsNone(trc8.check_regular_update_error())
        cert = trc8.certificates.filter(key__usage=Key.ISSUING_ROOT).last()
        trc8.certificates.remove(cert)
        as_ = cert.key.AS
        cert = Certificate.objects.create_issuer_root_cert(as_)
        trc8.certificates.add(cert)
        trc8.save()
        self.assertIsNotNone(trc8.check_regular_update_error())
        self.assertIn('root certificate', trc8.check_regular_update_error())
        self.assertIn('not sign', trc8.check_regular_update_error())

        # change root certificate, make it part of voters
        trc8.signatures.add(cert)
        self.assertIsNone(trc8.check_regular_update_error())

    def _reset_core_ases(self, trc):
        trc.core_ases.clear()
        trc.core_ases.set(trc.isd.ases.filter(is_core=True))
        trc.quorum = trc.core_ases.count() // 2 + 1
        # insert all core AS certificates:
        trc.certificates.clear()
        trc.certificates.add(*_coreas_certificates(trc.isd))
        trc.save()


class TRCCreationTests(TestCase):
    def setUp(self):
        self.isd1 = ISD.objects.create(isd_id=1, label='Test')

    def test_create_empty(self):
        self.assertRaises(Exception,  # no core ases
                          TRC.objects.create,
                          isd=self.isd1)

    def test_create_first(self):
        self._create_ases()
        trc = TRC.objects.create(self.isd1)

        _check_trc(trc, trc)
        self.assertEqual(trc.serial_version, trc.base_version)
        self.assertEqual(trc.predecessor_trc_or_none(), trc)
        self.assertFalse(trc.votes.exists())
        self.assertEqual(trc.quorum, 2)

    def test_create_regular_update(self):
        self._create_ases()
        prev = TRC.objects.create(self.isd1)
        trc = TRC.objects.create(self.isd1)

        _check_trc(trc, prev)
        self.assertEqual(trc.serial_version, prev.serial_version + 1)
        self.assertEqual(trc.base_version, prev.base_version)
        self.assertEqual(trc.predecessor_trc_or_none(), prev)
        self.assertTrue(trc.votes.exists())
        self.assertEqual(trc.quorum, prev.quorum)

    def test_create_sensitive_update(self):
        self._create_ases()
        prev = TRC.objects.create(self.isd1)
        # add another core AS. This forces a sensitive update.
        as4 = _create_AS(self.isd1, 'ff00:0:4', is_core=True)
        Key.objects.create_all_keys(as4)
        Certificate.objects.create_all_certs(as4)
        trc = TRC.objects.create(self.isd1)

        _check_trc(trc, prev)
        self.assertEqual(trc.serial_version, prev.serial_version + 1)
        self.assertEqual(trc.base_version, prev.base_version)
        self.assertEqual(trc.predecessor_trc_or_none(), prev)
        self.assertTrue(trc.votes.exists())
        self.assertEqual(trc.quorum, prev.quorum)

    def test_delete_one_core_as(self):
        self._create_ases()
        prev = TRC.objects.create(self.isd1)
        # remove one core AS
        AS.objects.filter(is_core=True, isd=self.isd1).first().delete()
        # deleting a core As triggers a generation of a TRC. Get that TRC:
        trc = TRC.objects.latest()

        # check the trc chain
        _check_trc(trc, prev)
        # check it's a sensitive update
        self.assertEqual(trc.serial_version, prev.serial_version + 1)
        self.assertEqual(trc.base_version, prev.base_version)
        self.assertEqual(trc.predecessor_trc_or_none(), prev)
        self.assertTrue(trc.votes.exists())
        self.assertNotEqual(trc.quorum, prev.quorum)

        # Check valid latest CP AS certificates regenerated, core
        some_core = AS.objects.filter(is_core=True, isd=self.isd1).first()
        cert_cp_as = some_core.certificates_latest().filter(key__usage=Key.CP_AS).first()
        loaded_chain = cert_cp_as.format_certfile()
        certs.verify_cp_as_chain(loaded_chain, trc.trc)
        some_core.validate_crypto()

        # Check valid latest CP AS certificates regenerated, non-core
        any_none_core = AS.objects.filter(is_core=False, isd=self.isd1).first()
        cert_cp_as = any_none_core.certificates_latest().filter(key__usage=Key.CP_AS).first()
        loaded_chain = cert_cp_as.format_certfile()
        certs.verify_cp_as_chain(loaded_chain, trc.trc)
        any_none_core.validate_crypto()

    def test_broken_delete_one_core_as(self):
        # [regression test] Check that validating an invalid / old certificate fails
        # against an updated TRC
        self._create_ases()
        prev = TRC.objects.create(self.isd1)
        # remove one core AS
        AS.objects.filter(is_core=True, isd=self.isd1).first().delete()
        # deleting a core As triggers a generation of a TRC. Get that TRC:
        trc = TRC.objects.latest()

        # check the trc chain
        _check_trc(trc, prev)
        # check it's a sensitive update
        self.assertEqual(trc.serial_version, prev.serial_version + 1)
        self.assertEqual(trc.base_version, prev.base_version)
        self.assertEqual(trc.predecessor_trc_or_none(), prev)
        self.assertTrue(trc.votes.exists())
        self.assertNotEqual(trc.quorum, prev.quorum)

        # Check invalid CP AS certificates when selecting old certificate, core
        with self.assertRaises(pkicommand.ScionPkiError):
            some_core = AS.objects.filter(is_core=True, isd=self.isd1).first()
            cert_cp_as = Certificate.objects.filter(key__AS=some_core, key__usage=Key.CP_AS,
                                                    key__version=1).get()
            loaded_chain = cert_cp_as.format_certfile()
            certs.verify_cp_as_chain(loaded_chain, trc.trc)

        # Check invalid CP AS certificates when randomly selecting, non-core
        with self.assertRaises(AttributeError):
            any_none_core = AS.objects.filter(is_core=False, isd=self.isd1).first()
            cert_cp_as = Certificate.objects.filter(key__AS=any_none_core, key__usage=Key.CP_AS,
                                                    key__version=1).get()
            loaded_chain = cert_cp_as.format_certfile()
            # We should never get further, Unreachable code
            # The first core AS was deleted and the non-core v1 CP AS cert was referring to
            # that core AS CA cert
            certs.verify_cp_as_chain(loaded_chain, trc.trc)

    def test_create_less_core_ases(self):
        self._create_ases()
        prev = TRC.objects.create(self.isd1)
        # leave only one core AS
        AS.objects.exclude(pk=AS.objects.filter(is_core=True).first().pk).delete()
        # deleting core ASes triggers a generation of a TRC. Get that TRC:
        trc = TRC.objects.latest()

        # check it's a sensitive update
        _check_trc(trc, prev)
        self.assertEqual(trc.serial_version, prev.serial_version + 1)
        self.assertEqual(trc.base_version, prev.base_version)
        self.assertEqual(trc.predecessor_trc_or_none(), prev)
        self.assertTrue(trc.votes.exists())
        self.assertNotEqual(trc.quorum, prev.quorum)

    def _create_ases(self):
        as1 = _create_AS(self.isd1, 'ff00:0:1', is_core=True)
        as2 = _create_AS(self.isd1, 'ff00:0:2', is_core=True)
        as3 = _create_AS(self.isd1, 'ff00:0:3', is_core=False)
        Key.objects.create_all_keys(as1)
        Key.objects.create_all_keys(as2)
        Key.objects.create_all_keys(as3)
        Certificate.objects.create_all_certs(as1)
        Certificate.objects.create_all_certs(as2)
        Certificate.objects.create_all_certs(as3)


class WithExpiredCertsTests(TestCase):
    def setUp(self):
        self.isd1 = ISD.objects.create(isd_id=1, label='Test')
        self.as1 = _create_AS(self.isd1, 'ff00:0:1', is_core=True)

    def test_create_with_expired_crypto_material(self):
        # have the certificates expire before voting and signing.
        not_before = datetime.utcnow() - timedelta(days=1)
        not_after = not_before + timedelta(seconds=3600)
        Key.objects.create_all_keys(self.as1, not_before, not_after)
        Certificate.objects.create_all_certs(self.as1)
        prev = TRC.objects.create(self.isd1)

        # add another core AS.
        as2 = _create_AS(self.isd1, 'ff00:0:2', is_core=True)
        Key.objects.create_all_keys(as2, not_before, not_after)
        Certificate.objects.create_all_certs(as2)
        trc = TRC.objects.create(self.isd1)

        # despite being created with currently expired material, all is good:
        _check_trc(trc, prev)
        # and check this is just an update
        self.assertEqual(trc.serial_version, prev.serial_version + 1)
        self.assertEqual(trc.base_version, prev.base_version)
        self.assertEqual(trc.predecessor_trc_or_none(), prev)
        self.assertTrue(trc.votes.exists())

    def test_create_with_not_overlapping_crypto_material(self):
        # create a prev. TRC and update it with a TRC whose validity doesn't overlap with prev.
        not_before = datetime.utcnow()
        not_after = not_before + timedelta(days=1)
        Key.objects.create_core_keys(self.as1, not_before, not_after)
        Certificate.objects.create_core_certs(self.as1)
        prev = TRC.objects.create(self.isd1)
        # add another core AS.
        as2 = _create_AS(self.isd1, 'ff00:0:2', is_core=True)
        not_before = not_after + timedelta(microseconds=100)
        not_after = not_before + timedelta(days=1)
        Key.objects.create_core_keys(as2, not_before=not_before, not_after=not_after)
        Certificate.objects.create_core_certs(as2)
        # and refresh the crypto material of as1
        Key.objects.create_core_keys(self.as1, not_before, not_after)
        Certificate.objects.create_core_certs(self.as1)
        trc = TRC.objects.create(self.isd1)

        # we should get a base TRC
        _check_trc(trc, trc)
        self.assertEqual(trc.serial_version, prev.serial_version + 1)
        self.assertEqual(trc.base_version, trc.serial_version)
        self.assertEqual(trc.predecessor_trc_or_none(), trc)
        self.assertFalse(trc.votes.exists())


class WithNewCoreASesTests(TestCase):
    def test_delete_all_core_ases(self):
        isd1 = ISD.objects.create(isd_id=1, label='Test')
        as1 = _create_AS(isd1, 'ff00:0:1', is_core=True)
        as1.update_keys_certs()
        trc1 = TRC.objects.create(isd1)
        self.assertIsNotNone(trc1)
        self.assertEqual(trc1.base_version, trc1.serial_version)  # base TRC
        _check_trc(trc1, trc1)
        # delete all ASes in the ISD, and then create new ones with different ID
        AS.objects.filter(isd=isd1).delete()
        as2 = _create_AS(isd1, 'ff00:0:2', is_core=True)
        as2.update_keys_certs()
        trc2 = TRC.objects.create(isd1)
        self.assertIsNotNone(trc2)
        self.assertEqual(trc2.serial_version, trc1.serial_version + 1)
        self.assertEqual(trc2.base_version, trc1.base_version)  # just an update
        _check_trc(trc2, trc1)  # sufficient to verify votes and signatures


def _create_AS(isd, as_id, is_core=False):
    as_ = AS(isd=isd, as_id=as_id, as_id_int=as_ids.parse(as_id), is_core=is_core)
    as_.save()
    return as_


def _create_TRC(isd, serial, base):
    # avoid using the create methods from the TRCManager
    trc = TRC(isd=isd, not_before=datetime.utcnow(), not_after=datetime.utcnow(),
              base_version=base, serial_version=serial)
    trc.save()
    return trc


def _get_voters_indices(trc):
    """ uses the certificate indices of the previous TRC to indicate who voted """
    prev = trc.predecessor_trc_or_none()
    if prev is None:
        return None
    return prev.get_certificate_indices(trc.votes.all())


def _check_trc(trc, anchor):
    """ Verify a TRC, raises on error """
    trcs.verify_trcs(anchor.trc, trc.trc)
