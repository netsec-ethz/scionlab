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
from datetime import datetime, timedelta
from django.test import TestCase
from time import sleep

from scionlab.defines import (
    DEFAULT_EXPIRATION_AS_KEYS,
    DEFAULT_EXPIRATION_CORE_KEYS,
    DEFAULT_TRC_GRACE_PERIOD,
)
from scionlab.scion import as_ids, keys, trcs, jws
from scionlab.models.core import ISD, AS
from scionlab.models.pki import Key, Certificate
from scionlab.models.trc import TRC, _can_update, _coreas_certificates
from scionlab.tests.utils import check_scion_trc


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
        as110 = _create_AS(self.isd1, "ff00:0:110", is_core=True)
        Key.objects.create_core_keys(as110)
        Certificate.objects.create_core_certs(as110)
        prev = _create_TRC(self.isd1, 1, 1)
        c0 = Certificate.objects.create_voting_regular_cert(as110)
        c1 = Certificate.objects.create_voting_regular_cert(as110)
        c2 = Certificate.objects.create_voting_regular_cert(as110)
        c3 = Certificate.objects.create_voting_regular_cert(as110)
        c4 = Certificate.objects.create_voting_regular_cert(as110)
        prev.add_certificates([c0, c1, c2, c3, c4])
        prev.save()
        trc = _create_TRC(self.isd1, 2, 1)
        trc.add_certificates([c0, c1, c2, c3, c4])
        trc.add_vote(c1)
        self.assertEqual(trc.get_voters_indices(), [1])
        trc.add_vote(c4)
        self.assertEqual(trc.get_voters_indices(), [1, 4])
        # insert votes in a different order
        trc.votes.clear()
        trc.add_vote(c3)
        trc.add_vote(c4)
        trc.add_vote(c1)
        self.assertEqual(trc.get_voters_indices(), [1, 3, 4])


class TRCUpdateTests(TestCase):
    def setUp(self):
        self.isd1 = ISD.objects.create(isd_id=1, label='Test')

    def test_can_update(self):
        self.assertFalse(_can_update(self.isd1))
        _create_TRC(self.isd1, 1, 1)
        self.assertTrue(_can_update(self.isd1))  # only checks that there exists a prev. TRC

    def test_update_regular_possible(self):
        trc1 = _create_TRC(self.isd1, 1, 1)
        self.assertTrue(trc1.update_regular_impossible())  # no previous TRC
        self.assertIn("no previous", trc1.update_regular_impossible())
        as1 = _create_AS(self.isd1, "ff00:0:110", is_core=True)
        Key.objects.create_core_keys(as1)
        Certificate.objects.create_core_certs(as1)
        self._reset_core_ases(trc1)
        trc2 = TRC(isd=self.isd1, not_before=datetime.utcnow(), not_after=datetime.utcnow(),
                   base_version=1, serial_version=2)
        trc2.save()
        self._reset_core_ases(trc2)
        self.assertFalse(trc2.update_regular_impossible())
        # create new voter
        as2 = _create_AS(self.isd1, "ff00:0:210", is_core=True)
        Key.objects.create_core_keys(as2)
        Certificate.objects.create_core_certs(as2)
        self._reset_core_ases(trc2)
        self.assertTrue(trc2.update_regular_impossible())  # quorum changed
        self.assertIn("quorum", trc2.update_regular_impossible())
        trc2.quorum = trc1.quorum  # force quorum to be the same
        trc2.save()
        self.assertTrue(trc2.update_regular_impossible())  # core section changed
        self.assertIn("core section", trc2.update_regular_impossible())
        trc2.quorum += 1  # reinstate the correct quorum
        trc2.save()
        # sanity check
        trc3 = TRC(isd=self.isd1, not_before=datetime.utcnow(), not_after=datetime.utcnow(),
                   base_version=1, serial_version=3)
        trc3.save()
        self._reset_core_ases(trc3)
        self.assertFalse(trc3.update_regular_impossible())
        # change sensitive voting cert (only the cert suffices)
        Certificate.objects.create_voting_sensitive_cert(as1)
        trc4 = TRC(isd=self.isd1, not_before=datetime.utcnow(), not_after=datetime.utcnow(),
                   base_version=1, serial_version=4)
        trc4.save()
        self._reset_core_ases(trc4)
        self.assertTrue(trc4.update_regular_impossible())  # sensitive voting different
        self.assertIn("sensitive vote", trc4.update_regular_impossible())
        # sanity check
        trc5 = TRC(isd=self.isd1, not_before=datetime.utcnow(), not_after=datetime.utcnow(),
                   base_version=1, serial_version=5)
        trc5.save()
        self._reset_core_ases(trc5)
        self.assertFalse(trc5.update_regular_impossible())
        # change number of included certificates
        trc6 = TRC(isd=self.isd1, not_before=datetime.utcnow(), not_after=datetime.utcnow(),
                   base_version=1, serial_version=6)
        trc6.save()
        self._reset_core_ases(trc6)
        trc6.certificateintrc_set.filter(certificate__key__usage=Key.ISSUING_ROOT).last().delete()
        self.assertTrue(trc6.update_regular_impossible())
        self.assertIn("different number", trc6.update_regular_impossible())
        # change regular voting certificate, not part of voters
        self._reset_core_ases(trc6)
        trc7 = TRC(isd=self.isd1, not_before=datetime.utcnow(), not_after=datetime.utcnow(),
                   base_version=1, serial_version=7)
        trc7.save()
        self._reset_core_ases(trc7)
        self.assertFalse(trc7.update_regular_impossible())
        cert = trc7.certificateintrc_set.filter(
            certificate__key__usage=Key.TRC_VOTING_REGULAR).last()
        trc7.del_certificates([cert.certificate])
        as_ = cert.certificate.key.AS
        trc7.add_certificates([Certificate.objects.create_voting_regular_cert(as_)])
        trc7.save()
        self.assertTrue(trc7.update_regular_impossible())
        self.assertIn("regular voting certificate", trc7.update_regular_impossible())
        self.assertIn("not part of voters", trc7.update_regular_impossible())
        # change regular voting certificate, make it part of voters
        trc7.votes.add(cert.certificate)
        self.assertFalse(trc7.update_regular_impossible())

        # change root certificate, not part of voters
        trc8 = TRC(isd=self.isd1, not_before=datetime.utcnow(), not_after=datetime.utcnow(),
                   base_version=1, serial_version=8)
        trc8.save()
        self._reset_core_ases(trc8)
        self.assertFalse(trc8.update_regular_impossible())
        cert = trc8.certificateintrc_set.filter(
            certificate__key__usage=Key.ISSUING_ROOT).last()
        trc8.del_certificates([cert.certificate])
        as_ = cert.certificate.key.AS
        cert = Certificate.objects.create_issuer_root_cert(as_)
        trc8.add_certificates([cert])
        trc8.save()
        self.assertTrue(trc8.update_regular_impossible())
        self.assertIn("root certificate", trc8.update_regular_impossible())
        self.assertIn("not sign", trc8.update_regular_impossible())

        # change root certificate, make it part of voters
        trc8.signatures.add(cert)
        self.assertFalse(trc8.update_regular_impossible())

    def _reset_core_ases(self, trc):
        trc.core_ases.clear()
        trc.core_ases.set(trc.isd.ases.filter(is_core=True))
        trc.quorum = trc.core_ases.count() // 2 + 1
        # insert all core AS certificates:
        trc.certificates.clear()
        trc.add_certificates(_coreas_certificates(trc.isd))
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

        _check_trc(self, trc, trc)
        self.assertEqual(trc.serial_version, trc.base_version)
        self.assertEqual(trc.predecessor_trc_or_none(), trc)
        self.assertFalse(trc.votes.exists())
        self.assertEqual(trc.quorum, 2)

    def test_create_regular_update(self):
        self._create_ases()
        prev = TRC.objects.create(self.isd1)
        trc = TRC.objects.create(self.isd1)

        _check_trc(self, trc, prev)
        self.assertEqual(trc.serial_version, prev.serial_version + 1)
        self.assertEqual(trc.base_version, prev.base_version)
        self.assertEqual(trc.predecessor_trc_or_none(), prev)
        self.assertTrue(trc.votes.exists())
        self.assertEqual(trc.quorum, prev.quorum)

    def test_create_sensitive_update(self):
        self._create_ases()
        prev = TRC.objects.create(self.isd1)
        # add another core AS. This forces a sensitive update.
        as4 = _create_AS(self.isd1, "ff00:0:4", is_core=True)
        Key.objects.create_all_keys(as4)
        Certificate.objects.create_all_certs(as4)
        trc = TRC.objects.create(self.isd1)

        _check_trc(self, trc, prev)
        self.assertEqual(trc.serial_version, prev.serial_version + 1)
        self.assertEqual(trc.base_version, prev.base_version)
        self.assertEqual(trc.predecessor_trc_or_none(), prev)
        self.assertTrue(trc.votes.exists())
        self.assertEqual(trc.quorum, prev.quorum)

    def test_create_less_core_ases(self):
        self._create_ases()
        prev = TRC.objects.create(self.isd1)
        # leave only one core AS
        AS.objects.exclude(pk=AS.objects.filter(is_core=True).first().pk).delete()
        # deleting core ASes triggers a generation of a TRC. Get that TRC:
        trc = TRC.objects.latest()

        # check it's a sensitive update
        _check_trc(self, trc, prev)
        self.assertEqual(trc.serial_version, prev.serial_version + 1)
        self.assertEqual(trc.base_version, prev.base_version)
        self.assertEqual(trc.predecessor_trc_or_none(), prev)
        self.assertTrue(trc.votes.exists())
        self.assertNotEqual(trc.quorum, prev.quorum)

    def _create_ases(self):
        as1 = _create_AS(self.isd1, "ff00:0:1", is_core=True)
        as2 = _create_AS(self.isd1, "ff00:0:2", is_core=True)
        as3 = _create_AS(self.isd1, "ff00:0:3", is_core=False)
        Key.objects.create_all_keys(as1)
        Key.objects.create_all_keys(as2)
        Key.objects.create_all_keys(as3)
        Certificate.objects.create_all_certs(as1)
        Certificate.objects.create_all_certs(as2)
        Certificate.objects.create_all_certs(as3)


class WithExpiredCertsTests(TestCase):
    def setUp(self):
        self.isd1 = ISD.objects.create(isd_id=1, label='Test')
        self.as1 = _create_AS(self.isd1, "ff00:0:1", is_core=True)

    def test_create_with_expired_crypto_material(self):
        # have the certificates expire before voting and signing.
        not_before = datetime.utcnow() - timedelta(days=1)
        not_after = not_before + timedelta(seconds=3600)
        Key.objects.create_all_keys(self.as1, not_before, not_after)
        Certificate.objects.create_all_certs(self.as1)
        prev = TRC.objects.create(self.isd1)

        # add another core AS.
        as2 = _create_AS(self.isd1, "ff00:0:2", is_core=True)
        Key.objects.create_all_keys(as2, not_before, not_after)
        Certificate.objects.create_all_certs(as2)
        trc = TRC.objects.create(self.isd1)

        # despite being created with currently expired material, all is good:
        _check_trc(self, trc, prev)
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
        as2 = _create_AS(self.isd1, "ff00:0:2", is_core=True)
        not_before = not_after + timedelta(microseconds=100)
        not_after = not_before + timedelta(days=1)
        Key.objects.create_core_keys(as2, not_before=not_before, not_after=not_after)
        Certificate.objects.create_core_certs(as2)
        # and refresh the crypto material of as1
        Key.objects.create_core_keys(self.as1, not_before, not_after)
        Certificate.objects.create_core_certs(self.as1)
        trc = TRC.objects.create(self.isd1)

        # we should get a base TRC
        _check_trc(self, trc, trc)
        self.assertEqual(trc.serial_version, prev.serial_version + 1)
        self.assertEqual(trc.base_version, trc.serial_version)
        self.assertEqual(trc.predecessor_trc_or_none(), trc)
        self.assertFalse(trc.votes.exists())


class WithNewCoreASesTests(TestCase):
    def test_delete_all_core_ases(self):
        isd1 = ISD.objects.create(isd_id=1, label='Test')
        as1 = _create_AS(isd1, "ff00:0:1", is_core=True)
        as1.update_keys_certs()
        trc1 = TRC.objects.create(isd1)
        self.assertIsNotNone(trc1)
        self.assertEqual(trc1.base_version, trc1.serial_version)  # base TRC
        _check_trc(self, trc1, trc1)
        # delete all ASes in the ISD, and then create new ones with different ID
        AS.objects.filter(isd=isd1).delete()
        as2 = _create_AS(isd1, "ff00:0:2", is_core=True)
        as2.update_keys_certs()
        trc2 = TRC.objects.create(isd1)
        self.assertIsNotNone(trc2)
        self.assertEqual(trc2.serial_version, trc1.serial_version + 1)
        self.assertEqual(trc2.base_version, trc1.base_version)  # just an update
        _check_trc(self, trc2, trc1)  # sufficient to verify votes and signatures


class OlderTests(TestCase):
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

    def _test_generate_initial(self):
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

    def _test_update_offline(self):
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

    def _test_remove_as(self):
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

    def _test_add_as(self):
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

    def _test_update_online(self):
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

    def _test_update_issuing(self):
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


def _gen_key(version):
    """
    Generate a new signing key and return it as a trcs.Key info object.
    """
    priv = keys.generate_sign_key()
    pub = keys.public_sign_key(priv)
    return trcs.Key(version=version, priv_key=priv, pub_key=pub)


def _check_trc(testcase, trc, anchor):
    """ takes a TRC object and checks it """
    check_scion_trc(testcase, trcs.decode_trc(trc.trc), trcs.decode_trc(anchor.trc))

