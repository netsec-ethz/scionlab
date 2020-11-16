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

"""
:mod:`scionlab.models.trc` --- Django models for SCION TRC entities
================================================================================
"""

from django.db import models

from scionlab.defines import DEFAULT_TRC_GRACE_PERIOD
from scionlab.models.core import AS, ISD
from scionlab.models.pki import Certificate, Key
from scionlab.scion import as_ids, keys, trcs


class TRCManager(models.Manager):
    def create(self, isd):
        """
        Create a TRC for this ISD.

        A TRC is "versioned" using a serial number.

        

        

        The update is sensitive if it is not regular.
        For sensitive TRC updates to be verifyable, they must contain votes
        only from sensitive certificates.

        For SCIONLab this means that only updates to the validity will be regular updates. The rest
        will be sensitive, as the update will involve changing membership of the core ASes.




        The version is incremented from the previous TRC. The voting offline keys related to the
        previous TRC may be (precisely: for online key updates and sensitive updates) used to sign
        the new TRC.

        In SCIONLab, authoritative ASes = core ASes = CA ASes.

        Requires at least one core AS in this ISD.

        The latest keys for all core ASes are used. The validity period for the TRC is determined
        based the validity of these keys.

        :param isd ISD:
        """

        if _can_update(isd):
            if _can_regular_update(isd):
                pass
            else:
                pass

        prev = isd.trcs.latest_or_none()

        if prev:
            version = prev.version + 1
            prev_trc = prev.trc
            prev_voting_offline = {key.as_id: _key_info(key)
                                   for key in prev.voting_offline.all()}
        else:
            version = 1
            prev_trc = None
            prev_voting_offline = None

        keys = {as_.as_id: _latest_core_keys(as_) for as_ in isd.ases.filter(is_core=True)}
        all_keys = flatten(keys.values())

        not_before, not_after = _validity(all_keys)

        primary_ases = {as_id: _core_key_info(as_keys) for as_id, as_keys in keys.items()}

        trc = trcs.generate_trc(
            isd=isd,
            version=version,
            grace_period=DEFAULT_TRC_GRACE_PERIOD,
            not_before=not_before,
            not_after=not_after,
            primary_ases=primary_ases,
            prev_trc=prev_trc,
            prev_voting_offline=prev_voting_offline,
        )

        voting_offline = [k for k in all_keys if k.usage == Key.TRC_VOTING_OFFLINE]

        obj = super().create(
            isd=isd,
            version=version,
            not_before=not_before,
            not_after=not_after,
            trc=trc,
        )
        obj.voting_offline.set(voting_offline)

    def latest(self):
        """ there could be more than one TRC with the same serial, but the latest is the one
        that has its base the further in the sequence """
        return super().latest("version_serial", "base_version")

    def latest_or_none(self):
        try:
            return self.latest()
        except TRC.DoesNotExist:
            return None


class TRC(models.Model):
    isd = models.ForeignKey(
        'ISD',
        related_name='trcs',
        on_delete=models.CASCADE,
        verbose_name='ISD'
    )

    # the serial version should be incremented monotonically.
    version_serial = models.PositiveIntegerField(editable=False, default=1)
    # the base version points at the serial which represents the anchor of an update chain.
    # when the base version is equal to the serial version, this TRC is the anchor, and
    # there is no update, but a creation from scratch.
    base_version = models.PositiveIntegerField(editable=False, default=1)

    not_before = models.DateTimeField()
    not_after = models.DateTimeField()

    certificates = models.ManyToManyField(
        Certificate,
        through="CertificateInTRC",
        related_name="trc_included",
    )

    quorum = models.PositiveIntegerField(
        default=1,
    )

    trc = models.BinaryField()  # in binary DER format

    # Sensitive voting keys are required to create the next TRC version for sensitive updates;
    # These keys are never deleted to ensure it is always possible to create a new TRC version, even
    # after removing _all_ core ASes of an ISD. (see also _key_set_null_or_cascade).
    # TODO(juagargi) should we reference the cert instead?
    voting_sensitive = models.ManyToManyField(
        Key,
        related_name="trc_voted_sensitive",
    )

    # we keep track of the certificates that have been included in the TRC
    # TODO(juagargi) do we? should we?
    voting_regular = models.ManyToManyField(
        Key,
        related_name="trc_voted_regular",
    )

    objects = TRCManager()

    class Meta:
        verbose_name = 'TRC'
        verbose_name_plural = 'TRCs'
        # unique_together = ('isd', 'version')
        unique_together = ('isd', 'version_serial', 'base_version')

    def add_certificates(self, certs):
        count = self.certificates.count()
        for i in range(len(certs)):
            CertificateInTRC.objects.create(trc=self, certificate=certs[i],
                                            index=count + i)

    def __str__(self):
        return self.filename()

    def filename(self) -> str:
        return f"ISD{self.isd.isd_id}-B{self.base_version}-S{self.version_serial}"

    def can_update_regular(self):
        """
        Check if this is a regular TRC update (as opposed to a sensitive one).

        It is a regular update if:
        - The voting quorum does not change.
        - The core ASes section does not change.
        - The authoritative ASes section does not change.
        - The number of sensitive, regular and root certificates does not change.
        - The set of sensitive certificates does not change.
        - For every regular certificate that changes, the regular certificate in the previous
            TRC is part of the voters of the new TRC.
        - For every root certificate that changes, the root certificate in the previous TRC
            attaches a signature to the new TRC.
        For regular TRC updates to be verifyable, they must contain votes
        only from regular certificates.

        - All votes from ASes with unchanged online voting keys must be cast with the online voting key.
        - All ASes with changed online voting keys must cast a vote with their offline voting key.
        """
        prev = TRC.objects.filter(isd=self.isd, version_serial=self.version_serial - 1)
        if not prev.exists() or prev.get() == self:
            return False
        prev = prev.get()
        if prev.quorum != self.quorum:
            return False
        # check core, authoritative ASes (they are treated the same in SCIONLab)
        prev_voters = prev.voting_sensitive.values_list(
            "AS__as_id_int", flat=True).order_by("AS__as_id_int")
        if list(self.voting_sensitive.values_list(
                "AS__as_id_int", flat=True).order_by("AS__as_id_int")) != list(prev_voters):
            return False
        # get sensitive certificates
        prev_sensitive = list(k.certificates.latest(Key.TRC_VOTING_SENSITIVE)
                              for k in prev.voting_sensitive.order_by("AS__as_id_int"))
        if list(k.certificates.latest(Key.TRC_VOTING_SENSITIVE) for k in self.voting_sensitive.order_by("AS__as_id_int")) != prev_sensitive:
            return False
        # TODO(juagargi) compare certs using the bytes
        return True

    @staticmethod
    def next_version():
        prev = TRC.objects.aggregate(
            models.Max('version_serial'))['version_serial__max'] or 0
        return prev + 1


class CertificateInTRC(models.Model):
    """ relationship through-table between TRC and Certificate """
    certificate = models.ForeignKey(
        Certificate,
        on_delete=models.CASCADE,
    )
    trc = models.ForeignKey(
        TRC,
        on_delete=models.CASCADE,
    )
    index = models.PositiveIntegerField()

# def _latest_core_keys(as_) -> List[Key]:
#     return [
#         as_.keys.latest(Key.TRC_ISSUING_GRANT),
#         as_.keys.latest(Key.TRC_VOTING_ONLINE),
#         as_.keys.latest(Key.TRC_VOTING_OFFLINE),
#     ]


# def _key_info(key: Key) -> trcs.Key:
#     return trcs.Key(
#         version=key.version,
#         priv_key=key.key,
#         pub_key=keys.public_sign_key(key.key),
#     )


# def _core_key_info(keys: List[Key]) -> trcs.CoreKeys:
#     key_by_usage = {key.usage: _key_info(key) for key in keys}
#     return trcs.CoreKeys(
#         issuing_grant=key_by_usage[Key.TRC_ISSUING_GRANT],
#         voting_online=key_by_usage[Key.TRC_VOTING_ONLINE],
#         voting_offline=key_by_usage[Key.TRC_VOTING_OFFLINE],
#     )


def _can_update(isd):
    """
    All TRC updates must comply with the following:
    - The ISD identifier must not change.
    - The base identifier must not change.
    - noTrustReset must not change.
    - Votes must belong to sensitive or regular certificates present in the previous TRC.
    - The number of votes >= previous TRC votingQuorum.
    - Every "sensitive voting cert" and "regular voting cert" that are new in
        this TRC, attach a signature to the TRC.

    In SCIONLab we only need to worry about the quorum.
    """
    # prev = TRC.objects.filter(isd=isd).latest_or_none()
    prev = ISD.objects.get(isd_id=isd).trcs.latest_or_none()
    if prev is None:
        return False
    # get number of voters. I.e. core ASes in this ISD (all of them vote)
    return AS.objects.filter(isd__isd_id=isd, is_core=True).count() >= prev.quorum





def _voters(isd):
    """ returns the certificates that could vote a TRC """
    pass
