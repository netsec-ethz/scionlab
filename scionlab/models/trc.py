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

from collections import defaultdict
from django.db import models

from scionlab.defines import DEFAULT_TRC_GRACE_PERIOD
from scionlab.models.core import AS
from scionlab.models.pki import Certificate, Key, validity
from scionlab.scion import trcs


class TRCManager(models.Manager):
    def create(self, isd):
        """
        Create a TRC for this ISD.

        It will attempt to update the TRC in the lightest way possible. That is, first attempt to
        have a regular update. If not possible, try a sensitive update.
        Last, go and create a base TRC, without update.

        A base TRC breaks the chain of trust, and cannot be verified from the existing material.
        Typically this means that a base TRC has to be copied to the ASes, so that the trust
        is placed manually.

        For sensitive TRC updates to be verifyable, they must contain votes
        only from sensitive certificates.

        The serial (version) is incremented from the previous TRC.

        In SCIONLab, authoritative ASes = core ASes = CA ASes.

        Requires at least one core AS in this ISD.

        The latest certificates for all core ASes are used. The validity period for the TRC
        is determined based on the validity of these certificates.

        :param isd ISD object.
        """
        prev = isd.trcs.latest_or_none()
        serial = prev.serial_version + 1 if prev else 1
        core_ases = AS.objects.filter(isd=isd, is_core=True)
        quorum = len(core_ases) // 2 + 1
        certificates = _coreas_certificates(isd)
        if len(core_ases) == 0:
            raise RuntimeError("no core ASes found")

        if _can_update(isd):
            base = prev.base_version
            if not _is_regular_update_prevented(prev, quorum, core_ases, certificates):
                # find compatible voters and signers:
                # votes will be the subset of regular certs of the prev. trc
                votes = prev.certificates.filter(key__usage=Key.TRC_VOTING_REGULAR)
                changed_root_certs = certificates.filter(key__usage=Key.ISSUING_ROOT)\
                    .difference(prev.certificates.all())
                signers = votes | changed_root_certs
            else:
                votes = prev.certificates.filter(key__usage=Key.TRC_VOTING_SENSITIVE)
                added_core_certs = certificates.filter(key__usage__in=[
                    Key.TRC_VOTING_SENSITIVE, Key.TRC_VOTING_REGULAR]).difference(
                        prev.certificates.filter())
                signers = votes.union(added_core_certs)
            # prepare to check that there exists a non-empty validity window:
            not_before, not_after = validity(*[*certificates, *signers])
            if (not_after - not_before).total_seconds() <= 0:
                # fall back to a base TRC
                base = serial
        else:
            base = serial

        if base == serial:  # base TRC: either we can't update or there was no validity window
            prev = None
            votes = Certificate.objects.none()
            signers = certificates.filter(key__usage__in=[
                Key.TRC_VOTING_SENSITIVE, Key.TRC_VOTING_REGULAR])
            not_before, not_after = validity(*[*certificates])  # "certificates" covers everything

        votes_idx = prev.get_certificate_indices(votes) if prev else []

        trc = trcs.generate_trc(
            prev_trc=trcs.decode_trc(prev.trc) if prev else None,
            isd_id=isd.isd_id,
            base=base,
            serial=serial,
            primary_ases=[c.as_id for c in core_ases],
            quorum=quorum,
            votes=votes_idx,
            grace_period=DEFAULT_TRC_GRACE_PERIOD,
            not_before=not_before,
            not_after=not_after,
            certificates=[c.certificate for c in certificates],
            signers_certs=[s.certificate for s in signers],
            signers_keys=[s.key.key for s in signers],
        )
        obj = super().create(isd=isd, serial_version=serial, base_version=base,
                             not_before=not_before, not_after=not_after,
                             quorum=quorum, trc=trcs.encode_trc(trc))
        obj.core_ases.set(core_ases)
        obj.add_certificates(certificates)
        obj.votes.set(votes)
        obj.signatures.set(signers)

        return obj

    def latest(self):
        """ there could be more than one TRC with the same serial, but the latest is the one
        that has its base the further in the sequence """
        return super().latest("serial_version", "base_version")

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
    serial_version = models.PositiveIntegerField(editable=False, default=1)
    # the base version points at the serial which represents the anchor of an update chain.
    # when the base version is equal to the serial version, this TRC is the anchor, and
    # there is no update, but a creation from scratch.
    base_version = models.PositiveIntegerField(editable=False, default=1)

    not_before = models.DateTimeField()
    not_after = models.DateTimeField()

    # in scionlab, core ASes == authoritative ASes.
    core_ases = models.ManyToManyField(
        AS,
        related_name="trcs_attesting_core_as"
    )

    # List of sensitive, regular, and root certificates.
    # Sensitive voting certs and keys are required to create the next TRC version for
    # sensitive updates. These certs and keys are never deleted to ensure it is always possible
    # to create a new TRC version, even after removing _all_ core ASes of an ISD.
    # See also _key_set_null_or_cascade
    certificates = models.ManyToManyField(
        Certificate,
        through="CertificateInTRC",
        related_name="trc_included",
    )

    quorum = models.PositiveIntegerField(
        default=1,
    )

    # The votes refer to certificates that where present in the previous TRC.
    # Every voter must also include their signature in the final TRC.
    votes = models.ManyToManyField(
        Certificate,
        related_name="trc_votes",
    )

    # certificates signing this TRC. They could be sensitive or regular.
    # We could also have root certs. signing the TRC, in case of a regular update,
    # if the root certificate is changed in the update.
    # See also can_update_regular
    signatures = models.ManyToManyField(
        Certificate,
        related_name="trc_signatures",
    )

    trc = models.TextField(editable=False)  # in DER format, base64 encoded

    objects = TRCManager()

    class Meta:
        verbose_name = 'TRC'
        verbose_name_plural = 'TRCs'
        unique_together = ('isd', 'serial_version', 'base_version')

    def add_core_as(self, AS):
        """ adds the AS to the core ases list, and its certificates to the cert. list """
        certs = []
        for usage in [Key.TRC_VOTING_SENSITIVE, Key.TRC_VOTING_REGULAR, Key.ISSUING_ROOT]:
            certs.append(Certificate.objects.latest(usage, AS))
        self.core_ases.add(AS)
        self.add_certificates(certs)
        self.quorum = self.core_ases.count() // 2 + 1

    def get_certificates(self):
        """ returns the list of certificates ordered by their index """
        return (cert_in_trc.certificate for cert_in_trc in
                self.certificateintrc_set.order_by("index"))

    def add_certificates(self, certs):
        count = self.certificates.count()
        for i, c in enumerate(certs):
            CertificateInTRC.objects.create(trc=self, certificate=c,
                                            index=count + i)

    def set_certificates(self, certs):
        self.certificates.clear()
        self.add_certificates(certs)

    def del_certificates(self, certs):
        # simply reset the certificate list:
        self.set_certificates([c for c in self.get_certificates() if c not in set(certs)])

    def add_vote(self, cert_in_prev_trc):
        """ cert_in_prev_trc must be an object in the prev_trc.certificates """
        self.votes.add(cert_in_prev_trc)

    def get_voters_indices(self):
        """ uses the certificate indices of the previous TRC to indicate who voted """
        prev = self.predecessor_trc_or_none()
        if prev is None:
            return None
        return prev.get_certificate_indices(self.votes.iterator())

    def get_certificate_indices(self, certs):
        """ returns the indices of the certs argument """
        return list(self.certificateintrc_set.filter(certificate__in=certs)
                    .order_by("index").values_list("index", flat=True))

    def __str__(self):
        return self.filename()

    def filename(self) -> str:
        return f"ISD{self.isd.isd_id}-B{self.base_version}-S{self.serial_version}"

    def update_regular_impossible(self):
        """
        Check if this TRC could do a regular TRC update (as opposed to a sensitive one).
        Returns None if all okay, and the error message otherwise.

        It is a regular update if:
        - _is_regular_update_prevented returns False. It checks:
            - The voting quorum does not change.
            - The core ASes section does not change.
            - The authoritative ASes section does not change.
            - The number of sensitive, regular and root certificates does not change.
            - The set of sensitive certificates does not change.
        - For every regular certificate that changes, the regular certificate in the previous
            TRC is part of the voters of the new TRC.
        - For every root certificate that changes, the root certificate in the previous TRC
            attaches a signature to the new TRC.
        For regular TRC updates to be verifiable, they must contain votes
        only from regular certificates.
        """
        prev = self.predecessor_trc_or_none()
        if prev is None or prev == self:
            return "no previous TRC"
        msg = _is_regular_update_prevented(prev, self.quorum, self.core_ases, self.certificates)
        if msg is not None:
            return msg
        # For every Regular Voting Certificate that changes, the Regular Voting Certificate
        # in the predecessor TRC is part of the voters on the successor TRC.
        msg = _validate_old_regular_votes(prev, self)
        if msg is not None:
            return msg
        # check root certificates
        # For every CP Root Certificate that changes, the CP Root Certificate in the
        # predecessor TRC attaches a signature to the signed successor TRC.
        msg = _validate_compatible_root(prev, self)
        if msg is not None:
            return msg
        return None

    def predecessor_trc_or_none(self):
        """
        Finds and returns the predecessor (anchor) TRC. If this is a base TRC, it returns "self".
        Returns None iff there is a gap in the TRC serial sequence.
        """
        if self.base_version == self.serial_version:
            return self
        prev = TRC.objects.filter(isd=self.isd, serial_version=self.serial_version - 1)
        return prev.get() if prev.exists() else None


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

    In SCIONLab we only need to worry about the previous TRC.
    Still, it is possible to try to update a prev. TRC with new certificates, and get
    an empty validity window. In this case, no update will be performed.
    That empty validity window has to be checked at the caller of this function.
    """
    return isd.trcs.latest_or_none() is not None


def _can_regular_update(prev, quorum, core_ases, certificates):
    return not _is_regular_update_prevented(prev, quorum, core_ases, certificates)


def _is_regular_update_prevented(prev_trc, quorum, core_ases, certificates):
    """
    Returns False if a regular update could be performed.
    Returns a string message with the reason, otherwise.

    There can be a regular update if:
        - The voting quorum does not change.
        - The core ASes section does not change.
        - The authoritative ASes section does not change.
        - The number of sensitive, regular and root certificates does not change.
        - The set of sensitive certificates does not change.

    Some more conditions must hold as well.
    See also update_regular_impossible
    """
    if prev_trc.quorum != quorum:
        return "different quorum"
    # check core, authoritative ASes section (they are treated the same in SCIONLab):
    if set(prev_trc.core_ases.all()) != set(core_ases.all()):
        return "different core section"
    # number of sensitive, regular and root certificates is the same
    msg = _validate_compatible_certificates(prev_trc.certificates, certificates)
    if msg is not None:
        return msg
    # check sensitive voting certificate set:
    prev_sensitive = prev_trc.certificates.filter(key__usage=Key.TRC_VOTING_SENSITIVE)
    if prev_sensitive.intersection(certificates.filter(key__usage=Key.TRC_VOTING_SENSITIVE
                                                       )).count() != prev_sensitive.count():
        return "different sensitive voters certificates"
    return None


def _validate_compatible_certificates(prev_certs, this_certs):
    """ checks that the certificates are the same, or have the same DN """
    for usage in [Key.TRC_VOTING_SENSITIVE, Key.TRC_VOTING_REGULAR, Key.ISSUING_ROOT]:
        prev = prev_certs.filter(key__usage=usage)
        this = this_certs.filter(key__usage=usage)
        if prev.count() != this.count():
            return f"different number of certificates for {usage}"
        prev_ases = AS.objects.filter(pk__in=prev.values("key__AS")).order_by("pk")
        this_ases = AS.objects.filter(pk__in=this.values("key__AS")).order_by("pk")
        if list(prev_ases) != list(this_ases):
            return f"different distinguished name in certs. for {usage}"


def _validate_old_regular_votes(prev, this):
    diff = prev.certificates.filter(key__usage=Key.TRC_VOTING_REGULAR).difference(
        this.certificates.all())
    if this.votes.intersection(diff).count() != diff.count():
        return "regular voting certificate changed and old one not part of voters"


def _validate_compatible_root(prev, this):
    diff = this.certificates.filter(key__usage=Key.ISSUING_ROOT).difference(prev.certificates.all())
    if this.signatures.all().intersection(diff).count() != diff.count():
        return "changed root certificates are not signing the TRC"


def _coreas_certificates(isd):
    """ returns a queryset of the sensitive, regular and root certificates for all core ASes """
    certs = Certificate.objects.filter(key__AS__isd=isd).filter(key__usage__in=[
        Key.TRC_VOTING_SENSITIVE, Key.TRC_VOTING_REGULAR, Key.ISSUING_ROOT]
        ).filter(key__AS__is_core=True)
    # group them by [usage], [AS], annotate ( max(version) , certificate )
    dcerts = defaultdict(lambda: defaultdict(lambda: (0, None)))
    for cert in certs:
        stored_ver = dcerts[cert.key.usage][cert.key.AS.pk][0]
        if cert.version > stored_ver:  # replace this cert with the newer one
            dcerts[cert.key.usage][cert.key.AS.pk] = (cert.version, cert.pk)
    return Certificate.objects.filter(pk__in=[tup[1]
                                      for per_as in dcerts.values()
                                      for tup in per_as.values()])
