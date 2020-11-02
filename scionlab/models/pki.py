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
:mod:`scionlab.models.pki` --- Django models for SCION control plane PKI objects
================================================================================
"""

import textwrap
import jsonfield
from collections import namedtuple
from datetime import datetime, timezone
from typing import List

from django.db import models

from scionlab.defines import (
    DEFAULT_EXPIRATION_CORE_KEYS,
    DEFAULT_EXPIRATION_AS_KEYS,
    DEFAULT_TRC_GRACE_PERIOD,
)
from scionlab.scion import as_ids, keys, trcs, certs
from scionlab.util import flatten

_MAX_LEN_CHOICES_DEFAULT = 32
""" Max length value for choices fields without specific requirements to max length """

Validity = namedtuple("Validity", ["not_before", "not_after"])


def _key_set_null_or_cascade(collector, field, sub_objs, using):
    """
    on_delete callback for AS relation:
        - SET_NULL for keys with usage==TRC_VOTING_SENSITIVE
        - CASCADE for all others

    This "trick" is required to be able to use voting sensitive keys for the creation of a new TRC
    after an AS has been deleted.
    """
    sensitive = [key for key in sub_objs if key.usage == Key.TRC_VOTING_SENSITIVE]
    others = [key for key in sub_objs if key.usage != Key.TRC_VOTING_SENSITIVE]

    if sensitive:
        models.SET_NULL(collector, field, sensitive, using)
    if others:
        models.CASCADE(collector, field, others, using)


class KeyManager(models.Manager):
    def create(self, AS, usage, not_before=None, not_after=None):
        """
        Create a Key for this AS, for the given usage.
        :param AS AS:
        :param str usage: Key usage, one of Key.USAGES
        :param datetime not_before: start of validity, optional, default is now
        :param datetime not_after: end of validity, optional, default is not_before+DEFAULT_EXPIRAT.
        """
        not_before = not_before or datetime.utcnow()
        not_after = not_after or not_before + Key.default_expiration(usage)

        key = keys.encode_key(keys.generate_key())
        return super().create(
            AS=AS,
            _as_id_int=AS.as_id_int,
            usage=usage,
            version=Key.next_version(AS, usage),
            key=key,
            not_before=not_before,
            not_after=not_after
        )

    def latest(self, usage):
        """
        Return the latest key (highest version) for the given usage type.
        """
        return self.filter(usage=usage).latest('version')


class Key(models.Model):
    TRC_VOTING_SENSITIVE = "sensitive-voting"
    TRC_VOTING_REGULAR = "regular-voting"
    ISSUING_ROOT = "cp-root"
    ISSUING_CA = "cp-ca"
    CP_AS = "cp-as"  # control plane AS regular chain certificate

    USAGES = (
        TRC_VOTING_SENSITIVE,
        TRC_VOTING_REGULAR,
        ISSUING_ROOT,
        ISSUING_CA,
        CP_AS,
    )

    AS = models.ForeignKey(
        'AS',
        related_name='keys',
        on_delete=_key_set_null_or_cascade,
        editable=False,
        null=True,
    )
    _as_id_int = models.BigIntegerField(
        editable=False,
        help_text="Copy of AS.as_id_int."
    )

    usage = models.CharField(
        choices=list(zip(USAGES, USAGES)),
        max_length=_MAX_LEN_CHOICES_DEFAULT,
        editable=False,
    )
    version = models.PositiveIntegerField(editable=False)

    not_before = models.DateTimeField()
    not_after = models.DateTimeField()

    key = models.TextField(editable=False)  # key in PEM format

    objects = KeyManager()

    class Meta:
        unique_together = ('AS', 'usage', 'version')

    def __str__(self):
        return f"{self.as_id()}={self.usage}-{self.version}"

    @property
    def as_id(self) -> str:
        """
        Shortcut to AS.as_id.
        Returns the ASID stored directly on this Key object, in order to keep this information
        after deleting an AS.
        """
        return as_ids.format(self._as_id_int)

    def filename(self):
        return f"{self.usage}.key"

    def format_keyfile(self) -> str:
        """
        Create the PEM file content for this key.
        """
        return self.key  # already in PEM format

    @staticmethod
    def next_version(as_, usage):
        prev = as_.keys.filter(usage=usage).aggregate(models.Max('version'))['version__max'] or 0
        return prev + 1

    @staticmethod
    def default_expiration(usage):
        """
        Return the default expiration time for keys of the given usage.
        """
        if usage in [Key.TRC_VOTING_SENSITIVE,
                     Key.TRC_VOTING_REGULAR,
                     Key.ISSUING_ROOT,
                     Key.ISSUING_CA]:
            return DEFAULT_EXPIRATION_CORE_KEYS
        else:
            return DEFAULT_EXPIRATION_AS_KEYS


class CertificateManager(models.Manager):
    # TODO(juagargi) check if everytime we create a certificate, we also create a key.
    # is it then the same entity in disguise?
    def create(self):
        pass

    def create_voting_sensitive_cert(self, subject, not_before, not_after):
        """ Voting sensitive cert is self signed """
        return self._create_self_signed_cert(
            subject, not_before, not_after, Key.TRC_VOTING_SENSITIVE,
            certs.generate_voting_sensitive_certificate)

    def create_voting_regular_cert(self, subject, not_before, not_after):
        """ Voting regular cert is self signed """
        return self._create_self_signed_cert(
            subject, not_before, not_after, Key.TRC_VOTING_REGULAR,
            certs.generate_voting_regular_certificate)

    def create_issuer_root_cert(self, subject, not_before, not_after):
        """ Issuer root cert is self signed. It will also sign CA certs """
        return self._create_self_signed_cert(
            subject, not_before, not_after, Key.ISSUING_ROOT, certs.generate_issuer_root_certificate)

    def create_issuer_ca_cert(self, subject, not_before, not_after):
        """ A CA cert is signed by a root cert. For now, always from the same AS """
        subject_key = subject.keys.latest(usage=Key.ISSUING_CA)
        issuer_key = subject.keys.latest(usage=Key.ISSUING_ROOT)
        not_before, not_after = _validity(Validity(not_before, not_after), subject_key, issuer_key)
        return self._create_cert(
            certs.generate_as_certificate, subject_key, not_before, not_after, issuer_key)

    def create_as_cert(self, subject, issuer, not_before, not_after):
        """ An AS cert is signed by the CA cert of the issuer """
        subject_key = subject.keys.latest(usage=Key.CP_AS)
        issuer_key = issuer.keys.latest(usage=Key.ISSUING_CA)
        not_before, not_after = _validity(Validity(not_before, not_after), subject_key, issuer_key)
        return self._create_cert(
            certs.generate_as_certificate, subject_key, not_before, not_after, issuer_key)

    def latest(self, usage):
        return self.filter(key__usage=usage).latest('version')

    def _create_self_signed_cert(self, subject, not_before, not_after, usage, fcn):
        key = subject.keys.latest(usage=usage)
        not_before, not_after = _validity(Validity(not_before, not_after), key)
        return self._create_cert(fcn, key, not_before, not_after)

    def _create_cert(self, fcn, subject_key, not_before, not_after, issuer_key=None):
        """
        :param callable fcn The function from the certs package to call to generate the cert.
        :param Key issuer_key If it is None, then self signed.
        """
        subject_id = subject_key.AS.isd_as_str()
        not_before, not_after = _validity(Validity(not_before, not_after), subject_key)
        kwargs = {}
        if issuer_key is not None:
            not_before, not_after = _validity(Validity(not_before, not_after), issuer_key)
            kwargs = {"issuer_key": keys.decode_key(issuer_key.key),
                      "issuer_id": issuer_key.AS.isd_as_str()}

        cert = fcn(subject_id=subject_id,
                   subject_key=keys.decode_key(subject_key.key),
                   not_before=not_before,
                   not_after=not_after,
                   **kwargs)
        version = Certificate.next_version(subject_key.AS, subject_key.usage)
        cert = super().create(
            key=subject_key,
            version=version,
            not_before=not_before,
            not_after=not_after,
            certificate=certs.encode_certificate(cert),  # PEM encoded
        )
        cert.ca_cert = issuer_key.certificates.latest(issuer_key.usage) if issuer_key else cert
        return cert


class Certificate(models.Model):
    key = models.ForeignKey(
        Key,
        related_name="certificates",
        null=True,
        on_delete=models.CASCADE,
    )
    ca_cert = models.ForeignKey(  # the CA. If self signed, it will point to itself.
        "self",
        related_name='issued_certificates',
        on_delete=models.SET_NULL,  # if null, we know the CA cert was deleted
        null=True,
    )
    version = models.PositiveIntegerField()
    not_before = models.DateTimeField()
    not_after = models.DateTimeField()
    certificate = models.TextField(editable=False)  # in PEM format

    objects = CertificateManager()

    class Meta:
        unique_together = ("key", "version")

    def AS(self):
        return self.key.AS

    def usage(self):
        return self.key.usage

    def __str__(self):
        return self.filename()

    def filename(self):
        if self.usage() == Key.VOTING_SENSITIVE:
            suffix = ".sensitive.crt"
        elif self.usage() == Key.VOTING_REGULAR:
            suffix = ".regular.crt"
        elif self.usage() == Key.ISSUER_ROOT:
            suffix = ".root.crt"
        elif self.usage() == Key.ISSUER_CA:
            suffix = ".ca.crt"
        else:
            suffix = ".pem"
        return f"ISD{self.AS.isd.isd_id}-AS{self.AS.as_path_str()}{suffix}"

    def format_certfile(self) -> str:
        """
        Create the PEM file content for this certificate.
        AS certificates will return the whole chain: first the subject cert, then the issuer's one.
        """
        return self.certificate + (self.ca_cert.certificate if self.key.usage == Key.CP_AS else "")

    @staticmethod
    def next_version(as_, usage):
        prev = Certificate.objects.filter(key__AS=as_, key__usage=usage).aggregate(
            models.Max('version'))['version__max'] or 0
        return prev + 1


class TRCManager(models.Manager):
    def create(self, isd):
        """
        Create a TRC for this ISD.

        A TRC is "versioned" using a base number, and a serial number.

        All TRC updates must comply with the following:
        - The ISD identifier must not change.
        - noTrustReset must not change.
        - Votes must belong to sensitive or regular certificates present in the previous TRC.
        - The number of votes >= previous TRC votingQuorum.
        - Every "sensitive voting cert" and "regular voting cert" that are new in
          this TRC, attach a signature to the TRC.

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

        The update is sensitive if it is not regular.
        For sensitive TRC updates to be verifyable, they must contain votes
        only from sensitive certificates.




        The version is incremented from the previous TRC. The voting offline keys related to the
        previous TRC may be (precisely: for online key updates and sensitive updates) used to sign
        the new TRC.

        Requires at least one core AS in this ISD.

        The latest keys for all core ASes are used. The validity period for the TRC is determined
        based the validity of these keys.

        :param isd ISD:
        """

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
        return self.order_by("-version_base").latest("version_serial")

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

    # version = models.PositiveIntegerField(editable=False)
    version_base = models.PositiveIntegerField(editable=False, default=1)
    version_serial = models.PositiveIntegerField(editable=False, default=1)
    not_before = models.DateTimeField()
    not_after = models.DateTimeField()

    # trc = jsonfield.JSONField(editable=False)
    trc = models.BinaryField()  # in binary DER format

    # Sensitive voting keys are required to create the next TRC version for sensitive updates;
    # These keys are never deleted to ensure it is always possible to create a new TRC version, even
    # after removing _all_ core ASes of an ISD. (see also _key_set_null_or_cascade).
    # TODO(juagargi) should we reference the cert instead?
    voting_offline = models.ManyToManyField(
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
        unique_together = ('isd', 'version_base', 'version_serial')

    def __str__(self):
        return self.filename()

    def filename(self) -> str:
        return f"ISD{self.isd.isd_id}-B{self.version_base}-S{self.version_serial}"

    @staticmethod
    def next_version_base():
        prev = TRC.objects.aggregate(
            models.Max('version_base'))['version_base__max'] or 0
        return prev + 1

    @staticmethod
    def next_version_serial():
        prev = TRC.objects.aggregate(
            models.Max('version_serial'))['version_serial__max'] or 0
        return prev + 1


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


def _validity(*vs):
    """
    Return the intersection of the validity periods for the given inputs.
    :param vs: iterable of objects with `not_before` and `not_after` datetime members
    """
    not_before = max(v.not_before for v in vs)
    not_after = min(v.not_after for v in vs)
    return not_before, not_after
