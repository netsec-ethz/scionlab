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
from datetime import datetime, timezone
import jsonfield
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
    CP_ROOT = "cp-root"
    CP_CA = "cp-ca"
    CP_AS = "cp-as"

    USAGES = (
        TRC_VOTING_SENSITIVE,
        TRC_VOTING_REGULAR,
        CP_ROOT,
        CP_CA,
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
        prev = as_.keys.filter(usage=usage).aggregate(models.Max('version'))['version__max']
        return (prev or 0) + 1

    @staticmethod
    def default_expiration(usage):
        """
        Return the default expiration time for keys of the given usage.
        """
        if usage in [Key.TRC_VOTING_SENSITIVE,
                     Key.TRC_VOTING_REGULAR,
                     Key.CP_ROOT,
                     Key.CP_CA]:
            return DEFAULT_EXPIRATION_CORE_KEYS
        else:
            return DEFAULT_EXPIRATION_AS_KEYS


class CertificateManager(models.Manager):
    def create(self, AS, type, *args, **kwargs):
        """
        Create issuer certificate or AS certificate chain, depending on type.
        When creating an AS certificate chains, an `issuer` AS with an existing issuer certificate
        must be given.
        """
        if type == Certificate.ISSUER:
            self.create_issuer_cert(AS, *args, **kwargs)
        else:
            assert type == Certificate.CHAIN
            self.create_as_cert(AS, *args, **kwargs)

    # def create_issuer_cert(self, as_):
    def create_issuer_cert(self, as_, not_before, not_after):
        """
        Create an issuer certificate for this AS.

        An CA AS in SCIONLab has both the root and the CA certificates.
        A root certificate is used to sign a CA certificate.
        A CA certificate is used to sign an AS certificate.
        When creating / modifying a root certificate, a new TRC must be issued.
        """
        # version = Certificate.next_version(as_, Certificate.ISSUER)

        # trc = as_.isd.trcs.latest()
        # issuer_key = as_.keys.latest(usage=Key.CERT_SIGNING)
        # issuing_grant = as_.keys.latest(usage=Key.TRC_ISSUING_GRANT)

        # not_before, not_after = _validity([issuer_key, issuing_grant, trc])

        # cert = certs.generate_issuer_certificate(as_, version, trc, not_before, not_after,
        #                                          issuing_grant, issuer_key)

        cert, key = certs.generate_issuer_root_certificate(as_, not_before, not_after)

        return super().create(
            AS=as_,
            type=Certificate.ISSUER,
            version=version,
            not_before=not_before,
            not_after=not_after,
            certificate=cert
        )

    def create_as_cert(self, subject, issuer):
        """
        Create an AS certificate chain for the subject AS.

        Uses the latest cert signing key and issuer certificate of the issuer AS (i.e. assumes that
        these match) to sign a certificate for the latest encryption and signing key of the subject
        AS.
        The validity period is defined by the validity of these input keys.
        """
        version = Certificate.next_version(subject, Certificate.CHAIN)

        encryption_key = subject.keys.latest(usage=Key.DECRYPT)
        signing_key = subject.keys.latest(usage=Key.SIGNING)
        issuer_key = issuer.keys.latest(usage=Key.CERT_SIGNING)
        issuer_cert = issuer.certificates.latest(type=Certificate.ISSUER)

        not_before, not_after = _validity([encryption_key, signing_key, issuer_cert])

        cert = certs.generate_as_certificate(subject, version, not_before, not_after,
                                             encryption_key, signing_key,
                                             issuer, issuer_cert, issuer_key)

        return super().create(
            AS=subject,
            type=Certificate.CHAIN,
            version=version,
            not_before=not_before,
            not_after=not_after,
            certificate=cert
        )

    def latest(self, type):
        return self.filter(type=type).latest('version')


class Certificate(models.Model):
    VOTING_SENSITIVE = 'voting_sensitive'
    VOTING_REGULAR = 'voting_regular'
    ISSUER_ROOT = 'issuer_root'
    ISSUER_CA = 'issuer_ca'
    CHAIN = 'chain'  # AS certificates are a certificate chain

    TYPES = (
        # ISSUER,
        VOTING_SENSITIVE,
        VOTING_REGULAR,
        ISSUER_ROOT,
        ISSUER_CA,
        CHAIN,
    )

    AS = models.ForeignKey(
        'AS',
        related_name='certificates',
        on_delete=models.CASCADE,
    )

    type = models.CharField(
        choices=list(zip(TYPES, TYPES)),
        max_length=_MAX_LEN_CHOICES_DEFAULT,
        editable=False,
    )
    version = models.PositiveIntegerField()
    not_before = models.DateTimeField()
    not_after = models.DateTimeField()

    # certificate = jsonfield.JSONField()
    certificate = models.BinaryField()

    objects = CertificateManager()

    class Meta:
        unique_together = ('AS', 'type', 'version')

    def __str__(self):
        return self.filename()

    def filename(self):
        # TODO(juagargi) change to use the version_base version_serial
        # return "ISD%i-AS%s-V%i.crt" % (self.AS.isd.isd_id, self.AS.as_path_str(), self.version)
        if self.type == Certificate.VOTING_SENSITIVE:
            suffix = ".sensitive"
        elif self.type == Certificate.VOTING_REGULAR:
            suffix = ".regular"
        elif self.type == Certificate.ISSUER_ROOT:
            suffix = ".root"
        elif self.type == Certificate.ISSUER_CA:
            suffix = ".ca"
        else:
            suffix = ""
        return f"ISD{self.AS.isd.isd_id}-AS{self.AS.as_path_str()}{suffix}"

    @staticmethod
    def next_version(as_, type):
        prev = as_.certificates.filter(type=type).aggregate(models.Max('version'))['version__max']
        if prev:
            return prev + 1
        else:
            return 1


class TRCManager(models.Manager):
    def create(self, isd):
        """
        Create a TRC for this ISD.

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
        return super().latest('version')

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

    version = models.PositiveIntegerField(editable=False)
    # version_base = models.PositiveIntegerField(editable=False, default=1)
    # version_serial = models.PositiveIntegerField(editable=False, default=1)
    not_before = models.DateTimeField()
    not_after = models.DateTimeField()

    trc = jsonfield.JSONField(editable=False)

    # Offline voting keys required to create the next TRC version for sensitive updates;
    # These keys are never deleted to ensure it is always possible to create a new TRC version, even
    # after removing _all_ core ASes of an ISD. (see also _key_set_null_or_cascade).
    voting_offline = models.ManyToManyField(
        Key,
    )

    objects = TRCManager()

    class Meta:
        verbose_name = 'TRC'
        verbose_name_plural = 'TRCs'
        unique_together = ('isd', 'version')

    def __str__(self):
        return self.filename()

    def filename(self) -> str:
        # TODO(juagargi) change to use the version_base version_serial
        return 'ISD%i-V%i.trc' % (self.isd.isd_id, self.version)


def _latest_core_keys(as_) -> List[Key]:
    return [
        as_.keys.latest(Key.TRC_ISSUING_GRANT),
        as_.keys.latest(Key.TRC_VOTING_ONLINE),
        as_.keys.latest(Key.TRC_VOTING_OFFLINE),
    ]


def _key_info(key: Key) -> trcs.Key:
    return trcs.Key(
        version=key.version,
        priv_key=key.key,
        pub_key=keys.public_sign_key(key.key),
    )


def _core_key_info(keys: List[Key]) -> trcs.CoreKeys:
    key_by_usage = {key.usage: _key_info(key) for key in keys}
    return trcs.CoreKeys(
        issuing_grant=key_by_usage[Key.TRC_ISSUING_GRANT],
        voting_online=key_by_usage[Key.TRC_VOTING_ONLINE],
        voting_offline=key_by_usage[Key.TRC_VOTING_OFFLINE],
    )


def _validity(vs):
    """
    Return the intersection of the validity periods for the given inputs.
    :param vs: iterable of objects with `not_before` and `not_after` datetime members
    """
    not_before = max(v.not_before for v in vs)
    not_after = min(v.not_after for v in vs)
    return not_before, not_after
