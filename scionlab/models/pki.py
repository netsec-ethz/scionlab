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
from django.db.models import Q

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
        - SET_NULL for keys that have a cert sensitive signing a TRC
        - CASCADE for all others

    This "trick" is required to be able to use voting sensitive keys for the creation of a new TRC
    after an AS has been deleted.
    We use the callback on the Key.on_delete because Key is an intermediate model between
    Certificate and AS, and simplifies checking membership on the cert.trc_voted_sensitive.
    See also: test_pki:CertificateTests.test_delete_while_sensitive_voted
    """
    sensitive = [key for key in sub_objs if key.certificates.exclude(trc_included__isnull=True)
                 .filter(key__usage=Key.TRC_VOTING_SENSITIVE)]
    others = [key for key in sub_objs if key not in sensitive]

    if sensitive:
        models.SET_NULL(collector, field, sensitive, using)
    if others:
        models.CASCADE(collector, field, others, using)


class KeyManager(models.Manager):
    def create_all_keys(self, AS, not_before=None, not_after=None):
        return self.create_core_keys(AS, not_before, not_after) + [
            self.create(AS, Key.CP_AS, not_before, not_after)]

    def create_core_keys(self, AS, not_before=None, not_after=None):
        return [self.create(AS, usage, not_before, not_after) for usage in [
            Key.TRC_VOTING_SENSITIVE,
            Key.TRC_VOTING_REGULAR,
            Key.ISSUING_ROOT,
            Key.ISSUING_CA]]

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

        key = keys.encode_key(keys.generate_key()).decode("ascii")
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
        return f"{self.as_id}={self.usage}-{self.version}"

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
    def create_all_certs(self, subject, not_before=None, not_after=None):
        certs = self.create_core_certs(subject, not_before, not_after)
        assert certs[-1].key.usage == Key.ISSUING_CA
        return certs + [self.create_as_cert(subject, certs[-1].key.AS, not_before, not_after)]

    def create_core_certs(self, subject, not_before=None, not_after=None):
        return [f(subject, not_before, not_after)
                for f in [self.create_voting_sensitive_cert,
                          self.create_voting_regular_cert,
                          self.create_issuer_root_cert,
                          self.create_issuer_ca_cert]]

    def create_voting_sensitive_cert(self, subject, not_before=None, not_after=None):
        """ Voting sensitive cert is self signed """
        return self._create_self_signed_cert(
            subject, not_before, not_after, Key.TRC_VOTING_SENSITIVE,
            certs.generate_voting_sensitive_certificate)

    def create_voting_regular_cert(self, subject, not_before=None, not_after=None):
        """ Voting regular cert is self signed """
        return self._create_self_signed_cert(
            subject, not_before, not_after, Key.TRC_VOTING_REGULAR,
            certs.generate_voting_regular_certificate)

    def create_issuer_root_cert(self, subject, not_before=None, not_after=None):
        """ Issuer root cert is self signed. It will also sign CA certs """
        return self._create_self_signed_cert(subject, not_before, not_after, Key.ISSUING_ROOT,
                                             certs.generate_issuer_root_certificate)

    def create_issuer_ca_cert(self, subject, not_before=None, not_after=None):
        """ A CA cert is signed by a root cert. For now, always from the same AS """
        subject_key = subject.keys.latest(usage=Key.ISSUING_CA)
        issuer_key = subject.keys.latest(usage=Key.ISSUING_ROOT)
        not_before, not_after = _validity(Validity(not_before, not_after), subject_key, issuer_key)
        return self._create_cert(
            certs.generate_as_certificate, subject_key, not_before, not_after, issuer_key)

    def create_as_cert(self, subject, issuer, not_before=None, not_after=None):
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
            kwargs = {"issuer_key": keys.decode_key(issuer_key.key.encode("ascii")),
                      "issuer_id": issuer_key.AS.isd_as_str()}

        cert = fcn(subject_id=subject_id,
                   subject_key=keys.decode_key(subject_key.key.encode("ascii")),
                   not_before=not_before,
                   not_after=not_after,
                   **kwargs)
        version = Certificate.next_version(subject_key.AS, subject_key.usage)
        cert = super().create(
            key=subject_key,
            version=version,
            not_before=not_before,
            not_after=not_after,
            certificate=certs.encode_certificate(cert).decode("ascii"),  # PEM encoded
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
        if self.usage() == Key.TRC_VOTING_SENSITIVE:
            suffix = ".sensitive.crt"
        elif self.usage() == Key.TRC_VOTING_REGULAR:
            suffix = ".regular.crt"
        elif self.usage() == Key.ISSUING_ROOT:
            suffix = ".root.crt"
        elif self.usage() == Key.ISSUING_CA:
            suffix = ".ca.crt"
        else:
            suffix = ".pem"
        return f"ISD{self.key.AS.isd.isd_id}-AS{self.key.AS.as_path_str()}{suffix}"

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


def _validity(*vs):
    """
    Return the intersection of the validity periods for the given inputs.
    :param vs: iterable of objects with `not_before` and `not_after` datetime members
    """
    not_before = max(v.not_before for v in vs if v.not_before)
    not_after = min(v.not_after for v in vs if v.not_after)
    return not_before, not_after
