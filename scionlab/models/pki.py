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
import jsonfield
from typing import List

from django.db import models

from scionlab.defines import (
    DEFAULT_EXPIRATION,
    DEFAULT_TRC_GRACE_PERIOD,
)
from scionlab.scion import keys, trcs, certs

_MAX_LEN_CHOICES_DEFAULT = 16
""" Max length value for choices fields without specific requirements to max length """
_MAX_LEN_KEYS = 255
""" Max length value for base64 encoded AS keys """


class KeyManager(models.Manager):
    def create(self, AS, usage, version=None, not_before=None, not_after=None):
        version = version or Key.next_version(AS, usage)

        not_before = not_before or datetime.utcnow()
        not_after = not_after or not_before + DEFAULT_EXPIRATION  # TODO(matzf) expiration for different key types

        if usage == Key.DECRYPT:
            key = keys.generate_enc_key()
        else:
            key = keys.generate_sign_key()

        return super().create(
            AS=AS,
            usage=usage,
            version=version,
            key=key,
            not_before=not_before,
            not_after=not_after
        )

    def latest(self, usage):
        return self.filter(usage=usage).latest('version')


class Key(models.Model):
    DECRYPT = 'as-decrypt'
    # REVOCATION = 'as-revocation'  # Not currently used by SCIONLab
    SIGNING = 'as-signing'
    CERT_SIGNING = 'as-cert-signing'
    TRC_ISSUING_GRANT = 'trc-issuing-grant'
    TRC_VOTING_ONLINE = 'trc-voting-online'
    TRC_VOTING_OFFLINE = 'trc-voting-offline'

    USAGES = (
        DECRYPT,
        SIGNING,
        CERT_SIGNING,
        TRC_ISSUING_GRANT,
        TRC_VOTING_ONLINE,
        TRC_VOTING_OFFLINE,
    )

    AS = models.ForeignKey(
        'AS',
        related_name='keys',
        on_delete=models.CASCADE,
        editable=False,
    )

    usage = models.CharField(
        choices=list(zip(USAGES, USAGES)),
        max_length=_MAX_LEN_CHOICES_DEFAULT,
        editable=False,
    )
    version = models.PositiveIntegerField(editable=False)
    not_before = models.DateTimeField()
    not_after = models.DateTimeField()

    key = models.CharField(max_length=_MAX_LEN_KEYS, editable=False)

    objects = KeyManager()

    class Meta:
        unique_together = ('AS', 'usage', 'version')

    def __str__(self):
        return self.filename()

    def filename(self):
        return "%s-v%i.key" % (self.usage, self.version)

    def format_keyfile(self) -> str:
        """
        -----BEGIN PRIVATE KEY-----
        algorithm: {algo}
        ia: {ia}
        not_after: {not_before}
        not_before: {not_after}
        usage: {usage}
        version: {version}

        {key}
        -----END PRIVATE KEY-----
        """.format(
            algo=self.algorithm(),
            ia=self.AS.isd_as_str(),
            not_after=self.not_after,
            not_before=self.not_before,
            usage=self.usage,
            version=self.version,
            key=self.key
        )

    def algorithm(self):
        """
        Return the algorithm corresponding to this key, in the format expected for the .key file
        """
        if self.is_encryption_key():
            return 'curve25519xsalsa20poly1305'
        else:
            return 'ed25519'

    def is_encryption_key(self):
        """
        Returns True iff this is an encryption key. Otherwise, this is a signing key.
        """
        return self.usage == Key.DECRYPT

    @staticmethod
    def next_version(as_, usage):
        return as_.keys.filter(usage=usage).count() + 1 # BUG XXX


class TRCManager(models.Manager):
    def create(self, isd):

        prev = self.latest(isd)

        if prev:
            version = prev.version + 1
            prev_trc = prev.trc
            prev_voting_offline = {key.AS.as_id: _key_info(key)
                                   for key in prev.voting_offline.all()}
        else:
            version = 1
            prev_trc = None
            prev_voting_offline = None

        keys = {as_.as_id: _latest_core_keys(as_) for as_ in isd.ases.filter(is_core=True)}
        all_keys = sum(keys.values(), [])

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

    def latest(self, isd):
        if not self.filter(isd=isd).exists():
            return None
        return self.filter(isd=isd).latest('version')


class TRC(models.Model):
    isd = models.ForeignKey(
        'ISD',
        related_name='trcs',
        on_delete=models.CASCADE,
        verbose_name='ISD'
    )

    version = models.PositiveIntegerField(editable=False)
    not_before = models.DateTimeField()
    not_after = models.DateTimeField()

    trc = jsonfield.JSONField(editable=False)

    # TODO(matzf) o-oh, cannot delete core ASes, ever.
    # Maybe a solution can be on_delete=models.SET() on Key, which
    # could, for offline keys, null the AS relation and store the
    # as_id in a separate field. Bah.
    voting_offline = models.ManyToManyField(
        Key,
    )

    objects = TRCManager()

    class Meta:
        verbose_name = 'TRC'
        verbose_name_plural = 'TRCs'

    def __str__(self):
        return self.filename()

    def filename(self) -> str:
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


class CertificateManager(models.Manager):
    # XXX(matzf): change the create functions so they can be called on the reverse relation manager?
    def create_issuer_cert(self, as_):
        version = Certificate.next_version(as_, Certificate.ISSUER)

        trc = TRC.objects.latest(as_.isd)
        issuer_key = as_.keys.latest(usage=Key.CERT_SIGNING)
        issuing_grant = as_.keys.latest(usage=Key.TRC_ISSUING_GRANT)

        not_before, not_after = _validity([issuer_key, issuing_grant, trc])

        cert = certs.generate_issuer_certificate(as_, version, trc, not_before, not_after,
                                                 issuing_grant, issuer_key)

        return super().create(
            AS=as_,
            type=Certificate.ISSUER,
            version=version,
            not_before=not_before,
            not_after=not_after,
            certificate=cert
        )

    def create_as_cert(self, subject, issuer):
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
    ISSUER = 'issuer'
    CHAIN = 'chain'  # AS certificates are a certificate chain

    TYPES = (
        ISSUER,
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

    certificate = jsonfield.JSONField()

    objects = CertificateManager()

    def __str__(self):
        return self.filename()

    def filename(self):
        return "ISD%i-AS%s-V%i.crt" % (self.AS.isd.isd_id, self.AS.as_id, self.version)

    @staticmethod
    def next_version(as_, type):
        return as_.certificates.filter(type=type).count() + 1  # BUG XXX


def _validity(vs):
    not_before = max(v.not_before for v in vs)
    not_after = min(v.not_after for v in vs)
    return not_before, not_after