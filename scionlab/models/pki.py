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

import datetime
import jsonfield
from typing import List

from django.db import models

from scionlab.models.core import (
    AS,
    ISD,
)
from scionlab.defines import (
    DEFAULT_EXPIRATION,
    DEFAULT_TRC_GRACE_PERIOD,
)
from scionlab.scion import keys, trcs

_MAX_LEN_CHOICES_DEFAULT = 16
""" Max length value for choices fields without specific requirements to max length """
_MAX_LEN_KEYS = 255
""" Max length value for base64 encoded AS keys """


class KeyManager(models.Manager):
    def create(self, AS, usage, version=None, not_before=None, not_after=None):
        version = version or Key.next_version(AS, usage)

        not_before = not_before or datetime.datetime.now()
        not_after = not_after or not_before + DEFAULT_EXPIRATION

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
    REVOCATION = 'as-revocation'
    SIGNING = 'as-signing'
    CERT_SIGNING = 'as-cert-signing'
    TRC_ISSUING_GRANT = 'trc-issuing-grant'
    TRC_VOTING_ONLINE = 'trc-voting-online'
    TRC_VOTING_OFFLINE = 'trc-voting-offline'

    USAGES = (
        DECRYPT,
        REVOCATION,
        SIGNING,
        CERT_SIGNING,
        TRC_ISSUING_GRANT,
        TRC_VOTING_ONLINE,
        TRC_VOTING_OFFLINE,
    )

    AS = models.ForeignKey(
        AS,
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

    key = models.CharField(max_length=_MAX_LEN_KEYS, editable=False)
    not_before = models.DateField()
    not_after = models.DateField()

    objects = KeyManager()

    class Meta:
        unique_together = ('AS', 'usage', 'version')

    def __str__(self):
        return "%s-v%i.key" % (self.usage, self.version)

    @staticmethod
    def next_version(as_, usage):
        if as_.pk:
            return Key.objects.filter(AS=as_, usage=usage).count() + 1
        else:
            return 1


class TRCManager(models.Manager):
    def create(self, isd, version, grace_period):

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
        not_before = max(key.not_before for key in all_keys)
        not_after = min(key.not_after for key in all_keys)

        primary_ases = {as_id: _core_key_info(as_keys) for as_id, as_keys in keys}

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

        return super().create(
            isd=isd,
            version=version,
            trc=trc,
            voting_offline=voting_offline,
        )

    def latest(self, isd):
        return self.filter(isd=isd).latest('version')


class TRC(models.Model):
    isd = models.ForeignKey(
        ISD,
        related_name='trcs',
        on_delete=models.CASCADE,
        verbose_name='ISD'
    )

    version = models.PositiveIntegerField(editable=False)

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


def _latest_core_keys(as_: AS) -> List[Key]:
    return [
        as_.keys.latest(Key.TRC_ISSUING_GRANT),
        as_.keys.latest(Key.TRC_VOTING_ONLINE),
        as_.keys.latest(Key.TRC_VOTING_OFFLINE),
    ]


def _key_info(key: Key):
    return trcs.Key(
        version=key.version,
        priv_key=key.key,
        pub_key=keys.public_sign_key(key.key),
    )


def _core_key_info(keys: List[Key]):
    key_by_usage = {key.usage: key for key in keys}
    return trcs.CoreKeys(
        issuing_grant=key_by_usage[Key.TRC_ISSUING_GRANT],
        voting_online=key_by_usage[Key.TRC_VOTING_ONLINE],
        voting_offline=key_by_usage[Key.TRC_VOTING_OFFLINE],
    )


class Certificate(models.Model):
    AS = models.ForeignKey(
        AS,
        related_name='certificates',
        on_delete=models.CASCADE,
    )

    version = models.PositiveIntegerField()

    certificate = jsonfield.JSONField()
