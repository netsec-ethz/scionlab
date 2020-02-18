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

from django.db import models

from scionlab.models.core import (
    AS,
    ISD,
)
from scionlab.certificates import (
    generate_trc,
    generate_core_certificate,
    generate_as_certificate_chain,
)
from scionlab.defines import (
    DEFAULT_EXPIRATION,
)
from scionlab.scion import keys

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
    )

    usage = models.CharField(
        choices=list(zip(USAGES, USAGES)),
        max_length=_MAX_LEN_CHOICES_DEFAULT,
    )
    version = models.PositiveIntegerField()

    key = models.CharField(max_length=_MAX_LEN_KEYS)
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
    def create():
        pass


class TRC(models.Model):
    isd = models.ForeignKey(
        ISD,
        related_name='trcs',
        on_delete=models.CASCADE,
        verbose_name='ISD'
    )

    version = models.PositiveIntegerField()  # TODO can this be auto?

    content = jsonfield.JSONField()
    content_signed = jsonfield.JSONField()  # TODO

    voting_keys = models.ManyToManyField(Key)

    objects = TRCManager()

    class Meta:
        verbose_name = 'TRC'
        verbose_name_plural = 'TRCs'


class Certificate(models.Model):
    AS = models.ForeignKey(
        AS,
        related_name='certificates',
        on_delete=models.CASCADE,
    )

    version = models.PositiveIntegerField()

    content = jsonfield.JSONField()
    content_signed = jsonfield.JSONField()  # TODO

