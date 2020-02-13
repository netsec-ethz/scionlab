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

import jsonfield

from django.db import models

import lib.crypto.asymcrypto

from scionlab.certificates import (
    generate_trc,
    generate_core_certificate,
    generate_as_certificate_chain,
)
from scionlab.models.core import (
    AS,
    ISD,
)

class Key(models.Model):
    DECRYPT = 'as-decrypy'
    REVOCATION = 'as-revocation'
    SIGNING = 'as-signing'
    CERT_SIGNING = 'as-cert-signing'
    TRC_ISSUING_GRANT = 'trc-issuing-grant'
    TRC_VOTING_OFFLINE = 'trc-voting-offline'
    TRC_VOTING_ONLINE = 'trc-voting-online'

    AS = models.ForeignKey(
        AS,
        related_name='keys',
        on_delete=models.CASCADE,
    )



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
    priv_keys = jsonfield.JSONField(  # TODO FK?
        null=True,
        blank=True,
        verbose_name="TRC private keys",
        help_text="""The private keys corresponding to the Core-AS keys in
            the current TRC. These keys will be used to sign the next version
            of the TRC."""
    )

    class Meta:
        verbose_name = 'TRC'
        verbose_name_plural = 'TRCs'


class Certificate(models.Model):

