# Copyright 2021 ETH Zurich
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

import textwrap

from django.db import migrations

PEM_WIDTH = 64  # see e.g. RFC 7468
TRC_PEM_HEADER = "-----BEGIN TRC-----\n"
TRC_PEM_FOOTER = "-----END TRC-----\n"


def convert_trcs_to_pem(apps, schema_editor):
    """
    Convert TRC data from DER to PEM.
    As the DER blob is already stored as base64-encoded text in the DB,
    we only need to wrap lines and add the header and footer to turn it into a PEM.
    """
    TRC = apps.get_model('scionlab', 'TRC')
    for trc in TRC.objects.all():
        trc.trc = trc_base64der_to_pem(trc.trc)
        trc.save()


def trc_base64der_to_pem(der: str) -> str:
    assert not der.startswith(TRC_PEM_HEADER)
    assert not der.endswith(TRC_PEM_HEADER)
    body = textwrap.fill(der, width=PEM_WIDTH)
    return TRC_PEM_HEADER + body + "\n" + TRC_PEM_FOOTER


def revert_trcs_to_der(apps, schema_editor):
    """
    Convert TRC from PEM back to base64-encoded DER.
    """
    TRC = apps.get_model('scionlab', 'TRC')
    for trc in TRC.objects.all():
        trc.trc = trc_pem_to_base64der(trc.trc)
        trc.save()


def trc_pem_to_base64der(pem: str) -> str:
    assert pem.startswith(TRC_PEM_HEADER)
    assert pem.endswith(TRC_PEM_FOOTER)
    stripped = pem[len(TRC_PEM_HEADER):-len(TRC_PEM_FOOTER)]
    return stripped.replace("\n", "")


class Migration(migrations.Migration):

    dependencies = [
        ('scionlab', '0004_remove_link_bandwidth'),
    ]

    operations = [
        migrations.RunPython(convert_trcs_to_pem,  # forward
                             revert_trcs_to_der),  # backward
    ]
