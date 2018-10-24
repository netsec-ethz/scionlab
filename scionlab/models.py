# Copyright 2018 ETH Zurich
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

from django.db import models
from django.contrib.auth.models import User

import lib.crypto.asymcrypto
import base64

_MAX_LEN_DEFAULT = 255
""" Max length value for fields without specific requirments to max length """
_MAX_LEN_CHOICES_DEFAULT = 16
""" Max length value for choices fields without specific requirments to max length """
_MAX_LEN_KEYS = 255
""" Max length value for base64 encoded AS keys """

class ISD(models.Model):
    id = models.PositiveIntegerField(primary_key=True)
    label = models.CharField(max_length=_MAX_LEN_DEFAULT, null=True, blank=True)
    trc = models.TextField(null=True, blank=True)

    class Meta:
        verbose_name = 'ISD'
        verbose_name_plural = 'ISDs'

    def __str__(self):
        if self.label:
            return 'ISD %d (%s)' % (self.id, self.label)
        else:
            return 'ISD %d' % self.id


class ASManager(models.Manager):
    def create_with_keys(self, **kwargs):
        # if 'sig_pub_key' in kwargs, etc:
        #   raise ValueError()
        a = AS(**kwargs)
        a.init_keys()
        a.save(force_insert=True)
        return a


class AS(models.Model):
    isd = models.ForeignKey(
        ISD,
        related_name='ases',
        on_delete=models.CASCADE
    )
    as_id = models.CharField(max_length=15)
    label = models.CharField(max_length=_MAX_LEN_DEFAULT, null=True, blank=True)

    owner = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        null=True,
        blank=True
    )

    sig_pub_key = models.CharField(max_length=_MAX_LEN_KEYS, null=True, blank=True)
    sig_priv_key = models.CharField(max_length=_MAX_LEN_KEYS, null=True, blank=True)
    enc_pub_key = models.CharField(max_length=_MAX_LEN_KEYS, null=True, blank=True)
    enc_priv_key = models.CharField(max_length=_MAX_LEN_KEYS, null=True, blank=True)

    is_core = models.BooleanField(default=False)

    objects = ASManager()

    class Meta:
        verbose_name = 'AS'
        verbose_name_plural = 'ASes'
        unique_together = ('as_id',) # could be primary key

    def __str__(self):
        if self.label:
            return '%s (%s)' % (self.isd_as_str(), self.label)
        else:
            return self.isd_as_str()

    def isd_as_str(self):
        """
        :return: the ISD-AS string representation
        """
        return '%d-%s' % (self.isd.id, self.as_id)

    def init_keys(self):
        """
        Initialise signing and encryption key pairs
        """
        sig_pub_key, sig_priv_key = lib.crypto.asymcrypto.generate_sign_keypair()
        enc_pub_key, enc_priv_key = lib.crypto.asymcrypto.generate_enc_keypair()
        self.sig_pub_key = base64.b64encode(sig_pub_key).decode()
        self.sig_priv_key = base64.b64encode(sig_priv_key).decode()
        self.enc_pub_key = base64.b64encode(enc_pub_key).decode()
        self.enc_priv_key = base64.b64encode(enc_priv_key).decode()


class UserAS(AS):
    # These fields are redundant for the network model
    # They are here to retain the values entered by the user
    # if she switches to VPN and back.
    public_ip = models.GenericIPAddressField(null=True, blank=True)
    bind_ip = models.GenericIPAddressField(null=True, blank=True)

    class Meta:
        verbose_name = 'User AS'
        verbose_name_plural = 'User ASes'

class AttachmentPoint(models.Model):
    AS = models.ForeignKey(
        AS,
        on_delete=models.CASCADE,
    )
    vpn = models.OneToOneField(
        'VPN',
        null=True,
        blank=True,
        related_name='+',
        on_delete=models.SET_NULL
    )


class Host(models.Model):
    """
    A host is a machine/vm/container running services for one AS.
    """
    AS = models.ForeignKey(
        AS,
        null=True,
        on_delete=models.SET_NULL,
    )
    config_version = models.PositiveIntegerField(default=0)
    ip = models.GenericIPAddressField(default="127.0.0.1")
    """ IP of the host IN the AS """

    class Meta:
        unique_together = ('AS', 'ip')

    def __str__(self):
        return '%s,[%s]'%(self.AS.isd_as_str(), self.ip)


class ManagedHost(Host):
    HOST_TYPES = (
        ('DEDICATED', 'Dedicated'),
        ('VM', 'VM'),
        ('DOCKER', 'Docker')
    )

    public_ip = models.GenericIPAddressField()
    ssh_port = models.PositiveSmallIntegerField(default=22)
    container_name = models.CharField(max_length=_MAX_LEN_DEFAULT, null=True, blank=True)
    type = models.CharField(
        choices=HOST_TYPES,
        max_length=_MAX_LEN_CHOICES_DEFAULT
    )
    label = models.CharField(max_length=_MAX_LEN_DEFAULT, null=True, blank=True)

    config_version_deployed = models.PositiveIntegerField()


class Interface(models.Model):
    host = models.ForeignKey(
        Host,
        related_name='interfaces',
        on_delete=models.PROTECT    # don't delete hosts with services configured
    )
    port = models.PositiveSmallIntegerField(null=True, blank=True)
    public_ip = models.GenericIPAddressField()
    public_port = models.PositiveSmallIntegerField()
    bind_ip = models.GenericIPAddressField(null=True, blank=True)
    bind_port = models.PositiveSmallIntegerField(null=True, blank=True)


class Link(models.Model):
    LINK_TYPES = (
        ('PROVIDER', 'Provider link from A to B'),
        ('CORE', 'Core link (symmetric)'),
        ('PEER', 'Peering link (symmetric)'),
    )
    interfaceA = models.OneToOneField(
        Interface,
        related_name='+',
        on_delete=models.CASCADE
    )
    interfaceB = models.OneToOneField(
        Interface,
        related_name='+',
        on_delete=models.CASCADE
    )
    link_type = models.CharField(
        choices=LINK_TYPES,
        max_length=_MAX_LEN_CHOICES_DEFAULT
    )
    active = models.BooleanField(default=True)


class Service(models.Model):
    """
        A SCION service, both for the control plane services (beacon, path, ...)
        and for any other service that communicates using SCION.
    """
    SERVICE_TYPES = (
        ('BS', 'Beacon Server'),
        ('PS', 'Path Server'),
        ('CS', 'Certificate Server'),
        ('ZK', 'Zookeeper (service discovery)'),
        ('BW', 'Bandwidth tester server'),
        ('PP', 'Pingpong server'),
    )

    host = models.ForeignKey(
        Host,
        related_name='services',
        on_delete=models.CASCADE
    )
    port = models.PositiveSmallIntegerField(null=True, blank=True)
    type = models.CharField(
        choices=SERVICE_TYPES,
        max_length=_MAX_LEN_CHOICES_DEFAULT
    )


class VPN(models.Model):
    server = models.ForeignKey(
        ManagedHost,
        related_name='vpn_servers',
        on_delete=models.CASCADE
    )
    server_port = models.PositiveSmallIntegerField()
    subnet = models.CharField(max_length=15)
    keys = models.TextField(null=True, blank=True)


class VPNClient(models.Model):
    vpn = models.ForeignKey(
        VPN,
        related_name='clients',
        on_delete=models.CASCADE
    )
    host = models.ForeignKey(
        Host,
        related_name='vpn_clients',
        on_delete=models.CASCADE
    )
    keys = models.TextField(null=True, blank=True)
