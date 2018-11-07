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

import os
import base64
from django.contrib.auth.models import User
from django.db import models
from django.db.models import F
import jsonfield
import lib.crypto.asymcrypto

# TODO(matzf) move to common definitions module?
_DEFAULT_HOST_IP = "127.0.0.1"


_MAX_LEN_DEFAULT = 255
""" Max length value for fields without specific requirments to max length """
_MAX_LEN_CHOICES_DEFAULT = 16
""" Max length value for choices fields without specific requirments to max length """
_MAX_LEN_KEYS = 255
""" Max length value for base64 encoded AS keys """


class ISD(models.Model):
    id = models.PositiveIntegerField(primary_key=True)
    label = models.CharField(max_length=_MAX_LEN_DEFAULT, null=True, blank=True)

    trc = jsonfield.JSONField(
        null=True,
        blank=True,
        verbose_name="Trust Root Configuration (TRC)")
    trc_priv_keys = jsonfield.JSONField(
        null=True,
        blank=True,
        verbose_name="TRC private keys",
        help_text="""The private keys corresponding to the Core-AS keys in
            the current TRC. These keys will be used to sign the next version
            of the TRC."""
    )
    trc_needs_update = models.BooleanField(
        default=True,
        help_text="""The TRC will be updated before the next deployment of
            the configuration of the core ASes.
            This flag is set by operations affecting the set of Core-ASes or
            their keys."""
    )

    class Meta:
        verbose_name = 'ISD'
        verbose_name_plural = 'ISDs'

    def __str__(self):
        if self.label:
            return 'ISD %d (%s)' % (self.id, self.label)
        else:
            return 'ISD %d' % self.id


class ASManager(models.Manager):
    def create(self, **kwargs):
        """ Create the AS and initialise the required keys """
        # if 'sig_pub_key' in kwargs, etc:
        #   raise ValueError()
        as_ = AS(**kwargs)
        as_.init_keys()
        as_.save(force_insert=True)
        return as_


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

    master_as_key = models.CharField(max_length=_MAX_LEN_KEYS, null=True, blank=True)

    is_core = models.BooleanField(default=False)
    core_sig_priv_key = models.CharField(max_length=_MAX_LEN_KEYS, null=True, blank=True)
    core_sig_pub_key = models.CharField(max_length=_MAX_LEN_KEYS, null=True, blank=True)
    core_online_priv_key = models.CharField(max_length=_MAX_LEN_KEYS, null=True, blank=True)
    core_online_pub_key = models.CharField(max_length=_MAX_LEN_KEYS, null=True, blank=True)
    core_offline_priv_key = models.CharField(max_length=_MAX_LEN_KEYS, null=True, blank=True)
    core_offline_pub_key = models.CharField(max_length=_MAX_LEN_KEYS, null=True, blank=True)

    certificates = jsonfield.JSONField(null=True, blank=True)
    certificates_needs_update = models.BooleanField(
        default=True,
        help_text=''
    )

    objects = ASManager()

    class Meta:
        verbose_name = 'AS'
        verbose_name_plural = 'ASes'
        unique_together = ('as_id',)    # could be primary key

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

    isd_as_str.short_description = 'ISD-AS'

    def init_keys(self):
        """
        Initialise signing and encryption key pairs, the MasterASKey (used for
        hop field Message Authentication Codes (MAC) and the Dynamically
        Recreatable Keys (DRKeys)), as well as the core AS signing key pairs.
        Note: the core AS keys will not used unless the AS is a core AS.
        """
        # FIXME(matzf): generate core keys only "on demand" or needlessly complicated?
        self._gen_keys()
        self._gen_master_as_key()
        self._gen_core_keys()

    def update_keys(self):
        """
        Generate new signing and encryption key pairs.
        Bump the corresponding indicators, so that certificates will be renewed
        and the configuration will be to all affected hosts.
        """
        # TODO(matzf): in coming scion versions, the master key can be updated too.
        self._gen_keys()
        self.certificates_needs_update = True
        self.hosts.update(config_version=F('config_version') + 1)

    def update_core_keys(self):
        """
        Generate new core AS signing key pairs.
        Bump the corresponding indicators, so that certificates will be renewed
        and the configuration will be to all affected hosts.
        """
        self._gen_core_keys()
        if self.is_core:
            self.isd.trc_needs_update = True
            self.certificates_needs_update = True
            self.isd \
                .ases \
                .filter(is_core=True) \
                .hosts \
                .update(config_version=F('config_version') + 1)

    def init_default_services(self):
        """
        Initialise a default Host object and the default AS services
        """
        host = Host.objects.create(AS=self, ip=_DEFAULT_HOST_IP)

        default_services = (Service.BS, Service.PS, Service.CS, Service.ZK)
        for service_type in default_services:
            Service.objects.create(AS=self, host=host, type=service_type)

    def find_interface_id(self):
        """
        Find an unused interface id
        """
        # TODO(matzf): use holes
        return max(
            (interface.interface_id for interface in self.interfaces.iterator()),
            default=0
        ) + 1

    def _gen_keys(self):
        """
        Generate signing and encryption key pairs.
        """
        self.sig_pub_key, self.sig_priv_key = _gen_sig_keypair()
        self.enc_pub_key, self.enc_priv_key = _gen_enc_keypair()

    def _gen_master_as_key(self):
        """
        Generate the MasterASKey.
        """
        self.master_as_key = _base64encode(os.urandom(16))

    def _gen_core_keys(self):
        """
        Generate core AS signing key pairs.
        """
        self.core_sig_pub_key, self.core_sig_priv_key = _gen_sig_keypair()
        self.core_online_pub_key, self.core_online_priv_key = _gen_sig_keypair()
        self.core_offline_pub_key, self.core_offline_priv_key = _gen_sig_keypair()


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
    AS = models.OneToOneField(
        AS,
        related_name='attachment_point',
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
        related_name='hosts',
        on_delete=models.SET_NULL,
    )
    config_version = models.PositiveIntegerField(default=0)
    ip = models.GenericIPAddressField(default=_DEFAULT_HOST_IP)
    """ IP of the host IN the AS """

    class Meta:
        unique_together = ('AS', 'ip')

    def __str__(self):
        return '%s,[%s]' % (self.AS.isd_as_str(), self.ip)


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
    AS = models.ForeignKey(
        AS,
        related_name='interfaces',
        on_delete=models.CASCADE,
    )
    interface_id = models.PositiveSmallIntegerField()
    host = models.ForeignKey(
        Host,
        related_name='interfaces',
        on_delete=models.CASCADE,
    )
    port = models.PositiveSmallIntegerField(null=True, blank=True)
    public_ip = models.GenericIPAddressField(null=True, blank=True)
    public_port = models.PositiveSmallIntegerField(null=True, blank=True)
    bind_ip = models.GenericIPAddressField(null=True, blank=True)
    bind_port = models.PositiveSmallIntegerField(null=True, blank=True)

    @classmethod
    def create(cls, host):
        ifid = host.AS.find_interface_id()
        host.update(config_version=F('config_version') + 1)
        return Interface(AS=host.AS, host=host, interface_id=ifid)

    def link(self):
        return (
            Link.objects.filter(interfaceA=self) |
            Link.objects.filter(interfaceB=self)
        ).first()

    def remote_interface(self):
        return (
            Link.objects.filter(interfaceA=self).interfaceB or
            Link.objects.filter(interfaceB=self).interfaceA
        )

    def remote_as(self):
        return self.remote_interface().AS


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

    @classmethod
    def create(cls, hostA, hostB, link_type, active=True):
        interfaceA = Interface.create(host=hostA)
        interfaceB = Interface.create(host=hostB)
        return Link(
            interfaceA=interfaceA,
            interfaceB=interfaceB,
            link_type=link_type,
            active=active
        )




class Service(models.Model):
    """
        A SCION service, both for the control plane services (beacon, path, ...)
        and for any other service that communicates using SCION.
    """
    BS = 'BS'
    PS = 'PS'
    CS = 'CS'
    ZK = 'ZK'
    BW = 'BW'
    PP = 'PP'
    SERVICE_TYPES = (
        (BS, 'Beacon Server'),
        (PS, 'Path Server'),
        (CS, 'Certificate Server'),
        (ZK, 'Zookeeper (service discovery)'),
        (BW, 'Bandwidth tester server'),
        (PP, 'Pingpong server'),
    )

    AS = models.ForeignKey(
        AS,
        related_name='services',
        on_delete=models.CASCADE,
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


def _base64encode(key):
    return base64.b64encode(key).decode()


def _base64encode_tuple(keys):
    return (_base64encode(k) for k in keys)


def _gen_sig_keypair():
    return _base64encode_tuple(lib.crypto.asymcrypto.generate_sign_keypair())


def _gen_enc_keypair():
    return _base64encode_tuple(lib.crypto.asymcrypto.generate_enc_keypair())
