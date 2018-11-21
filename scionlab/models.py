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
from django import urls
from django.conf import settings
from django.core.exceptions import ValidationError
from django.contrib.auth.models import User as auth_User
from django.dispatch import receiver
from django.db import models
from django.db.models import F, Max
from django.db.models.signals import pre_delete, post_delete
import jsonfield
import lib.crypto.asymcrypto


# TODO(matzf) move to common definitions module?
MAX_PORT = 2**16-1
""" Max value for ports """
DEFAULT_INTERFACE_PUBLIC_PORT = 50000
DEFAULT_INTERFACE_INTERNAL_PORT = 30000
DEFAULT_HOST_IP = "127.0.0.1"

_MAX_LEN_DEFAULT = 255
""" Max length value for fields without specific requirements to max length """
_MAX_LEN_CHOICES_DEFAULT = 16
""" Max length value for choices fields without specific requirements to max length """
_MAX_LEN_KEYS = 255
""" Max length value for base64 encoded AS keys """


class User(auth_User):
    class Meta:
        proxy = True

    def max_num_ases(self):
        if self.is_staff:
            return settings.MAX_ASES_ADMIN
        return settings.MAX_ASES_USER

    def num_ases(self):
        return UserAS.objects.filter(owner=self).count()

    def check_as_quota(self):
        """
        Check if the user is allowed to create another AS.
        :raises: Validation error if quota is exceeded
        """
        if self.num_ases() >= self.max_num_ases():
            raise ValidationError("UserAS quota exceeded",
                                  code='user_as_quota_exceeded')


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
        as_.save()
        return as_

    def create_with_default_services(self, **kwargs):
        """
        Create the AS, initialise the required keys and create a default host object
        with default services
        """
        as_ = self.create(**kwargs)
        as_.init_default_services()
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

    def _pre_delete(self):
        """
        Called by the pre_delete signal handler `_as_pre_delete`.
        Note: the pre_delete signal has the advantage that it is called
        also for bulk deletion, while this `delete()` method is not.
        """
        if self.is_core:
            self._bump_hosts_config_core_change()
        else:
            self.bump_hosts_config()

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
        self.bump_hosts_config()

    def update_core_keys(self):
        """
        Generate new core AS signing key pairs.
        Bump the corresponding indicators, so that certificates will be renewed
        and the configuration will be to all affected hosts.
        """
        self._gen_core_keys()
        if self.is_core:
            self._bump_hosts_config_core_change()

    def init_default_services(self):
        """
        Initialise a default Host object and the default AS services
        """
        host = Host.objects.create(AS=self, ip=DEFAULT_HOST_IP)

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

    def bump_hosts_config(self):
        self.hosts.update(config_version=F('config_version') + 1)

    def _bump_hosts_config_core_change(self):
        # TODO(matzf): untested
        self.isd.trc_needs_update = True
        self.certificates_needs_update = True
        self.isd \
            .ases \
            .filter(is_core=True) \
            .hosts \
            .update(config_version=F('config_version') + 1)

        # TODO(matzf): add issuer/subject relation, reset certificates for all signed_by

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


class UserASManager(models.Manager):
    def create(self,
               user,
               attachment_point,
               public_port,
               installation_type,
               label=None,
               use_vpn=False,
               public_ip=None,
               bind_ip=None,
               bind_port=None):
        """
        Create a UserAS attached to the given attachment point.
        The public_ip must be specified if use_vpn is not enabled.
        """
        user.check_as_quota()
        UserAS.check_vpn_available(use_vpn, attachment_point)

        isd = attachment_point.AS.isd
        as_id = self.get_next_id()
        user_as = UserAS(
            owner=user,
            label=label,
            isd=isd,
            as_id=as_id,
            attachment_point=attachment_point,
            public_ip=public_ip,
            bind_ip=bind_ip,
            bind_port=bind_port,
            installation_type=installation_type,
        )

        user_as.init_keys()
        user_as.save()
        user_as.init_default_services()
        host = user_as.hosts.first()

        vpn_client = None
        if use_vpn:
            vpn_client = attachment_point.vpn.create_client(host)

        host.default_public_ip = public_ip if not use_vpn else vpn_client.ip
        host.default_bind_ip = bind_ip if not use_vpn else None
        host.save()

        Link.objects.create(type=Link.PROVIDER,
                            kwargsA=dict(host=attachment_point.AS.hosts.first()),
                            kwargsB=dict(
                                host=user_as.hosts.first(),
                                public_port=public_port,
                                bind_port=bind_port if not use_vpn else None
                            ))

        # TODO(matzf): somewhere we need to trigger the config deployment

        return user_as

    def get_next_id(self):
        """
        Get the next available UserAS id.
        Assumes that UserASes have the "reserved" namespace `ff00:1:X`.
        """
        max_id = next(iter(self.aggregate(Max('id')).values())) or 1
        return 'ff00:1:%i' % max_id


class UserAS(AS):
    VM = 'VM'
    DEDICATED = 'DEDICATED'
    INSTALLATION_TYPES = (
        (VM, 'Install inside a virtual machine'),
        (DEDICATED, 'Install on a dedicated system (for experts)')
    )

    attachment_point = models.ForeignKey(
        'AttachmentPoint',
        related_name='user_ases',
        on_delete=models.SET_NULL,
        null=True,  # Null on deletion of AP
        blank=False,
        default=''  # Invalid default avoids rendering a '----' selection choice
    )
    # These fields are redundant for the network model
    # They are here to retain the values entered by the user
    # if she switches to VPN and back.
    public_ip = models.GenericIPAddressField(null=True, blank=True)
    bind_ip = models.GenericIPAddressField(null=True, blank=True)
    bind_port = models.PositiveSmallIntegerField(null=True, blank=True)

    installation_type = models.CharField(
        choices=INSTALLATION_TYPES,
        max_length=_MAX_LEN_CHOICES_DEFAULT,
        default=VM
    )

    objects = UserASManager()

    class Meta:
        verbose_name = 'User AS'
        verbose_name_plural = 'User ASes'

    def get_absolute_url(self):
        return urls.reverse('user_as_detail', kwargs={'pk': self.pk})

    def update(self,
               label,
               attachment_point,
               use_vpn,
               public_ip,
               public_port,
               bind_ip,
               bind_port,
               installation_type):
        """
        Update this UserAS instance and immediately `save`.
        Updates the related host, interface and link instances and will trigger
        a configuration bump for the hosts of the affected attachment point(s).
        """
        self.check_vpn_available(use_vpn, attachment_point)

        host = self.hosts.first()   # UserAS always has only one host
        link = self._get_ap_link()
        interface_ap = link.interfaceA
        interface_user = link.interfaceB
        assert interface_user.host == host

        if attachment_point != self.attachment_point:
            self.attachment_point = attachment_point
            interface_ap.update(host=attachment_point.hosts.first())

        if use_vpn:
            vpn_client = self._create_or_activate_vpn_client()
        else:
            host.vpn_clients.update(active=False)   # deactivate all vpn clients

        host.update_default_interface_ips(
            default_public_ip=public_ip if not use_vpn else vpn_client.ip,
            default_bind_ip=bind_ip if not use_vpn else None
        )
        interface_user.update(
            public_port=public_port,
            bind_port=bind_port if not use_vpn else None
        )

        self.installation_type = installation_type
        self.public_ip = public_ip
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.save()

        # TODO(matzf) trigger AP config deployment

    def is_use_vpn(self):
        """
        Is this UserAS currently configured with VPN?
        """
        return VPNClient.objects.filter(host__AS=self, active=True).exists()

    def is_active(self):
        """
        Is this UserAS currently active?
        """
        return self.interfaces.first().link().active

    def get_public_port(self):
        return self.interfaces.first().public_port

    def set_active(self, active):
        self.interfaces.first().link().set_active(active)
        # TODO(matzf) trigger AP config deployment (delayed?)

    def _get_ap_link(self):
        # FIXME(matzf): find the correct link to the AP if multiple links present!
        return self.interfaces.first().link()

    def _create_or_activate_vpn_client(self):
        """
        Get or create the VPN client config for the VPN of the current attachment point,
        and activate it.
        Deactivate all other vpn clients configured on this host.
        """
        host = self.hosts.first()
        host.vpn_clients.update(active=False)
        vpn_client = host.vpn_clients.filter(vpn=self.attachment_point.vpn).first()
        if vpn_client:
            vpn_client.active = True
            vpn_client.save()
            return vpn_client
        else:
            return self.attachment_point.vpn.create_client(host)

    @staticmethod
    def check_vpn_available(use_vpn, attachment_point):
        """
        Raise ValidationError if `use_vpn` is `True` but the attachment point
        does not support VPN.
        """
        if attachment_point.vpn is None and use_vpn:
            raise ValidationError("Selected attachment point does not support VPN",
                                  code='attachment_point_no_vpn')


class AttachmentPoint(models.Model):
    AS = models.OneToOneField(
        AS,
        related_name='attachment_point_info',
        on_delete=models.CASCADE,
    )
    vpn = models.OneToOneField(
        'VPN',
        null=True,
        blank=True,
        related_name='+',
        on_delete=models.SET_NULL
    )

    def __str__(self):
        return str(self.AS)


class HostManager(models.Manager):
    def reset_needs_config_deployment(self):
        """
        Reset `needs_config_deployement` to False for all hosts.
        """
        self.update(config_version=F('config_version_deployed'))

    def needs_config_deployment(self):
        """
        Find all hosts with `needs_config_deployment`.
        """
        return self.filter(config_version__gt=F('config_version_deployed'))


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
    # TODO(matzf): handle changes in the ip fields
    ip = models.GenericIPAddressField(
        default=DEFAULT_HOST_IP,
        help_text="IP of the host in the AS"
    )
    default_public_ip = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text="Default public IP for for border router interfaces running on this host."
    )
    default_bind_ip = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text="Default bind IP for for border router interfaces running on this host."
    )
    label = models.CharField(max_length=_MAX_LEN_DEFAULT, null=True, blank=True)

    managed = models.BooleanField(default=False)
    management_ip = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text="Public IP of the host for management (should be reachable by the coordinator)."
    )
    ssh_port = models.PositiveSmallIntegerField(default=22)

    # TODO(matzf): we may need additional information for container or VM
    # initialisation (to access the host's host)

    config_version = models.PositiveIntegerField(default=1)
    config_version_deployed = models.PositiveIntegerField(default=0)

    objects = HostManager()

    class Meta:
        unique_together = ('AS', 'ip')

    def __str__(self):
        if self.label:
            return self.label
        return '%s,[%s]' % (self.AS.isd_as_str(), self.ip)

    def needs_config_deployment(self):
        """
        Has the configuration for the services/interfaces running on this Host changed since the
        last deployment?
        """
        return self.config_version_deployed < self.config_version

    def update_default_interface_ips(self, default_public_ip, default_bind_ip):
        """
        Update the default_public_ip/default_bind_ip of this host instance, and immediately `save`.
        This will trigger a configuration bump for all Hosts in all affected ASes.
        """
        if default_bind_ip != self.default_bind_ip:
            self.default_bind_ip = default_bind_ip

        if default_public_ip != self.default_public_ip:
            self.default_public_ip = default_public_ip
            # bump affected remote ASes
            for interface in self.interfaces.filter(public_ip=None).iterator():
                interface.remote_as().bump_hosts_config()

        self.save()
        self.AS.bump_hosts_config()


class InterfaceManager(models.Manager):
    def create(self, host, **kwargs):
        # TODO(matzf): free port assignment
        as_ = host.AS
        ifid = as_.find_interface_id()
        as_.bump_hosts_config()
        return super().create(AS=as_, interface_id=ifid, host=host, **kwargs)


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
    public_ip = models.GenericIPAddressField(null=True, blank=True)
    public_port = models.PositiveSmallIntegerField(default=DEFAULT_INTERFACE_PUBLIC_PORT)
    bind_ip = models.GenericIPAddressField(null=True, blank=True)
    bind_port = models.PositiveSmallIntegerField(null=True, blank=True)
    internal_port = models.PositiveSmallIntegerField(default=DEFAULT_INTERFACE_INTERNAL_PORT)

    objects = InterfaceManager()

    def __str__(self):
        return '%s (%i)' % (self.AS.isd_as_str(), self.interface_id)

    def _pre_delete(self):
        """
        Called by the pre_delete signal handler `_interface_pre_delete`.
        Note: the deletion-signals have the advantage that they are triggerd
        also for bulk deletion, while the `delete()` method is not.
        """
        self.AS.bump_hosts_config()

    def clean(self):
        if not self.public_ip and not self.host.default_public_ip:
            raise ValidationError(
                "If the host doesn't specify a default public ip, the public ip must be specified",
                code='interface_no_public_ip'
            )

    def save(self, **kwargs):
        self.clean()
        super().save(**kwargs)

    def update(self,
               host=None,
               public_ip=None,
               public_port=None,
               bind_ip=None,
               bind_port=None,
               internal_port=None):
        # TODO(matzf): free port assignment
        """
        Update the fields for this interface and immediately `save`.
        This will trigger a configuration bump for all Hosts in all affected ASes.
        """
        bump_local = False
        bump_local_remote = False
        if host is not None and host != self.host:
            old_as = self.AS
            new_as = host.AS
            if new_as != old_as:
                ifid = new_as.find_interface_id()   # before setting AS-relation
                self.AS = new_as
                self.interface_id = ifid
                old_as.bump_hosts_config()
            self.host = host
            bump_local_remote = True

        # TODO(matzf): this is overly verbose
        if public_ip is not None and public_ip != self.public_ip:
            bump_local_remote = True
            self.public_ip = public_ip
        if public_port is not None and public_port != self.public_port:
            bump_local_remote = True
            self.public_port = public_port
        if bind_ip is not None and bind_ip != self.bind_ip:
            bump_local = True
            self.bind_ip = bind_ip
        if bind_port is not None and bind_port != self.bind_port:
            bump_local = True
            self.bind_port = bind_port
        if internal_port is not None and internal_port != self.internal_port:
            bump_local = True
            self.internal_port = internal_port

        if bump_local or bump_local_remote:
            self.AS.bump_hosts_config()
        if bump_local_remote:
            # bump remote AS
            # if both ASes of both interfaces are changed, this can be either old
            # or new AS, depending on order. Redundant but correct.
            self.remote_as().bump_hosts_config()
        self.save()

    def get_public_ip(self):
        if self.public_ip:
            return self.public_ip
        return self.host.default_public_ip

    def get_bind_ip(self):
        """ May be None """
        if self.bind_ip:
            return self.bind_ip
        return self.host.default_bind_ip

    def link(self):
        return (
            Link.objects.filter(interfaceA=self) |
            Link.objects.filter(interfaceB=self)
        ).first()

    def remote_interface(self):
        # FIXME(matzf): naive queries
        link = self.link()
        if self == link.interfaceA:
            return link.interfaceB
        else:
            return link.interfaceA

    def remote_as(self):
        # FIXME(matzf): naive queries
        return self.remote_interface().AS


class LinkManager(models.Manager):
    def create(self, type, kwargsA, kwargsB, active=True):
        """
        Create an AS-Link from the AS of host A to to the AS of host B.
        """
        self._check_link(kwargsA.get('host'), kwargsB.get('host'))
        interfaceA = Interface.objects.create(**kwargsA)
        interfaceB = Interface.objects.create(**kwargsB)
        return super().create(
            type=type,
            active=active,
            interfaceA=interfaceA,
            interfaceB=interfaceB,
        )

    def create_default(self, type, as_a, as_b):
        """
        Utility function, for tests etc.
        Create a link between these ASes. The interfaces are created on
        the first host of each AS.
        """
        hostA = as_a.hosts.first()
        hostB = as_b.hosts.first()
        return self.create(type, dict(host=hostA), dict(host=hostB))

    def _check_link(self, hostA, hostB):
        # TODO(matzf): validation (should be reusable for forms and for global system checks)
        # - no provider loops
        # - core links only for core ases
        # - no non-core providers for core ases (or no providers at all?)
        # - no cross ISD provider links
        if hostA.AS == hostB.AS:
            raise ValueError("Loop AS-link (from AS to itself) not allowed")


class Link(models.Model):
    PROVIDER = 'PROVIDER'
    CORE = 'CORE'
    PEER = 'PEER'
    LINK_TYPES = (
        (PROVIDER, 'Provider link from A to B'),
        (CORE, 'Core link (symmetric)'),
        (PEER, 'Peering link (symmetric)'),
    )
    # TODO(matzf): reduce number of types? CORE can be deduced?
    interfaceA = models.OneToOneField(
        Interface,
        related_name='link_as_interfaceA',
        on_delete=models.CASCADE
    )
    interfaceB = models.OneToOneField(
        Interface,
        related_name='link_as_interfaceB',
        on_delete=models.CASCADE
    )
    type = models.CharField(
        choices=LINK_TYPES,
        max_length=_MAX_LEN_CHOICES_DEFAULT
    )
    active = models.BooleanField(default=True)

    objects = LinkManager()

    def __str__(self):
        return '%s -- %s' % (self.interfaceA, self.interfaceB)

    def _post_delete(self):
        """
        Called by the post_delete signal handler `_link_post_delete`.
        Note: this is triggered by _post_delete to allow checking whether the
        related interfaces have already been deleted, and avoid recursion.
        Note: the deletion-signals have the advantage that they are triggerd
        also for bulk deletion, while the `delete()` method is not.
        """
        for interface in filter(None, [self.get_interface_a(), self.get_interface_b()]):
            interface.delete()

    def update(self,
               type=None,
               active=None,
               kwargsA=None,
               kwargsB=None):
        """
        Update the fields for this Link instance and the two related interfaces
        and immediately `save`. This will trigger a configuration bump for all
        Hosts in all affected ASes.
        """
        bump = False
        if type is not None and type != self.type:
            self.type = type
            bump = True

        if active is not None and active != self.active:
            self.active = active
            bump = True

        if kwargsA is not None:
            self.interfaceA.update(**kwargsA)

        if kwargsB is not None:
            self.interfaceB.update(**kwargsB)

        if bump:
            self.save()
            self.interfaceA.AS.bump_hosts_config()
            self.interfaceB.AS.bump_hosts_config()

    def set_active(self, active):
        """
        Set the link to be active/inactive.
        This will trigger a configuration bump for all Hosts in all affected ASes.
        """
        if self.active != active:
            self.active = active
            self.save()
            self.interfaceA.AS.bump_hosts_config()
            self.interfaceB.AS.bump_hosts_config()

    def get_interface_a(self):
        if hasattr(self, 'interfaceA'):
            return self.interfaceA
        return None

    def get_interface_b(self):
        if hasattr(self, 'interfaceB'):
            return self.interfaceB
        return None


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
        (ZK, 'Zookeeper'),
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
        Host,
        related_name='vpn_servers',
        on_delete=models.CASCADE
    )
    server_port = models.PositiveSmallIntegerField()
    subnet = models.CharField(max_length=15)
    keys = models.TextField(null=True, blank=True)

    def create_client(self, host):
        return VPNClient.objects.create(vpn=self, host=host, ip=self.find_ip())

    def find_ip(self):
        # TODO(matzf)
        return '10.0.0.1'


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
    ip = models.GenericIPAddressField()
    active = models.BooleanField(default=True)
    keys = models.TextField(null=True, blank=True)


@receiver(pre_delete, sender=AS, dispatch_uid='as_delete_callback')
def _as_pre_delete(sender, instance, using, **kwargs):
    instance._pre_delete()


@receiver(pre_delete, sender=Interface, dispatch_uid='interface_delete_callback')
def _interface_pre_delete(sender, instance, using, **kwargs):
    instance._pre_delete()


@receiver(post_delete, sender=Link, dispatch_uid='link_delete_callback')
def _link_post_delete(sender, instance, using, **kwargs):
    instance._post_delete()


def _base64encode(key):
    return base64.b64encode(key).decode()


def _base64encode_tuple(keys):
    return (_base64encode(k) for k in keys)


def _gen_sig_keypair():
    return _base64encode_tuple(lib.crypto.asymcrypto.generate_sign_keypair())


def _gen_enc_keypair():
    return _base64encode_tuple(lib.crypto.asymcrypto.generate_enc_keypair())
