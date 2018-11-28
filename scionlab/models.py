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
from django.core.validators import RegexValidator
from django.contrib.auth.models import User as auth_User
from django.dispatch import receiver
from django.db import models
from django.db.models import F, Max
from django.db.models.signals import pre_delete, post_delete
import jsonfield
import lib.crypto.asymcrypto
from scionlab.util import as_ids

# TODO(matzf): some of the models use explicit create & update methods
# The interface of these methods should be revisited & check whether
# we can make better use of e.g. changed_data information of the forms.

# TODO(matzf) move to common definitions module?
MAX_PORT = 2**16-1
""" Max value for ports """

MAX_INTERFACE_ID = 2**12-1

USER_AS_ID_BEGIN = as_ids.parse('ffaa:1:1')
USER_AS_ID_END = as_ids.parse('ffaa:1:ffff')

DEFAULT_PUBLIC_PORT = 50000
DEFAULT_INTERNAL_PORT = 30000
DEFAULT_ZOOKEEPER_PORT = 2181
DEFAULT_HOST_INTERNAL_IP = "127.0.0.1"

_MAX_LEN_DEFAULT = 255
""" Max length value for fields without specific requirements to max length """
_MAX_LEN_CHOICES_DEFAULT = 16
""" Max length value for choices fields without specific requirements to max length """
_MAX_LEN_KEYS = 255
""" Max length value for base64 encoded AS keys """

_placeholder = object()
""" Placeholder value for optional parameters, different from None """


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
    isd_id = models.PositiveIntegerField()
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
            return 'ISD %d (%s)' % (self.isd_id, self.label)
        else:
            return 'ISD %d' % self.isd_id


class ASManager(models.Manager):
    def create(self, isd, as_id, is_core=False, label=None, owner=None):
        """
        Create the AS and initialise the required keys
        :param ISD isd:
        :param str as_id: valid AS-identifier string
        :param bool is_core: should this AS be created as a core AS?
        :param str label: optional
        :param User owner: optional
        :returns: AS
        """
        as_id_int = as_ids.parse(as_id)
        as_ = AS(
            isd=isd,
            as_id=as_id,
            as_id_int=as_id_int,
            is_core=is_core,
            label=label,
            owner=owner,
        )
        as_.init_keys()
        as_.save()
        return as_

    def create_with_default_services(self, isd, as_id, public_ip,
                                     is_core=False, label=None, owner=None,
                                     bind_ip=None, internal_ip=None):
        """
        Create the AS, initialise the required keys and create a default Host object
        with default services.
        Create the AS and initialise the required keys
        :param ISD isd:
        :param str as_id: valid AS-identifier string
        :param bool is_core: should this AS be created as a core AS?
        :param str label: optional
        :param User owner: optional
        :param str internal_ip: AS-internal IP for the Host, defaults to 127.0.0.1
        :param str public_ip: public IP for the first Host
        :param str bind_ip: optional, bind IP for the first Host
        :returns: AS
        """
        as_ = self.create(
            isd=isd,
            as_id=as_id,
            is_core=is_core,
            label=label,
            owner=owner,
        )
        as_.init_default_services(
            public_ip=public_ip,
            bind_ip=bind_ip,
            internal_ip=internal_ip
        )
        return as_


class AS(models.Model):
    isd = models.ForeignKey(
        ISD,
        related_name='ases',
        on_delete=models.CASCADE,
        verbose_name='ISD'
    )
    as_id = models.CharField(
        max_length=15,
        validators=[
            RegexValidator(regex=as_ids.REGEX),
            RegexValidator(regex=r"0+:0+:0+", inverse_match=True),
        ],
        verbose_name='AS-ID'
    )
    as_id_int = models.BigIntegerField(editable=False)
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
        return '%d-%s' % (self.isd.isd_id, self.as_id)

    isd_as_str.short_description = 'ISD-AS'

    def init_keys(self):
        """
        Initialise signing and encryption key pairs, the MasterASKey (used for
        hop field Message Authentication Codes (MAC) and the Dynamically
        Recreatable Keys (DRKeys)).
        If this is a core AS, also initialise the core AS signing key pairs.
        """
        self._gen_keys()
        self._gen_master_as_key()
        if self.is_core:
            self.init_core_keys()

    def init_core_keys(self):
        """
        Initialise the core AS signing key pairs.
        """
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

    def init_default_services(self, public_ip, bind_ip=None, internal_ip=None):
        """
        Initialise a default Host object and the default AS services
        """
        host = Host.objects.create(
            AS=self,
            public_ip=public_ip,
            bind_ip=bind_ip,
            internal_ip=internal_ip or DEFAULT_HOST_INTERNAL_IP
        )

        default_services = (Service.BS, Service.PS, Service.CS, Service.ZK)
        for service_type in default_services:
            Service.objects.create(host=host, type=service_type)

    def find_interface_id(self):
        """
        Find an unused interface id
        """
        existing_ids = _value_set(self.interfaces, 'interface_id')
        for candidate_id in range(1, MAX_INTERFACE_ID):
            if candidate_id not in existing_ids:
                return candidate_id
        raise RuntimeError('Interface IDs exhausted')

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
               owner,
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

        :param User owner: owner of this UserAS
        :param AttachmentPoint attachment_point: the attachment point (AP) to connect to
        :param int public_port: the public port for the connection to the AP
        :param str label: optional label
        :param bool use_vpn: use VPN for the connection to the AP
        :param str public_ip: the public IP for the connection to the AP.
                              Must be specified if use_vpn is not enabled.
        :param str bind_ip: the bind IP for the connection to the AP (for NAT)
        :param str bind_port: the bind port for the connection to the AP (for NAT port remapping)
        :returns: UserAS
        """
        owner.check_as_quota()

        isd = attachment_point.AS.isd
        as_id_int = self.get_next_id()
        user_as = UserAS(
            owner=owner,
            label=label,
            isd=isd,
            as_id=as_ids.format(as_id_int),
            as_id_int=as_id_int,
            attachment_point=attachment_point,
            public_ip=public_ip,
            bind_ip=bind_ip,
            bind_port=bind_port,
            installation_type=installation_type,
        )

        user_as.init_keys()
        user_as.save()
        user_as.init_default_services(
            public_ip=public_ip,
            bind_ip=bind_ip,
        )

        host = user_as.hosts.get()

        if use_vpn:
            vpn_client = attachment_point.vpn.create_client(host)

            interface_client = Interface.objects.create(
                host=host,
                public_ip=vpn_client.ip,
                public_port=public_port,
            )
            interface_ap = Interface.objects.create(
                host=attachment_point.get_host_for_useras_interface(),
                public_ip=attachment_point.vpn.server_vpn_ip()
            )
        else:
            interface_client = Interface.objects.create(
                host=host,
                public_port=public_port,
                bind_port=bind_port
            )
            interface_ap = Interface.objects.create(
                host=attachment_point.get_host_for_useras_interface(),
            )

        Link.objects.create(
            type=Link.PROVIDER,
            interfaceA=interface_ap,
            interfaceB=interface_client
        )

        # TODO(matzf): somewhere we need to trigger the config deployment

        return user_as

    def get_next_id(self):
        """
        Get the next available UserAS id.
        """
        max_id = self._max_id()
        if max_id is not None:
            if max_id >= USER_AS_ID_END:
                raise RuntimeError('UserAS-ID range exhausted')
            return max(USER_AS_ID_BEGIN, max_id + 1)
        else:
            return USER_AS_ID_BEGIN

    def _max_id(self):
        """
        :returns: the max `as_id_int` of all UserASes, or None
        """
        return next(iter(self.aggregate(Max('as_id_int')).values()), None)


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
        host = self.hosts.get()   # UserAS always has only one host
        link = self._get_ap_link()
        interface_ap = link.interfaceA
        interface_user = link.interfaceB
        assert interface_user.host == host

        host.update_interface_ips(
            public_ip=public_ip,
            bind_ip=bind_ip
        )

        if use_vpn:
            vpn_client = self._create_or_activate_vpn_client(attachment_point.vpn)
            interface_user.update(
                public_ip=vpn_client.ip,
                public_port=public_port,
                bind_port=None
            )
            interface_ap.update(
                host=attachment_point.get_host_for_useras_interface(),
                public_ip=attachment_point.vpn.server_vpn_ip()
            )
        else:
            host.vpn_clients.update(active=False)   # deactivate all vpn clients
            interface_user.update(
                public_ip=None,
                public_port=public_port,
                bind_ip=None,
                bind_port=bind_port
            )
            interface_ap.update(
                host=attachment_point.get_host_for_useras_interface(),
                public_ip=None
            )

        self.attachment_point = attachment_point
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
        return self.interfaces.get().link().active

    def get_public_port(self):
        return self.interfaces.get().public_port

    def set_active(self, active):
        self.interfaces.get().link().set_active(active)
        # TODO(matzf) trigger AP config deployment (delayed?)

    def _get_ap_link(self):
        # FIXME(matzf): find the correct link to the AP if multiple links present!
        return self.interfaces.get().link()

    def _create_or_activate_vpn_client(self, vpn):
        """
        Get or create the VPN client config for the given VPN.
        Deactivate all other VPN clients configured on this host.
        :param VPN vpn:
        :returns: VPNClient
        """
        host = self.hosts.get()
        host.vpn_clients.exclude(vpn=vpn).update(active=False)
        vpn_client = host.vpn_clients.filter(vpn=vpn).first()
        if vpn_client:
            if not vpn_client.active:
                vpn_client.active = True
                vpn_client.save()
            return vpn_client
        else:
            return vpn.create_client(host)


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

    def get_host_for_useras_interface(self):
        """
        Selects the preferred host on which the Interfaces to UserASes should be configured.
        :returns: a `Host` of the related `AS`
        """
        if self.vpn is not None:
            assert(self.vpn.server.AS == self.AS)
            return self.vpn.server
        else:
            return self.AS.hosts.filter(public_ip__isnull=False)[0]

    def check_vpn_available(self):
        """
        Raise ValidationError if the attachment point does not support VPN.
        """
        if self.vpn is None:
            raise ValidationError("Selected attachment point does not support VPN",
                                  code='attachment_point_no_vpn')


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
    internal_ip = models.GenericIPAddressField(
        default=DEFAULT_HOST_INTERNAL_IP,
        help_text="IP of the host in the AS"
    )
    public_ip = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text="Default public IP for for border router interfaces running on this host."
    )
    bind_ip = models.GenericIPAddressField(
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
        unique_together = ('AS', 'internal_ip')

    def __str__(self):
        if self.label:
            return self.label
        return '%s,[%s]' % (self.AS.isd_as_str(), self.internal_ip)

    def needs_config_deployment(self):
        """
        Has the configuration for the services/interfaces running on this Host changed since the
        last deployment?
        """
        return self.config_version_deployed < self.config_version

    def bump_config(self):
        self.config_version += 1
        self.save()

    def update_interface_ips(self, public_ip, bind_ip):
        """
        Update the public_ip/bind_ip of this host instance, and immediately `save`.
        This will trigger a configuration bump for all Hosts in all affected ASes.
        """
        if bind_ip != self.bind_ip:
            self.bind_ip = bind_ip

        if public_ip != self.public_ip:
            self.public_ip = public_ip
            # bump affected remote ASes
            for interface in self.interfaces.filter(public_ip=None).iterator():
                interface.remote_as().bump_hosts_config()

        self.AS.bump_hosts_config()
        self.save()

    def find_free_port(self, ip, min, max=MAX_PORT):
        """
        Find a free port for the given IP, in the range {min..max}.
        :param str ip: IP
        :param int min: start of the port range to search
        :param int max: end of the port range to search (included)
        :return: a free port
        :raises: RuntimeError if no port could be found
        """
        used_ports = self.find_used_ports(ip)
        for port in range(min, max):
            if port not in used_ports:
                return port
        raise RuntimeError('No free port available')

    def find_used_ports(self, ip):
        """
        Find a set of ports used with the given IP.
        :param str ip: IP
        :returns: Set of used ports for the given IP
        """
        ports = _value_set(self.interfaces.filter(public_ip=ip), 'public_port')
        ports |= _value_set(self.interfaces.filter(bind_ip=ip), 'bind_port')
        if ip == self.public_ip:
            ports |= _value_set(self.interfaces.filter(public_ip=None), 'public_port')
            ports |= _value_set(self.vpn_servers, 'server_port')
        if ip == self.bind_ip:
            ports |= _value_set(self.interfaces.filter(bind_ip=None), 'public_port')
        if ip == self.internal_ip:
            ports |= _value_set(self.services, 'port')
            ports |= _value_set(self.interfaces, 'internal_port')
        return ports


class InterfaceManager(models.Manager):
    def create(self,
               host,
               public_ip=None,
               public_port=None,
               bind_ip=None,
               bind_port=None,
               internal_port=None):
        """
        Create an Interface
        :param Host host: The host on which this Interface should be configured. Defines the AS.
        :param str public_ip: optional, the public IP for this interface to override host.public_ip
        :param int public_port: optional, a free port is selected if not specified
        :param str bind_ip: optional, the bind IP for this interface to override host.bind_ip.
        :param int bind_port: optional, a free port is selected if bind IP set and not specified
        :param int internal_port: optional, a free port is selected if not specified
        """
        as_ = host.AS
        ifid = as_.find_interface_id()
        public_port = Interface._assign_public_port(host, public_ip, public_port)
        bind_port = Interface._assign_bind_port(host, public_ip, bind_ip, bind_port)
        internal_port = Interface._assign_internal_port(host, internal_port)
        as_.bump_hosts_config()

        return super().create(
            AS=as_,
            interface_id=ifid,
            host=host,
            public_ip=public_ip,
            public_port=public_port,
            bind_ip=bind_ip,
            bind_port=bind_port,
            internal_port=internal_port
        )


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
    public_ip = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text="""Public IP for this interface. If this is not null, overrides the Host's default
            public IP."""
    )
    public_port = models.PositiveSmallIntegerField()
    bind_ip = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text="""Bind IP for this interface (optional). If `public_ip` (!) is not null, this
            overrides the Host's default bind IP.""")
    bind_port = models.PositiveSmallIntegerField(null=True, blank=True)
    internal_port = models.PositiveSmallIntegerField()

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
        if not self.public_ip and not self.host.public_ip:
            raise ValidationError(
                "If the host doesn't specify a public ip, the public ip must be specified",
                code='interface_no_public_ip'
            )

    def save(self, **kwargs):
        self.clean()
        super().save(**kwargs)

    def update(self,
               host=_placeholder,
               public_ip=_placeholder,
               public_port=_placeholder,
               bind_ip=_placeholder,
               bind_port=_placeholder,
               internal_port=_placeholder):
        """
        Update the fields for this interface and immediately `save`.
        This will trigger a configuration bump for all Hosts in all affected ASes.
        :param Host host: The host on which this Interface should be configured. Defines the AS.
        :param str public_ip: optional, the public IP for this interface to override host.public_ip
        :param int public_port: optional, a free port is selected if not specified
        :param str bind_ip: optional, the bind IP for this interface to override host.bind_ip.
        :param int bind_port: optional, a free port is selected if bind IP set and not specified
        :param int internal_port: optional, a free port is selected if not specified
        """
        prev_public_info = self._get_public_info()
        prev_local_info = self._get_local_info()

        if host is not _placeholder:
            old_as = self.AS
            new_as = host.AS
            if new_as != old_as:
                ifid = new_as.find_interface_id()   # before setting AS-relation
                self.AS = new_as
                self.interface_id = ifid
                old_as.bump_hosts_config()
            self.host = host
        if public_ip is not _placeholder:
            self.public_ip = public_ip
        if public_port is not _placeholder:
            self.public_port = Interface._assign_public_port(self.host, self.public_ip, public_port)
        if bind_ip is not _placeholder:
            self.bind_ip = bind_ip
        if bind_port is not _placeholder:
            self.bind_port = Interface._assign_bind_port(self.host, self.public_ip, self.bind_ip,
                                                         bind_port)
        if internal_port is not _placeholder:
            self.internal_port = Interface._assign_internal_port(self.host, internal_port)

        diff_public = self._get_public_info() != prev_public_info
        diff_local = self._get_local_info() != prev_local_info
        if diff_local or diff_public:
            self.AS.bump_hosts_config()
        if diff_public:
            # bump remote AS
            # if the ASes of both interfaces of a link are changed, this can be either old
            # or new AS, depending on order. Redundant but correct.
            self.remote_as().bump_hosts_config()
        self.save()

    def get_public_ip(self):
        """ Get the effective public IP for this interface """
        if self.public_ip:
            return self.public_ip
        return self.host.public_ip

    def get_bind_ip(self):
        """ Get the effective bind IP for this interface. May be None. """
        if self.public_ip:  # SIC! Overriding the public_ip enables overriding bind_ip
            return self.bind_ip
        return self.host.bind_ip

    def link(self):
        """
        Get the link associated with this interface.
        :returns: Link
        """
        return (
            Link.objects.filter(interfaceA=self) |
            Link.objects.filter(interfaceB=self)
        ).get()

    def remote_interface(self):
        """
        Get the "other" interface of the link associated with this interface.
        :returns: Interface
        """
        # FIXME(matzf): naive queries
        link = self.link()
        if self == link.interfaceA:
            return link.interfaceB
        else:
            return link.interfaceA

    def remote_as(self):
        """
        Get the AS of the "other" interface of the link associated with this interface.
        :returns: AS
        """
        # FIXME(matzf): naive queries
        return self.remote_interface().AS

    @staticmethod
    def _assign_public_port(host, public_ip, public_port):
        """
        Helper to assign the public port. Returns the given public_port if defined,
        otherwise, selects and returns an appropriate free port.
        :param Host host:
        :param str public_ip: optional
        :param int public_port: optional
        """
        return public_port or host.find_free_port(public_ip or host.public_ip,
                                                  min=DEFAULT_PUBLIC_PORT)

    @staticmethod
    def _assign_bind_port(host, public_ip, bind_ip, bind_port):
        """
        Helper to assign the bind port. Returns the given bind_port if defined,
        otherwise, selects and returns an appropriate free port.
        :param Host host:
        :param str public_ip: optional
        :param str bind_ip: optional
        :param int bind_port: optional
        """
        if not bind_port and (bind_ip or (not public_ip and host.bind_ip)):
            return host.find_free_port(bind_ip or host.bind_ip,
                                       min=DEFAULT_PUBLIC_PORT)
        else:
            return bind_port

    @staticmethod
    def _assign_internal_port(host, internal_port):
        """
        Helper to assign the internal port. Returns the given internal_port if defined,
        otherwise, selects and returns an appropriate free port.
        :param Host host:
        :param int internal_port: optional
        """
        return internal_port or host.find_free_port(host.internal_ip,
                                                    min=DEFAULT_INTERNAL_PORT)

    def _get_public_info(self):
        """
        Helper for update: return the information that when changed triggers an update
        of both the remote and the local AS.
        """
        return [self.host.AS, self.get_public_ip(), self.public_port]

    def _get_local_info(self):
        """
        Helper for update: return the information that when changed triggers an update
        of only the local AS.
        """
        return [self.get_bind_ip(), self.bind_port, self.host.internal_ip, self.internal_port]


class LinkManager(models.Manager):
    def create(self, type, interfaceA, interfaceB, active=True):
        """
        Create a Link
        :param str type: Link type (Link.PROVIDER, Link.CORE, or Link.PEER)
        :param Interface interfaceA: interface representing the A side of the link
        :param Interface interfaceB: interface representing the B side of the link
        :param bool active: is the link created as active?
        :returns: Link
        """
        self._check_link(type, interfaceA.AS, interfaceB.AS)
        return super().create(
            type=type,
            active=active,
            interfaceA=interfaceA,
            interfaceB=interfaceB,
        )

    def create_from_hosts(self, type, host_a, host_b, active=True):
        """
        Create a Link connecting the given two hosts.
        Creates a default Interface for both hosts and a Link connecting the two Interfaces.
        :param str type: Link type (Link.PROVIDER, Link.CORE, or Link.PEER)
        :param Host host_a: host on the A side of the link
        :param Host host_b: host on the B side of the link
        :param bool active: is the link created as active?
        :returns: Link
        """
        self._check_link(type, host_a.AS, host_b.AS)
        interfaceA = Interface.objects.create(host=host_a)
        interfaceB = Interface.objects.create(host=host_b)
        return super().create(
            type=type,
            active=active,
            interfaceA=interfaceA,
            interfaceB=interfaceB,
        )

    def create_from_ases(self, type, as_a, as_b, active=True):
        """
        Create a link connecting the given two ASes.
        The interfaces are created on the *first* host of each AS.
        Creates a default Interface for both hosts and a Link connecting the two Interfaces.

        :param str type: Link type (Link.PROVIDER, Link.CORE, or Link.PEER)
        :param Host host_a: host on the A side of the link
        :param Host host_b: host on the B side of the link
        :param bool active: is the link created as active?
        """
        return self.create_from_hosts(
            type=type,
            active=active,
            host_a=as_a.hosts.first(),
            host_b=as_b.hosts.first(),
        )

    def _check_link(self, type, as_a, as_b):
        # TODO(matzf): validation (should be reusable for forms and for global system checks)
        # - no provider loops
        # - core links only for core ases
        # - no providers links for core ases
        # - no cross ISD provider links
        if as_a == as_b:
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

    def update(self, type=None, active=None):
        """
        Update the fields for this Link instance and the two related interfaces
        and immediately `save`. This will trigger a configuration bump for all
        Hosts in all affected ASes.
        :param str type: optional, Link type (Link.PROVIDER, Link.CORE, or Link.PEER)
        :param bool active: optional, should the link be active?
        """
        prev_info = [self.type, self.active]

        if type is not None:
            self.type = type
        if active is not None:
            self.active = active

        new_info = [self.type, self.active]
        if new_info != prev_info:
            self.save()
            self.interfaceA.AS.bump_hosts_config()
            self.interfaceB.AS.bump_hosts_config()

    def set_active(self, active):
        """
        Set the link to be active/inactive.
        This will trigger a configuration bump for all Hosts in all affected ASes.
        :param bool active: should the link be active?
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


class ServiceManager(models.Manager):
    def create(self, host, type, port=None):
        """
        Create a Service object.
        :param Host host: the host, defines the AS
        :param str type: Service type (Service.BS, PS, CS, ZK, BW, or PP)
        :returns: Service
        """
        Service._bump_affected(host, type)
        return super().create(
            AS=host.AS,
            host=host,
            type=type,
            port=Service._assign_service_port(host, type, port)
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
    port = models.PositiveSmallIntegerField(blank=True)
    type = models.CharField(
        choices=SERVICE_TYPES,
        max_length=_MAX_LEN_CHOICES_DEFAULT
    )

    objects = ServiceManager()

    def _pre_delete(self):
        """
        Called by the pre_delete signal handler `_service_pre_delete`.
        Note: the pre_delete signal has the advantage that it is called
        also for bulk deletion, while this `delete()` method is not.
        """
        Service._bump_affected(self.host, self.type)

    @staticmethod
    def _assign_service_port(host, type, port):
        """
        Helper to assign the public port. Returns the given public_port if defined,
        otherwise, selects and returns an appropriate free port.
        :param Host host: host
        :param str type: Service type
        :param int port: optional, a free port is selected if not specified
        """
        if port:
            return port

        if type == Service.ZK:
            return DEFAULT_ZOOKEEPER_PORT
        else:
            return host.find_free_port(host.internal_ip, DEFAULT_INTERNAL_PORT)

    @staticmethod
    def _bump_affected(host, type):
        """
        Helper: trigger a configuration bump for the hosts affected by a service of the given type
        on the given host.
        :param Host host:
        :param str type: Service type
        """
        if type in [Service.BS, Service.PS, Service.CS, Service.ZK]:
            host.AS.bump_hosts_config()
        else:
            host.bump_config()


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
        return VPNClient.objects.create(vpn=self, host=host, ip=self._find_client_ip())

    def server_vpn_ip(self):
        return '10.0.1.1'

    def _find_client_ip(self):
        # TODO(matzf)
        return '10.0.1.25'


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


@receiver(pre_delete, sender=Service, dispatch_uid='service_delete_callback')
def _service_pre_delete(sender, instance, using, **kwargs):
    instance._pre_delete()


def _base64encode(key):
    return base64.b64encode(key).decode()


def _base64encode_tuple(keys):
    return (_base64encode(k) for k in keys)


def _gen_sig_keypair():
    return _base64encode_tuple(lib.crypto.asymcrypto.generate_sign_keypair())


def _gen_enc_keypair():
    return _base64encode_tuple(lib.crypto.asymcrypto.generate_enc_keypair())


def _value_set(query_set, field_name):
    """
    Short-hand for creating a set out of a values-query for a single model field
    """
    return set(query_set.values_list(field_name, flat=True))
