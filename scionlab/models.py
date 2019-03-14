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

import base64
import ipaddress
import jsonfield
import os

from django import urls
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.contrib.auth.models import User as auth_User
from django.dispatch import receiver
from django.db import models
from django.db.models import F, Max
from django.db.models.signals import pre_delete, post_delete

import lib.crypto.asymcrypto

from scionlab.util import as_ids
from scionlab.util.portmap import PortMap, LazyPortMap

from scionlab.util.openvpn_config import generate_vpn_client_key_material, \
    generate_vpn_server_key_material

# TODO(matzf): some of the models use explicit create & update methods
# The interface of these methods should be revisited & check whether
# we can make better use of e.g. changed_data information of the forms.

# TODO(matzf) move to common definitions module?

MAX_PORT = 2**16-1
""" Max value for ports """

MAX_INTERFACE_ID = 2**12-1

USER_AS_ID_BEGIN = as_ids.parse('ffaa:1:1')
USER_AS_ID_END = as_ids.parse('ffaa:1:ffff')

DEFAULT_PUBLIC_PORT = 50000    # 30042-30051 (suggested by scion/wiki/default-port-ranges)
DEFAULT_INTERNAL_PORT = 31045  # 30242-30251
DEFAULT_CONTROL_PORT = 30045   # 30042-30051

DEFAULT_BS_PORT = 31041  # 30252
DEFAULT_PS_PORT = 31043  # 30253
DEFAULT_CS_PORT = 31042  # 30254
DEFAULT_ZK_PORT = 2181
DEFAULT_BW_PORT = 40001
DEFAULT_PP_PORT = 40002
DISPATCHER_PORT = 30041

DEFAULT_HOST_INTERNAL_IP = "127.0.0.1"
DEFAULT_LINK_MTU = 1500 - 20 - 8
DEFAULT_LINK_BANDWIDTH = 1000

DEFAULT_MAX_ROUTER_INTERFACES = 12

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

    class Meta:
        verbose_name = 'ISD'
        verbose_name_plural = 'ISDs'

    def __str__(self):
        if self.label:
            return 'ISD %d (%s)' % (self.isd_id, self.label)
        else:
            return 'ISD %d' % self.isd_id

    def init_trc_and_certificates(self):
        """
        Generate the TRC and all AS and Core AS Certificates and for all ASes in this ISD.
        Ensures that the certificates are updated in the correct order, i.e. Core AS certificates
        first.
        All updated objects are saved.
        """
        self._generate_trc()
        for as_ in self.ases.filter(is_core=True).iterator():
            self._update_coreas_certificates(as_)
            as_.save()

        for as_ in self.ases.filter(is_core=False).iterator():
            self._update_as_certificates(as_)
            as_.save()

    def update_trc_and_core_certificates(self, cached_ases=[]):
        """
        Update the TRC and the Core AS Certificates for all the core-ASes in this ISD.

        All AS objects not in `cached_ases` are saved. The ISD object is saved.

        :param iterable[AS] cached_ases: AS objects previously retrieved from the DB. Updated but
                                         not saved by this function.
        """
        self._generate_trc()

        cached_as_pks = [as_.pk for as_ in cached_ases]
        for as_ in self.ases.exclude(pk__in=cached_as_pks).filter(is_core=True).iterator():
            self._update_coreas_certificates(as_)
            as_.save()
        for as_ in cached_ases:
            if as_.isd_id == self.pk and as_.is_core:
                self._update_coreas_certificates(as_)

    def _generate_trc(self):
        from scionlab.util.certificates import generate_trc
        self.trc, self.trc_priv_keys = generate_trc(self)
        self.save()

    @staticmethod
    def _update_as_certificates(as_):
        as_.update_certificate_chain()
        as_.hosts.bump_config()

    @staticmethod
    def _update_coreas_certificates(as_):
        as_.update_core_certificate()
        as_.update_certificate_chain()
        as_.hosts.bump_config()


class ASManager(models.Manager):
    def create(self, isd, as_id, is_core=False, label=None, mtu=None, owner=None,
               init_certificates=True):
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
            mtu=mtu or DEFAULT_LINK_MTU,
            owner=owner,
        )
        as_.init_keys()
        if init_certificates:
            as_.init_certificates()
        as_.save()
        return as_

    def create_with_default_services(self, isd, as_id, public_ip,
                                     is_core=False, label=None, mtu=None, owner=None,
                                     bind_ip=None, internal_ip=None,
                                     init_certificates=True):
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
            mtu=mtu,
            owner=owner,
            init_certificates=init_certificates
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
    mtu = models.PositiveIntegerField(default=DEFAULT_LINK_MTU,
                                      help_text="Maximum Transfer Unit for intra AS packets.")

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

    certificate_chain = jsonfield.JSONField(null=True, blank=True)
    core_certificate = jsonfield.JSONField(null=True, blank=True)

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
            self.is_core = False
            self.isd.update_trc_and_core_certificates(cached_ases=[self])
        self.hosts.bump_config()

    def is_infrastructure_AS(self):
        return self.owner is None

    def isd_as_str(self):
        """
        :return: the ISD-AS string representation
        """
        return '%d-%s' % (self.isd.isd_id, self.as_id)

    isd_as_str.short_description = 'ISD-AS'

    def as_path_str(self):
        """
        :return: the AS string representation in the file format
        """
        return self.as_id.replace(":", "_")

    def isd_as_path_str(self):
        """
        :return: the ISD-AS string representation in the file format
        """
        return self.isd_as_str().replace(":", "_")

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
            self._gen_core_keys()

    def init_certificates(self):
        """
        Generate certificates for the current set of AS keys.
        If this is a core AS, also update the TRC and core AS certificates.
        """
        if self.is_core:
            self.isd.update_trc_and_core_certificates(cached_ases=[self])
        else:
            self.update_certificate_chain()

    def update_keys(self):
        """
        Generate new signing and encryption key pairs. Update the certificate.
        Bumps the configuration version on all affected hosts.
        """
        # TODO(matzf): in coming scion versions, the master key can be updated too.
        self._gen_keys()
        self.update_certificate_chain()
        self.hosts.bump_config()

    def update_core_keys(self):
        """
        Generate new core AS signing key pairs. Update the TRC and subsequently all core
        certificates.
        Bumps the configuration version on all affected hosts.
        """
        self._gen_core_keys()
        if self.is_core:
            self.isd.update_trc_and_core_certificates(cached_ases=[self])

    def update_certificate_chain(self):
        """
        Create or update the AS Certificate chain.

        Requires that the TRC in this ISD exists/is up to date.

        Requires that a Core AS in this ISD with existing/up to date Core AS Certificate exists;
        for core ASes, `update_core_certificate` needs to be called first.
        See ASManager.update_certificates, which creates the certificates in the correct order.
        """
        from scionlab.util.certificates import generate_as_certificate_chain
        if self.is_core:
            issuer = self
        else:
            # Find an issuer:
            candidates = self.isd.ases.filter(is_core=True)
            issuer = candidates.first()

        if issuer:  # Skip if failed to find a core AS as issuer
            self.certificate_chain = generate_as_certificate_chain(self, issuer)

    def update_core_certificate(self):
        """
        Create or update the Core AS Certificate.

        Requires that the TRC in this ISD exists/is up to date.
        """
        from scionlab.util.certificates import generate_core_certificate
        self.core_certificate = generate_core_certificate(self)

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

    def _change_isd(self, isd):
        """
        Change the AS to be part of a different ISD.
        Bump the corresponding indicators, so that certificates will be renewed
        and the configuration will updated on all affected hosts.
        Note: does *not* check/update any links etc.
        """
        if self.is_core:
            raise NotImplementedError

        self.isd = isd
        self.update_certificate_chain()
        self.hosts.bump_config()

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
        user_as.init_certificates()
        user_as.save()
        user_as.init_default_services(
            public_ip=public_ip,
            bind_ip=bind_ip,
        )

        host = user_as.hosts.get()

        if use_vpn:
            vpn_client = attachment_point.vpn.create_client(host=host,
                                                            active=True)

            interface_client = Interface.objects.create(
                border_router=BorderRouter.objects.first_or_create(host),
                public_ip=vpn_client.ip,
                public_port=public_port,
            )
            interface_ap = Interface.objects.create(
                border_router=attachment_point.get_border_router_for_useras_interface(),
                public_ip=attachment_point.vpn.server_vpn_ip()
            )
        else:
            interface_client = Interface.objects.create(
                border_router=BorderRouter.objects.first_or_create(host),
                public_port=public_port,
                bind_port=bind_port
            )
            interface_ap = Interface.objects.create(
                border_router=attachment_point.get_border_router_for_useras_interface(),
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

        if self.isd != attachment_point.AS.isd:
            self._change_isd(attachment_point.AS.isd)

        host.update(
            public_ip=public_ip,
            bind_ip=bind_ip
        )

        link = self._get_ap_link()
        interface_ap = link.interfaceA
        interface_user = link.interfaceB
        if use_vpn:
            vpn_client = self._create_or_activate_vpn_client(attachment_point.vpn)
            interface_user.update(
                public_ip=vpn_client.ip,
                public_port=public_port,
                bind_port=None
            )
            interface_ap.update(
                border_router=attachment_point.get_border_router_for_useras_interface(),
                public_ip=attachment_point.vpn.server_vpn_ip(),
                public_port=None,
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
                border_router=attachment_point.get_border_router_for_useras_interface(),
                public_ip=None,
                public_port=None,
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
            return vpn.create_client(host, True)


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

    def get_border_router_for_useras_interface(self):
        """
        Selects the preferred border router on which the Interfaces to UserASes should be configured
        :returns: a `BorderRouter` of the related `AS`
        """
        if self.vpn is not None:
            assert(self.vpn.server.AS == self.AS)
            host = self.vpn.server
        else:
            host = self.AS.hosts.filter(public_ip__isnull=False)[0]
        return BorderRouter.objects.first_or_create(host)

    def check_vpn_available(self):
        """
        Raise ValidationError if the attachment point does not support VPN.
        """
        if self.vpn is None:
            raise ValidationError("Selected attachment point does not support VPN",
                                  code='attachment_point_no_vpn')


class HostManager(models.Manager):
    def create(self, secret=None, **kwargs):
        secret = secret or Host._gen_secret()
        return super().create(
            secret=secret,
            **kwargs
        )

    def bump_config(self):
        """
        Increment the config version counter, i.e. set `needs_config_deployement` to True.
        """
        self.update(config_version=F('config_version') + 1)

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
    secret = models.CharField(max_length=_MAX_LEN_DEFAULT, null=True, blank=True)

    # TODO(matzf): we may need additional information for container or VM
    # initialisation (to access the host's host)

    config_version = models.PositiveIntegerField(default=1)
    config_version_deployed = models.PositiveIntegerField(default=0)

    objects = HostManager()

    class Meta:
        unique_together = ('AS', 'internal_ip')

    def path_str(self):
        return'%s__%s' % (self.AS.isd_as_path_str(), str(self.internal_ip).replace(":", "_"))

    def __str__(self):
        if self.label:
            return self.label
        return '%s,[%s]' % (self.AS.isd_as_str(), self.internal_ip)

    def update(self,
               internal_ip=_placeholder,
               public_ip=_placeholder,
               bind_ip=_placeholder,
               label=_placeholder,
               managed=_placeholder,
               management_ip=_placeholder,
               secret=_placeholder):
        """
        Update the specified fields of this host instance, and immediately `save`.
        Updates to the IPs will trigger a configuration bump for all Hosts in all affected ASes.

        :param str internal_ip: optional, IP of the host in the AS
        :param str public_ip: optional, default public IP for border router interfaces on this host
        :param str bind_ip: optional, default bind IP for border router interfaces on this host
        :param str label: optional
        :param bool managed: optional
        :param str management_ip: optional, public IP of the host for management
        :param str secret: optional, a secret to authenticate the host. If `None` is given, a new
                           random secret is generated.
        """

        prev_internal_ip = self.internal_ip
        prev_public_ip = self.public_ip
        prev_bind_ip = self.bind_ip

        if internal_ip is not _placeholder:
            self.internal_ip = internal_ip or None
        if public_ip is not _placeholder:
            self.public_ip = public_ip or None
        if bind_ip is not _placeholder:
            self.bind_ip = bind_ip or None
        if label is not _placeholder:
            self.label = label or None
        if managed is not _placeholder:
            self.managed = managed
        if management_ip is not _placeholder:
            self.management_ip = management_ip or None
        if secret is not _placeholder:
            self.secret = secret or self._gen_secret()
        self.save()

        bump_internal_ip = (self.internal_ip != prev_internal_ip) and self.services.exists()
        has_affected_interfaces = self.interfaces.filter(public_ip=None).exists()
        bump_public_ip = (self.public_ip != prev_public_ip) and has_affected_interfaces
        bump_bind_ip = (self.bind_ip != prev_bind_ip) and has_affected_interfaces

        if bump_internal_ip or bump_public_ip or bump_bind_ip:
            self.AS.hosts.bump_config()
        if bump_public_ip:
            # bump affected remote ASes
            for interface in self.interfaces.filter(public_ip=None).iterator():
                interface.remote_as().hosts.bump_config()

    def bump_config(self):
        self.config_version += 1
        self.save()

    def needs_config_deployment(self):
        """
        Has the configuration for the services/interfaces running on this Host changed since the
        last deployment?
        """
        return self.config_version_deployed < self.config_version

    def find_free_port(self, ip, min, max=MAX_PORT, preferred=None):
        """
        Get a free port for this IP address in the given range.

        Note: if more than one port needs to be assigned, use the PortMap returned by get_port_map
        instead.

        :param ip: IP address or `None` for the unspecified address
        :param int min: Start of acceptable port range
        :param int max: Optional, end (included) of acceptable port range
        :param int preferred: Optional, preferred port. Will be selected if free (range not checked)
        :returns: Port
        :raises: RuntimeError if no port could be found
        """
        return self.get_port_map().get_port(ip, min, max, preferred)

    def get_port_map(self):
        """
        Find a set of ports used.
        :returns: PortMap of used ports
        """
        portmap = PortMap()
        portmap.add(None, DISPATCHER_PORT)

        for internal_port, control_port in \
                self.border_routers.values_list('internal_port', 'control_port'):
            portmap.add(self.internal_ip, internal_port)
            portmap.add(self.internal_ip, control_port)

        # Note: could also use values_list for interface ports, but slightly more complicated
        for interface in self.interfaces.iterator():
            portmap.add(interface.get_public_ip(), interface.public_port)
            if interface.get_bind_ip():
                portmap.add(interface.get_bind_ip(), interface.bind_ip)

        for port, in self.services.values_list('port'):
            portmap.add(self.internal_ip, port)

        for port, in self.vpn_servers.values_list('server_port'):
            portmap.add(self.internal_ip, port)

        return portmap

    @staticmethod
    def _gen_secret():
        return base64.urlsafe_b64encode(os.urandom(16)).decode().rstrip('=')


class InterfaceManager(models.Manager):
    def create(self,
               border_router,
               public_ip=None,
               public_port=None,
               bind_ip=None,
               bind_port=None):
        """
        Create an Interface
        :param BorderRouter border_router: The border router process running responsible for this
                                           interface. Defines the AS and the host.
        :param str public_ip: optional, the public IP for this interface to override host.public_ip
        :param int public_port: optional, a free port is selected if not specified
        :param str bind_ip: optional, the bind IP for this interface to override host.bind_ip.
        :param int bind_port: optional, a free port is selected if bind IP set and not specified
        """
        host = border_router.host
        as_ = host.AS
        ifid = as_.find_interface_id()

        effective_public_ip = public_ip or host.public_ip
        effective_bind_ip = bind_ip if public_ip else host.bind_ip

        portmap = LazyPortMap(host.get_port_map)
        if public_port is None:
            public_port = portmap.get_port(effective_public_ip, DEFAULT_PUBLIC_PORT)
        if bind_port is None and effective_bind_ip is not None:
            bind_port = portmap.get_port(effective_bind_ip,
                                         min=DEFAULT_PUBLIC_PORT,
                                         preferred=public_port)

        as_.hosts.bump_config()

        return super().create(
            AS=as_,
            interface_id=ifid,
            host=host,
            border_router=border_router,
            public_ip=public_ip,
            public_port=public_port,
            bind_ip=bind_ip,
            bind_port=bind_port,
        )

    def active(self):
        """
        return list of Interfaces from active links
        """
        return self.filter(link_as_interfaceA__active=True) |\
            self.filter(link_as_interfaceB__active=True)


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
    border_router = models.ForeignKey(
        'BorderRouter',
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

    objects = InterfaceManager()

    def __str__(self):
        return '%s [IF %i]' % (self.AS, self.interface_id)

    def _pre_delete(self):
        """
        Called by the pre_delete signal handler `_interface_pre_delete`.
        Note: the deletion-signals have the advantage that they are triggerd
        also for bulk deletion, while the `delete()` method is not.
        """
        self.AS.hosts.bump_config()

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
               border_router=_placeholder,
               public_ip=_placeholder,
               public_port=_placeholder,
               bind_ip=_placeholder,
               bind_port=_placeholder):
        """
        Update the fields for this interface and immediately `save`.
        This will trigger a configuration bump for all Hosts in all affected ASes.
        :param BorderRouter border_router: optional, defines the Host and the AS.
        :param str public_ip: optional, the public IP for this interface to override host.public_ip
        :param int public_port: optional, a free port is selected if `None` is passed and either
                                `host` or `public_ip` are changed.
        :param str bind_ip: optional, the bind IP for this interface to override host.bind_ip.
        :param int bind_port: optional, if bind IP is set, a free port is selected if `None` is
                              passed and either `host` or `bind_ip` are changed
        """
        prev_host = self.host
        prev_public_ip = self.get_public_ip()
        prev_bind_ip = self.get_bind_ip()
        prev_public_info = self._get_public_info()
        prev_local_info = self._get_local_info()

        self._update_as_host_router(border_router)

        if public_ip is not _placeholder:
            self.public_ip = public_ip or None
        if bind_ip is not _placeholder:
            self.bind_ip = bind_ip or None

        self._update_ports(public_port,
                           bind_port,
                           host_changed=self.host != prev_host,
                           public_ip_changed=self.get_public_ip() != prev_public_ip,
                           bind_ip_changed=self.get_bind_ip() != prev_bind_ip)

        self.save()

        diff_public = self._get_public_info() != prev_public_info
        diff_local = self._get_local_info() != prev_local_info
        if diff_local or diff_public:
            self.AS.hosts.bump_config()
        if diff_public:
            # bump remote AS
            # if the ASes of both interfaces of a link are changed, this can be either old
            # or new AS, depending on order. Redundant but correct.
            self.remote_as().hosts.bump_config()

    def _update_as_host_router(self, border_router):
        """ Helper: set AS, host and border_router, bump hosts in old AS if AS is changed. """
        if border_router is not _placeholder:
            host = border_router.host
            old_as = self.AS
            new_as = host.AS
            if new_as != old_as:
                ifid = new_as.find_interface_id()   # before setting AS-relation
                self.AS = new_as
                self.interface_id = ifid
                old_as.hosts.bump_config()
            self.host = host
            self.border_router = border_router

    def _update_ports(self, public_port, bind_port,
                      host_changed, public_ip_changed, bind_ip_changed):
        """ Helper: update public port and bind port. """

        portmap = LazyPortMap(self.host.get_port_map)
        if public_port is not _placeholder:
            if public_port is not None:
                self.public_port = public_port
            elif host_changed or public_ip_changed:
                self.public_port = portmap.get_port(self.get_public_ip(), DEFAULT_PUBLIC_PORT)

        if bind_port is not _placeholder:
            if bind_port is not None:
                self.bind_port = bind_port
            elif not self.get_bind_ip():
                self.bind_port = None
            elif host_changed or bind_ip_changed:
                self.bind_port = portmap.get_port(self.get_bind_ip(),
                                                  min=DEFAULT_PUBLIC_PORT,
                                                  preferred=self.public_port)

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
        if hasattr(self, 'link_as_interfaceA'):
            return self.link_as_interfaceA
        else:
            return self.link_as_interfaceB

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

    def _get_public_info(self):
        """
        Helper for update: return the information that when changed triggers an update
        of both the remote and the local AS.
        """
        return [self.AS, self.get_public_ip(), self.public_port]

    def _get_local_info(self):
        """
        Helper for update: return the information that when changed triggers an update
        of only the local AS.
        """
        return [self.border_router, self.get_bind_ip(), self.bind_port]


class LinkManager(models.Manager):
    def create(self, type, interfaceA, interfaceB, active=True, bandwidth=None, mtu=None):
        """
        Create a Link
        :param str type: Link type (Link.PROVIDER, Link.CORE, or Link.PEER)
        :param Interface interfaceA: interface representing the A side of the link
        :param Interface interfaceB: interface representing the B side of the link
        :param bool active: is the link created as active?
        :param int bandwidth: optional, bandwidth for this link
        :param int mtu: optional, MTU for this link
        :returns: Link
        """
        self._check_link(type, interfaceA.AS, interfaceB.AS)
        return super().create(
            type=type,
            active=active,
            bandwidth=bandwidth or DEFAULT_LINK_BANDWIDTH,
            mtu=mtu or DEFAULT_LINK_MTU,
            interfaceA=interfaceA,
            interfaceB=interfaceB,
        )

    def create_from_hosts(self, type, host_a, host_b, active=True, bandwidth=None, mtu=None):
        """
        Create a Link connecting the given two hosts.
        Creates a default Interface for both hosts and a Link connecting the two Interfaces.
        :param str type: Link type (Link.PROVIDER, Link.CORE, or Link.PEER)
        :param Host host_a: host on the A side of the link
        :param Host host_b: host on the B side of the link
        :param bool active: is the link created as active?
        :param int bandwidth: optional, bandwidth for this link
        :param int mtu: optional, MTU for this link
        :returns: Link
        """
        self._check_link(type, host_a.AS, host_b.AS)
        br_a = BorderRouter.objects.first_or_create(host_a)
        br_b = BorderRouter.objects.first_or_create(host_b)
        interfaceA = Interface.objects.create(border_router=br_a)
        interfaceB = Interface.objects.create(border_router=br_b)
        return super().create(
            type=type,
            active=active,
            bandwidth=bandwidth or DEFAULT_LINK_BANDWIDTH,
            mtu=mtu or DEFAULT_LINK_MTU,
            interfaceA=interfaceA,
            interfaceB=interfaceB,
        )

    def create_from_ases(self, type, as_a, as_b, active=True, bandwidth=None, mtu=None):
        """
        Create a link connecting the given two ASes.
        The interfaces are created on the *first* host of each AS.
        Creates a default Interface for both hosts and a Link connecting the two Interfaces.

        :param str type: Link type (Link.PROVIDER, Link.CORE, or Link.PEER)
        :param Host host_a: host on the A side of the link
        :param Host host_b: host on the B side of the link
        :param bool active: is the link created as active?
        :param int bandwidth: optional, bandwidth for this link
        :param int mtu: optional, MTU for this link
        :returns: Link
        """
        return self.create_from_hosts(
            type=type,
            active=active,
            bandwidth=bandwidth,
            mtu=mtu,
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
        (PROVIDER, 'Provider link from parent A to child B'),
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
    bandwidth = models.PositiveIntegerField(default=DEFAULT_LINK_BANDWIDTH)
    mtu = models.PositiveIntegerField(default=DEFAULT_LINK_MTU)

    objects = LinkManager()

    def __str__(self):
        return '%s -- %s' % (self.interfaceA, self.interfaceB)

    def _post_delete(self):
        """
        Called by the post_delete signal handler `_link_spost_delete`.
        Note: this is triggered by _post_delete to allow checking whether the
        related interfaces have already been deleted, and avoid recursion.
        Note: the deletion-signals have the advantage that they are triggerd
        also for bulk deletion, while the `delete()` method is not.
        """
        for interface in filter(None, [self.get_interface_a(), self.get_interface_b()]):
            interface.delete()

    def update(self, type=None, active=None, bandwidth=None, mtu=None):
        """
        Update the fields for this Link instance and the two related interfaces
        and immediately `save`. This will trigger a configuration bump for all
        Hosts in all affected ASes.
        :param str type: optional, Link type (Link.PROVIDER, Link.CORE, or Link.PEER)
        :param bool active: optional, should the link be active?
        """
        prev_info = [self.type, self.active, self.bandwidth, self.mtu]

        if type is not None:
            self.type = type
        if active is not None:
            self.active = active
        if bandwidth is not None:
            self.bandwidth = bandwidth
        if mtu is not None:
            self.mtu = mtu

        curr_info = [self.type, self.active, self.bandwidth, self.mtu]
        if curr_info != prev_info:
            self.save()
            self.interfaceA.AS.hosts.bump_config()
            self.interfaceB.AS.hosts.bump_config()

    def set_active(self, active):
        """
        Set the link to be active/inactive.
        This will trigger a configuration bump for all Hosts in all affected ASes.
        :param bool active: should the link be active?
        """
        if self.active != active:
            self.active = active
            self.save()
            self.interfaceA.AS.hosts.bump_config()
            self.interfaceB.AS.hosts.bump_config()

    def get_interface_a(self):
        if hasattr(self, 'interfaceA'):
            return self.interfaceA
        return None

    def get_interface_b(self):
        if hasattr(self, 'interfaceB'):
            return self.interfaceB
        return None


class BorderRouterManager(models.Manager):
    def create(self, host, internal_port=None, control_port=None):
        """
        Create a BorderRouter object.
        :param Host host: the host, defines the AS
        :param int internal_port: optional, port, assigned automatically if not specified
        :param int control_port: optional, port, assigned automatically if not specified
        :returns: BorderRouter
        """
        host.AS.hosts.bump_config()
        portmap = LazyPortMap(host.get_port_map)
        if not internal_port:
            internal_port = portmap.get_port(host.internal_ip, DEFAULT_INTERNAL_PORT)
        if not control_port:
            control_port = portmap.get_port(host.internal_ip, DEFAULT_CONTROL_PORT)

        return super().create(
            AS=host.AS,
            host=host,
            internal_port=internal_port,
            control_port=control_port
        )

    def first_or_create(self, host):
        """
        Get the first border router related to this host, or create a new one with default settings.
        :param Host host: the host, defines the AS
        :returns: BorderRouter
        """
        return host.border_routers.first() or self.create(host=host)


class BorderRouter(models.Model):
    """
    A BorderRouter object represents the actual `border`-process executing an Interface.
    It stores the per-border-router settings (internal addess port and control addess port).
    """
    AS = models.ForeignKey(
        AS,
        related_name='border_routers',
        on_delete=models.CASCADE,
    )
    host = models.ForeignKey(
        Host,
        related_name='border_routers',
        on_delete=models.CASCADE
    )
    internal_port = models.PositiveSmallIntegerField(blank=True)
    control_port = models.PositiveSmallIntegerField(blank=True)

    objects = BorderRouterManager()

    def update(self, host=_placeholder, internal_port=_placeholder, control_port=_placeholder):
        """
        Update the given fields
        :param Host host: optional, the host. Must be in current AS.
        :param int internal_port: optional, port. A free port is selected if `None` is passed and
                                  the host is changed.
        :param int control_port: optional, port. A free port is selected if `None` is passed and
                                  the host is changed.
        """
        prev_host = self.host
        prev_info = [self.host, self.internal_port, self.control_port]

        if host is not _placeholder:
            if host.AS != self.AS:
                # Moving BR to different AS not supported. Would be doable (the Interface.update
                # already implements this) but not currently useful.
                raise RuntimeError('BorderRouter.update cannot change AS')
            self.host = host

        self._update_ports(internal_port,
                           control_port,
                           host_changed=self.host != prev_host)
        self.save()

        curr_info = [self.host, self.internal_port, self.control_port]
        if curr_info != prev_info:
            host.AS.hosts.bump_config()

    def _update_ports(self, internal_port, control_port, host_changed):
        """ Helper: update internal and control port. """
        portmap = LazyPortMap(self.host.get_port_map)
        if internal_port is not _placeholder:
            if internal_port is not None:
                self.internal_port = internal_port
            elif host_changed:
                self.internal_port = portmap.get_port(self.host.internal_ip, DEFAULT_INTERNAL_PORT)

        if control_port is not _placeholder:
            if control_port is not None:
                self.control_port = control_port
            elif host_changed:
                self.control_port = portmap.get_port(self.host.internal_ip, DEFAULT_CONTROL_PORT)


class ServiceManager(models.Manager):
    def create(self, host, type, port=None):
        """
        Create a Service object.
        :param Host host: the host, defines the AS
        :param str type: Service type (Service.BS, PS, CS, ZK, BW, or PP)
        :param int port: optional, port, assigned automatically if not specified
        :returns: Service
        """
        host.AS.hosts.bump_config()
        return super().create(
            AS=host.AS,
            host=host,
            type=type,
            port=port or Service._find_service_port(host, type)
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
    DEFAULT_PORTS = {
        BS: DEFAULT_BS_PORT,
        PS: DEFAULT_PS_PORT,
        CS: DEFAULT_CS_PORT,
        ZK: DEFAULT_ZK_PORT,
        BW: DEFAULT_BW_PORT,
        PP: DEFAULT_PP_PORT,
    }

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

    def update(self, host=_placeholder, port=_placeholder):
        """
        Update the given fields of the
        :param Host host: optional, the host
        :param str port: optional, port. A free port is selected if `None` is passed and the host is
                         changed.
        """
        prev_host = self.host
        prev_info = [self.host, self.port]

        if host is not _placeholder:
            if host != self.host:
                self._bump_affected(self.host, self.type)
            self.host = host

        if port is not _placeholder:
            if port is not None:
                self.port = port
            elif self.host != prev_host:
                self.port = Service._find_service_port(self.host, self.type)

        self.save()

        curr_info = [self.host, self.port]
        if curr_info != prev_info:
            self._bump_affected(self.host, self.type)

    @staticmethod
    def _find_service_port(host, type):
        """
        Helper to assign the public port.
        :param Host host: host
        :param str type: Service type
        """
        default_port = Service.DEFAULT_PORTS[type]
        return host.find_free_port(host.internal_ip, min=default_port)

    @staticmethod
    def _bump_affected(host, type, prev_host=None):
        """
        Helper: trigger a configuration bump for the hosts affected by a service of the given type
        on the given host.
        :param Host host:
        :param str type: Service type
        :param Host prev_host:
        """
        if type in [Service.BS, Service.PS, Service.CS, Service.ZK]:
            host.AS.hosts.bump_config()
        else:
            host.bump_config()


class VPNManager(models.Manager):
    def create(self, server, server_port, subnet):
        vpn = VPN(
            server=server,
            server_port=server_port,
            subnet=subnet,
        )
        vpn.init_key()
        vpn.save()
        return vpn


class VPN(models.Model):
    server = models.ForeignKey(
        Host,
        related_name='vpn_servers',
        on_delete=models.CASCADE
    )
    server_port = models.PositiveSmallIntegerField()

    subnet = models.CharField(max_length=15)
    private_key = models.TextField(null=True, blank=True)
    cert = models.TextField(null=True, blank=True)
    dh_params = models.TextField(null=True, blank=True)

    objects = VPNManager()

    def init_key(self):
        key, dh_params, cert = generate_vpn_server_key_material(self.server)
        self.private_key = key
        self.dh_params = dh_params
        self.cert = cert

    def create_client(self, host, active):
        client_ip = str(self._find_client_ip())
        return VPNClient.objects.create(vpn=self, host=host, ip=client_ip, active=active)

    def server_vpn_ip(self):
        """
        :return: str: VPN server IP
        """
        subnet = ipaddress.ip_network(self.subnet)
        # Use first address in the VPN subnet for the VPN server IP
        return str(next(subnet.hosts()))

    def vpn_subnet(self):
        return ipaddress.ip_network(self.subnet)

    def vpn_subnet_min_max_client_ips(self):
        subnet = self.vpn_subnet()
        # First host IP in the VPN subnet is the server IP
        # return first and last client IP in the subnet
        _, min_ip, *_, max_ip = subnet.hosts()
        return min_ip, max_ip

    def _find_client_ip(self):
        last_client = self.clients.last()
        used_ips = {self.server_vpn_ip()} | \
            _value_set(VPNClient.objects.filter(vpn=self), 'ip')
        if last_client:
            last_assigned_ip = ipaddress.ip_address(last_client.ip)
            # assign consecutive IPs to clients in the same VPN
            candidate_ip = last_assigned_ip + 1
            _, max_ip = self.vpn_subnet_min_max_client_ips()
            if candidate_ip <= max_ip and str(candidate_ip) not in used_ips:
                return candidate_ip
        # try to find an unused IP from a removed client
        subnet = ipaddress.ip_network(self.subnet)
        for ip in subnet.hosts():
            if str(ip) not in used_ips:
                return ip
        raise RuntimeError('No free client IP available')


class VPNClientManager(models.Manager):
    def create(self, vpn, host, ip, active):
        client = VPNClient(
            vpn=vpn,
            host=host,
            ip=ip,
            active=active
        )
        client.init_key()
        client.save()
        return client


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
    private_key = models.TextField(null=True, blank=True)
    cert = models.TextField(null=True, blank=True)

    objects = VPNClientManager()

    def init_key(self):
        key, cert = generate_vpn_client_key_material(self.host.AS)
        self.private_key = key
        self.cert = cert


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
