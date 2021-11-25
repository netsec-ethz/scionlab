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

"""
:mod:`scionlab.models.core` --- Django models for SCION network representation
==============================================================================
"""

import base64
import os
import uuid

from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.dispatch import receiver
from django.db import models
from django.db.models import F, Count
from django.db.models.signals import pre_delete, post_delete
from django.utils.functional import cached_property
from datetime import datetime

from scionlab.models.user import User
from scionlab.models.pki import Key, Certificate
from scionlab.scion import as_ids
from scionlab.scion.certs import verify_certificate_valid, verify_cp_as_chain
from scionlab.scion.keys import verify_key
from scionlab.scion.trcs import decode_trc, verify_trcs
from scionlab.scion.pkicommand import ScionPkiError
from scionlab.util.django import value_set
from scionlab.defines import (
    MAX_INTERFACE_ID,
    MAX_PORT,
    DEFAULT_PUBLIC_PORT,
    BR_INTERNAL_PORT_BASE,
    BR_METRICS_PORT_BASE,
    CS_PORT,
    CS_METRICS_PORT,
    SIG_CTRL_PORT,
    CO_PORT,
    BW_PORT,
    PP_PORT,
    DEFAULT_HOST_INTERNAL_IP,
    DEFAULT_LINK_MTU,
)

_MAX_LEN_DEFAULT = 255
""" Max length value for fields without specific requirements to max length """
_MAX_LEN_CHOICES_DEFAULT = 16
""" Max length value for choices fields without specific requirements to max length """
_MAX_LEN_KEYS = 255
""" Max length value for base64 encoded AS keys """

_placeholder = object()
""" Placeholder value for optional parameters, different from None """


class TimestampedModel(models.Model):
    """
    Helper model-base-class to include created/modified timestamps.
    """
    created_date = models.DateTimeField(auto_now_add=True)
    modified_date = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class ISD(TimestampedModel):
    isd_id = models.PositiveIntegerField()
    label = models.CharField(max_length=_MAX_LEN_DEFAULT, null=True, blank=True)

    class Meta:
        verbose_name = 'ISD'
        verbose_name_plural = 'ISDs'

    def __str__(self):
        if self.label:
            return 'ISD %d (%s)' % (self.isd_id, self.label)
        else:
            return 'ISD %d' % self.isd_id

    def update_trc_and_certificates(self):
        """
        Generate the TRC and all AS and Core AS Certificates and for all ASes in this ISD.
        Ensures that the certificates are updated in the correct order, i.e. Core AS certificates
        first, then AS certificates, then TRC.
        All updated objects are saved.
        """
        if not self.ases.filter(is_core=True).exists():
            return None

        # regenerate certificates for every AS: non core ASes could need regeneration due to
        # a replaced issuer core AS.
        # First core ASes
        for as_ in self.ases.filter(is_core=True):
            as_.update_keys_certs()
        # Then non-core (which need a core with a CA cert)
        for as_ in self.ases.filter(is_core=False):
            as_.update_keys_certs()

        return self.trcs.create()

    def validate_crypto(self):
        """
        checks that the crypto material for this object is correct,
        namely that the trc chain is valid.
        Returns the number of valid trcs in this ISD.
        """
        ts = [decode_trc(t.trc) for t in self.trcs.order_by('serial_version')]
        verify_trcs(ts[0], *ts)
        return len(ts)


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
        as_ = super().create(
            isd=isd,
            as_id=as_id,
            as_id_int=as_id_int,
            is_core=is_core,
            label=label,
            mtu=mtu or DEFAULT_LINK_MTU,
            owner=owner,
            master_as_key=AS._make_master_as_key()
        )

        as_.generate_keys()
        if init_certificates:
            as_.generate_certs()
            if is_core:
                isd.trcs.create()

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

    def get_by_isd_as(self, isd_as):
        """
        Get the AS given its IA ISD-ASID
        """
        groups = isd_as.split('-')
        if len(groups) != 2:
            raise ValueError('Invalid IA %s' % isd_as)
        return self.get(isd__isd_id=int(groups[0]), as_id=groups[1])


class AS(TimestampedModel):
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
        related_name='ases',
        on_delete=models.CASCADE,
        null=True,
        blank=True
    )

    master_as_key = models.CharField(max_length=_MAX_LEN_KEYS, null=True, blank=True)

    is_core = models.BooleanField(default=False)

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

    def _post_delete(self):
        """
        Called by the post_delete signal handler `_as_post_delete`.
        Note: the post_delete signal has the advantage that it is called
        also for bulk deletion, while this `delete()` method is not.
        """
        if self.is_core:
            self.isd.update_trc_and_certificates()
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

    def certificates(self):
        """ returns a queryset of all of this AS' certificates (in random order) """
        return Certificate.objects.filter(key__AS=self).order_by('?')

    def certificates_latest(self):
        """ returns a queryset of all the latest certificates of this AS """
        certs = Certificate.objects.none()
        for key_usage in Key.USAGES:
            latest_version = self.keys.filter(usage=key_usage).aggregate(models.Max('version'))[
                                 'version__max'] or 1
            certs = certs | Certificate.objects.filter(key__AS=self, key__usage=key_usage,
                                                       key__version__gte=latest_version)
        return certs

    def keys_latest(self):
        """ returns a queryset of all of the latest keys of this AS """
        keys = Key.objects.none()
        for key_usage in Key.USAGES:
            latest_version = self.keys.filter(usage=key_usage).aggregate(models.Max('version'))[
                                 'version__max'] or 1
            keys = keys | Key.objects.filter(AS=self, usage=key_usage,
                                             version__gte=latest_version)
        return keys

    def validate_crypto(self):
        """
        checks that the crypto material for this object is correct, by obtaining the
        latests certificates and keys and checking them against the latest TRC.
        Returns the number of certificates (with keys) that passed the check.
        """
        trc = decode_trc(self.isd.trcs.latest().trc)
        certs = self.certificates_latest()
        cert_map = {}
        for cert in certs:
            cert_map[cert.usage()] = cert.certificate
            verify_certificate_valid(cert.certificate, cert.usage())
            if cert.usage() == Key.CP_AS:
                verify_cp_as_chain(cert.format_certfile(), trc)  # chain
        keys = self.keys_latest()
        for key in keys:
            if key.usage not in cert_map:
                raise ScionPkiError(f'no corresponding cert for key {key.filename()}')
            verify_key(key.key, cert_map[key.usage])
        if len(keys) != len(certs):
            raise ScionPkiError(f'different number of keys ({len(keys)}) than certs ({len(certs)})')
        if (self.is_core and len(keys) != 5) or (not self.is_core and len(keys) != 1):
            raise ScionPkiError(
                f'AS {self.as_id}, core:{self.is_core}: '
                f'invalid number of keys/certs {len(keys)}')
        return len(keys)

    def generate_keys(self, not_before=None):
        Key.objects.create_all_keys(self, not_before=not_before)

    def generate_certs(self):
        Certificate.objects.create_all_certs(self)

    def update_keys_certs(self, not_before=None):
        """
        Generate new keys and certificates (core and non core).
        The keys and certs have to be updated simultaneously to avoid getting a nil validity range
        when signing a CP AS certificate; e.g. the subject has keys valid during a year, but the
        issuer's keys are valid only until last year.
        Bumps the configuration version on all affected hosts.
        """
        self.generate_keys(not_before)
        self.generate_certs()
        self.hosts.bump_config()
        self.save()

    @staticmethod
    def update_cp_as_keys(queryset):
        """
        Simply update the CP AS keys. These keys are only used for the control plane of each AS,
        so there is no need to update any other crytographic material.
        """
        for as_ in queryset:
            # find a core AS
            core_ases = AS.objects.filter(isd=as_.isd, is_core=True)
            if not core_ases.exists():
                continue
            Key.objects.create(as_, Key.CP_AS)
            Certificate.objects.create_cp_as_cert(as_, core_ases.first())
            as_.hosts.bump_config()

    @staticmethod
    def update_core_as_keys(queryset):
        """
        All the ASes in the queryset must update their keys and certificates.
        Since this some of these ASes could act as CA for other, non-core ASes,
        we must re-issue all certificates in that ISD.
        So in this function, we just update keys, certificates and TRCs for all
        core ASes in all ISDs that are touched by the given queryset.
        """
        for isd in ISD.objects.filter(pk__in=queryset.values('isd')):
            isd.update_trc_and_certificates()

    def init_default_services(self, public_ip=None, bind_ip=None, internal_ip=None):
        """
        Initialise a default Host object and the default AS services
        """
        host = Host.objects.create(
            AS=self,
            public_ip=public_ip,
            bind_ip=bind_ip,
            internal_ip=internal_ip or DEFAULT_HOST_INTERNAL_IP
        )

        default_services = (Service.CS, Service.CO, )
        for service_type in default_services:
            Service.objects.create(host=host, type=service_type)

    def find_interface_id(self):
        """
        Find an unused interface id
        """
        existing_ids = value_set(self.interfaces, 'interface_id')
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
        self.generate_certs()

        # Drop all previous certificates; these were created in a different ISD and would confuse.
        # Keep versions increasing (by generating new cert before deleting old ones); in case we
        # move back to the original ISD, we need to have a version number different from the
        # original certificate.
        # Preserve last certificate and those that were part of TRCs.
        # See also: pki._key_set_null_or_cascade
        # Since this function checks that the AS is non-core, it contains no certs. part of TRCs.
        latest = Certificate.objects.latest(usage=Key.CP_AS, AS=self)
        self.certificates().exclude(id=latest.pk).delete()

        self.hosts.bump_config()

    @staticmethod
    def _make_master_as_key():
        """
        Generate a random MasterASKey.
        The MasterASKey is used for hop field Message Authentication Codes (MAC) and Dynamically
        Recreatable Keys (DRKeys).
        """
        return _base64encode(os.urandom(16))

    def is_attachment_point(self):
        return hasattr(self, 'attachment_point_info')


class HostManager(models.Manager):
    use_in_migrations = True

    def create(self, uid=None, secret=None, **kwargs):
        uid = uid or uuid.uuid4().hex
        secret = secret or uuid.uuid4().hex
        return super().create(
            uid=uid,
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
    internal_ip = models.GenericIPAddressField(
        default=DEFAULT_HOST_INTERNAL_IP,
        help_text="IP of the host in the AS"
    )
    public_ip = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text="Default public IP for border router interfaces running on this host."
    )
    bind_ip = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text="Default bind IP for border router interfaces running on this host."
    )
    label = models.CharField(max_length=_MAX_LEN_DEFAULT, null=True, blank=True)

    ssh_host = models.CharField(
        max_length=_MAX_LEN_DEFAULT,
        null=True,
        blank=True,
        help_text="Hostname or IP for management access via SSH. Configured in run/ssh_config."
    )

    uid = models.CharField(max_length=_MAX_LEN_DEFAULT, unique=True, editable=False,
                           help_text="Identifier for API",
                           verbose_name="UID")
    secret = models.CharField(max_length=_MAX_LEN_DEFAULT,
                              help_text="Secret token for API")

    config_version = models.PositiveIntegerField(default=1)
    config_version_deployed = models.PositiveIntegerField(default=0)
    config_queried_at = models.DateTimeField(null=True, blank=True)

    objects = HostManager()

    class Meta:
        unique_together = ('AS', 'internal_ip')

    def scion_address(self):
        if self.AS:
            return '%s,[%s]' % (self.AS.isd_as_str(), self.internal_ip)
        else:
            return None

    def path_str(self):
        return'%s__%s' % (self.AS.isd_as_path_str(), str(self.internal_ip).replace(":", "_"))

    def __str__(self):
        if self.label:
            return self.label
        elif self.AS:
            return '%s,[%s]' % (self.AS.isd_as_str(), self.internal_ip)
        else:
            return '<deleted-AS>,[%s]' % self.internal_ip

    def update(self,
               internal_ip=_placeholder,
               public_ip=_placeholder,
               bind_ip=_placeholder,
               label=_placeholder,
               ssh_host=_placeholder,
               secret=_placeholder):
        """
        Update the specified fields of this host instance, and immediately `save`.
        Updates to the IPs will trigger a configuration bump for all Hosts in all affected ASes.

        :param str internal_ip: optional, IP of the host in the AS
        :param str public_ip: optional, default public IP for border router interfaces on this host
        :param str bind_ip: optional, default bind IP for border router interfaces on this host
        :param str label: optional
        :param str ssh_host: optional, hostname/IP for management access via SSH
        :param str secret: optional, a secret to authenticate the host. If `None` is given, a new
                           random secret is generated.
        """

        prev_internal_ip = self.internal_ip
        prev_public_ip = self.public_ip
        prev_bind_ip = self.bind_ip
        prev_secret = self.secret

        if internal_ip is not _placeholder:
            self.internal_ip = internal_ip or None
        if public_ip is not _placeholder:
            self.public_ip = public_ip or None
        if bind_ip is not _placeholder:
            self.bind_ip = bind_ip or None
        if label is not _placeholder:
            self.label = label or None
        if ssh_host is not _placeholder:
            self.ssh_host = ssh_host or None
        if secret is not _placeholder:
            self.secret = secret or uuid.uuid4().hex

        internal_ip_changed = (self.internal_ip != prev_internal_ip)
        public_ip_changed = (self.public_ip != prev_public_ip)
        bind_ip_changed = (self.bind_ip != prev_bind_ip)
        secret_changed = (self.secret != prev_secret)

        has_affected_interfaces = self.interfaces.filter(public_ip=None).exists()
        bump_host = internal_ip_changed or public_ip_changed or bind_ip_changed or secret_changed
        bump_local_AS = internal_ip_changed or (public_ip_changed and has_affected_interfaces)
        bump_remote_ASes = public_ip_changed and has_affected_interfaces

        if bump_host and not bump_local_AS:
            self.config_version += 1
        self.save()

        if bump_local_AS:
            self.AS.hosts.bump_config()
        if bump_remote_ASes:
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

    def find_public_port(self):
        """
        Find an unused public port for an AS interface on this Host
        """
        used_ports = value_set(self.interfaces, 'public_port')
        for candidate_port in range(DEFAULT_PUBLIC_PORT, MAX_PORT):
            if candidate_port not in used_ports:
                return candidate_port

    def update_config_queried_timestamp(self):
        self.config_queried_at = datetime.utcnow()
        self.save()


class InterfaceManager(models.Manager):
    def create(self,
               border_router,
               public_ip=None,
               public_port=None,
               bind_ip=None,
               interface_id=None):
        """
        Create an Interface
        :param BorderRouter border_router: The border router process running responsible for this
                                           interface. Defines the AS and the host.
        :param str public_ip: optional, the public IP for this interface to override host.public_ip
        :param int public_port: optional, a free port is selected if not specified
        :param str bind_ip: optional, the bind IP for this interface to override host.bind_ip.
        :param int interface_id: optional, the interface id for this interface.
        """
        host = border_router.host
        as_ = host.AS
        ifid = interface_id or as_.find_interface_id()

        if public_port is None:
            public_port = host.find_public_port()

        as_.hosts.bump_config()

        return super().create(
            AS=as_,
            interface_id=ifid,
            host=host,
            border_router=border_router,
            public_ip=public_ip,
            public_port=public_port,
            bind_ip=bind_ip,
        )

    def active(self):
        """
        return list of Interfaces from active links
        """
        return self.filter(link_as_interfaceA__active=True) | \
            self.filter(link_as_interfaceB__active=True)

    def inactive(self):
        """
        return list of Interfaces from inactive links
        """
        return self.filter(link_as_interfaceA__active=False) | \
            self.filter(link_as_interfaceB__active=False)


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
    public_port = models.PositiveIntegerField()
    bind_ip = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text="""Bind IP for this interface (optional). If `public_ip` (!) is not null, this
            overrides the Host's default bind IP.""")

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
               bind_ip=_placeholder):
        """
        Update the fields for this interface and immediately `save`.
        This will trigger a configuration bump for all Hosts in all affected ASes.
        :param BorderRouter border_router: optional, defines the Host and the AS.
        :param str public_ip: optional, the public IP for this interface to override host.public_ip
        :param int public_port: optional, a free port is selected if `None` is passed and either
                                `host` or `public_ip` are changed.
        :param str bind_ip: optional, the bind IP for this interface to override host.bind_ip.
        """
        prev_host = self.host
        prev_public_ip = self.get_public_ip()
        prev_public_info = self._get_public_info()
        prev_local_info = self._get_local_info()

        self._update_as_host_router(border_router)

        if public_ip is not _placeholder:
            self.public_ip = public_ip or None
        if bind_ip is not _placeholder:
            self.bind_ip = bind_ip or None

        if public_port is not _placeholder:
            if public_port is not None:
                self.public_port = public_port
            elif self.host != prev_host or self.get_public_ip() != prev_public_ip:
                self.public_port = self.host.find_public_port()

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
        if hasattr(self, 'link_as_interfaceA'):
            return self.link_as_interfaceA.interfaceB
        else:
            return self.link_as_interfaceB.interfaceA

    def remote_as(self):
        """
        Get the AS of the "other" interface of the link associated with this interface.
        :returns: AS
        """
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
        return [self.border_router, self.get_bind_ip()]


class LinkManager(models.Manager):
    def create(self, type, interfaceA, interfaceB, active=True, mtu=None):
        """
        Create a Link
        :param str type: Link type (Link.PROVIDER, Link.CORE, or Link.PEER)
        :param Interface interfaceA: interface representing the A side of the link
        :param Interface interfaceB: interface representing the B side of the link
        :param bool active: is the link created as active?
        :param int mtu: optional, MTU for this link
        :returns: Link
        """
        self._check_link(type, interfaceA.AS, interfaceB.AS)
        return super().create(
            type=type,
            active=active,
            mtu=mtu or DEFAULT_LINK_MTU,
            interfaceA=interfaceA,
            interfaceB=interfaceB,
        )

    def create_from_hosts(self, type, host_a, host_b, active=True, mtu=None):
        """
        Create a Link connecting the given two hosts.
        Creates a default Interface for both hosts and a Link connecting the two Interfaces.
        :param str type: Link type (Link.PROVIDER, Link.CORE, or Link.PEER)
        :param Host host_a: host on the A side of the link
        :param Host host_b: host on the B side of the link
        :param bool active: is the link created as active?
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
            mtu=mtu or DEFAULT_LINK_MTU,
            interfaceA=interfaceA,
            interfaceB=interfaceB,
        )

    def create_from_ases(self, type, as_a, as_b, active=True, mtu=None):
        """
        Create a link connecting the given two ASes.
        The interfaces are created on the *first* host of each AS.
        Creates a default Interface for both hosts and a Link connecting the two Interfaces.

        :param str type: Link type (Link.PROVIDER, Link.CORE, or Link.PEER)
        :param Host host_a: host on the A side of the link
        :param Host host_b: host on the B side of the link
        :param bool active: is the link created as active?
        :param int mtu: optional, MTU for this link
        :returns: Link
        """
        return self.create_from_hosts(
            type=type,
            active=active,
            mtu=mtu,
            host_a=as_a.hosts.first(),
            host_b=as_b.hosts.first(),
        )

    def _check_link(self, type, as_a, as_b):
        # TODO(matzf): validation (should be reusable for forms and for global system checks)
        # - no provider loops
        # - core links only for core ases
        if as_a == as_b:
            raise ValidationError("Loop AS-link (from AS to itself) not allowed")
        if (type == Link.CORE) != (as_a.is_core and as_b.is_core):
            raise ValidationError("CORE links only between core ASes")
        if as_b.is_core and type == Link.PROVIDER:
            raise ValidationError("No providers for core ASes")
        if as_a.isd_id != as_b.isd_id and type == Link.PROVIDER:
            raise ValidationError("No provider links between ISDs")


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

    def update(self, type=None, active=None, mtu=None):
        """
        Update the fields for this Link instance and the two related interfaces
        and immediately `save`. This will trigger a configuration bump for all
        Hosts in all affected ASes.
        :param str type: optional, Link type (Link.PROVIDER, Link.CORE, or Link.PEER)
        :param bool active: optional, should the link be active?
        """
        prev_info = [self.type, self.active, self.mtu]

        if type is not None:
            self.type = type
        if active is not None:
            self.active = active
        if mtu is not None:
            self.mtu = mtu

        curr_info = [self.type, self.active, self.mtu]
        if curr_info != prev_info:
            self.save()
            self.interfaceA.AS.hosts.bump_config()
            self.interfaceB.AS.hosts.bump_config()

    def update_active(self, active):
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
    def create(self, host):
        """
        Create a BorderRouter object.
        :param Host host: the host, defines the AS
        :returns: BorderRouter
        """
        host.AS.hosts.bump_config()

        return super().create(
            AS=host.AS,
            host=host,
        )

    def first_or_create(self, host):
        """
        Get the first border router related to this host, or create a new one with default settings.
        :param Host host: the host, defines the AS
        :returns: BorderRouter
        """
        return host.border_routers.first() or self.create(host=host)

    def iterator_non_empty(self):
        """
        Returns the iterator for all border routers that have at least one interface
        :returns iterator
        """
        return self.annotate(num_ifaces=Count('interfaces')).filter(num_ifaces__gt=0).iterator()


class BorderRouter(models.Model):
    """
    A BorderRouter object represents the actual `border`-process executing an Interface.
    It stores the per-border-router settings (internal address port and control address port).
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

    objects = BorderRouterManager()

    def __str__(self):
        return f"{self.AS.isd_as_str()} {self.instance_name}"

    @cached_property
    def instance_id(self):
        """
        The index/id of this border router instance in this AS.
        This is inferred from the order by PK.
        """
        # Hint: when loading this from in scionlab.scion.topology._fetch_routers, we _override_ the
        # instance_id attribute, as we know the id from having loaded all routers. This code is not
        # run. This is analogous to the way that the @cached_property works (the decorator overrides
        # itself with the computed value when first accessed).
        if self.pk:
            # slow!
            return self.AS.border_routers.filter(pk__lt=self.pk).count() + 1
        else:
            return 0

    @property
    def instance_name(self):
        """
        Name of this border router instance in the AS topology.
        """
        return f"br-{self.instance_id}"

    @property
    def internal_port(self):
        return BR_INTERNAL_PORT_BASE + self.instance_id

    @property
    def metrics_port(self):
        return BR_METRICS_PORT_BASE + self.instance_id

    def update(self, host=_placeholder):
        """
        Update the given fields
        :param Host host: optional, the host. Must be in current AS.
        """
        prev_host = self.host

        if host is not _placeholder:
            if host.AS != self.AS:
                # Moving BR to different AS not supported. Would be doable (the Interface.update
                # already implements this) but not currently useful.
                raise RuntimeError('BorderRouter.update cannot change AS')
            self.host = host

        self.save()

        if host != prev_host:
            host.AS.hosts.bump_config()


class ServiceManager(models.Manager):
    def create(self, host, type):
        """
        Create a Service object.
        :param Host host: the host, defines the AS
        :param str type: Service type (Service.CS, CO, BW, or PP)
        :returns: Service
        """
        host.AS.hosts.bump_config()
        return super().create(
            AS=host.AS,
            host=host,
            type=type,
        )


class Service(models.Model):
    """
    A SCION service, both for the control plane services (beacon, path, ...)
    and for any other service that communicates using SCION.
    """
    CS = 'CS'
    SIG = 'SIG'
    CO = 'CO'
    BW = 'BW'
    PP = 'PP'
    SERVICE_TYPES = (
        (CS, 'Control Service'),  # monolithic control plane service
        (SIG, 'SCION IP Gateway'),
        (CO, 'Colibri Service'),
        (BW, 'Bandwidth tester server'),
        (PP, 'Pingpong server'),
    )
    CONTROL_SERVICE_TYPES = (
        CS,
        CO,
    )
    EXTRA_SERVICE_TYPES = (
        BW,
        PP,
    )
    SERVICE_PORTS = {
        CS: CS_PORT,
        SIG: SIG_CTRL_PORT,
        CO: CO_PORT,
        BW: BW_PORT,
        PP: PP_PORT,
    }
    METRICS_PORTS = {
        CS: CS_METRICS_PORT,
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

    type = models.CharField(
        choices=SERVICE_TYPES,
        max_length=_MAX_LEN_CHOICES_DEFAULT
    )

    objects = ServiceManager()

    def __str__(self):
        return f"{self.AS.isd_as_str()} {self.instance_name}"

    @cached_property
    def instance_id(self):
        """
        The index/id of this service instance in this AS.
        This is inferred from the order by PK.
        """
        # Hint: when loading this from in scionlab.scion.topology._fetch_services, we _override_ the
        # instance_id attribute, as we know the id from having loaded all services. This code is not
        # run.
        if self.pk:
            # slow!
            return self.AS.services.filter(type=self.type, pk__lt=self.pk).count() + 1
        else:
            return 0

    @property
    def instance_name(self):
        """
        Name of this service instance in the AS topology.
        """
        return f"{self.type.lower()}-{self.instance_id}"

    @property
    def port(self):
        if self.type not in self.SERVICE_PORTS:
            raise KeyError('Unknown type %s' % self.type)
        return self.SERVICE_PORTS[self.type]

    @property
    def metrics_port(self):
        return self.METRICS_PORTS.get(self.type)

    def _pre_delete(self):
        """
        Called by the pre_delete signal handler `_service_pre_delete`.
        Note: the pre_delete signal has the advantage that it is called
        also for bulk deletion, while this `delete()` method is not.
        """
        Service._bump_affected(self.host, self.type)

    def update(self, host=_placeholder):
        """
        Update the given fields of the
        :param Host host: optional, the host
        """
        prev_host = self.host

        if host is not _placeholder:
            if host != self.host:
                self._bump_affected(self.host, self.type)
            self.host = host

        self.save()

        if self.host != prev_host:
            self._bump_affected(self.host, self.type)

    @staticmethod
    def _bump_affected(host, type, prev_host=None):
        """
        Helper: trigger a configuration bump for the hosts affected by a service of the given type
        on the given host.
        :param Host host:
        :param str type: Service type
        :param Host prev_host:
        """
        if type in Service.CONTROL_SERVICE_TYPES:
            host.AS.hosts.bump_config()
        else:
            host.bump_config()


@receiver(post_delete, sender=AS, dispatch_uid='as_delete_callback')
def _as_post_delete(sender, instance, using, **kwargs):
    instance._post_delete()


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
