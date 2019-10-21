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

import ipaddress

from django import urls
from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.utils.html import format_html

import scionlab.tasks
from scionlab.models.core import (
    AS,
    Interface,
    Link,
    BorderRouter,
)
from scionlab.models.vpn import VPNClient, VPN
from scionlab.defines import (
    USER_AS_ID_BEGIN,
    USER_AS_ID_END,
)
from scionlab.util import as_ids

_MAX_LEN_CHOICES_DEFAULT = 16
_VAGRANT_VM_LOCAL_IP = '10.0.2.15'


class UserASManager(models.Manager):
    def create(self,
               owner,
               installation_type,
               isd,
               public_ip=None,
               bind_ip=None,
               as_id=None,
               label=None):
        """
        Create a UserAS attached to the given attachment point.

        :param User owner: owner of this UserAS
        :param str installation_type:
        :param int isd:
        :param str as_id: optional as_id, if None is given, the next free ID is chosen
        :param str label: optional label
        :param str public_ip: the public IP for the connection to the AP.
                              Must be specified if use_vpn is not enabled.
        :param str bind_ip: the bind IP for the connection to the AP (for NAT)

        :returns: UserAS
        """
        owner.check_as_quota()

        if as_id:
            as_id_int = as_ids.parse(as_id)
        else:
            as_id_int = self.get_next_id()
            as_id = as_ids.format(as_id_int)

        user_as = UserAS(
            owner=owner,
            label=label,
            isd=isd,
            as_id=as_id,
            as_id_int=as_id_int,
            installation_type=installation_type,
        )

        user_as.init_keys()
        user_as.generate_certificate_chain()
        user_as.save()
        user_as.init_default_services(
            public_ip=public_ip,
            bind_ip=_VAGRANT_VM_LOCAL_IP if installation_type == UserAS.VM else bind_ip,
        )

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
        return next(iter(self.aggregate(models.Max('as_id_int')).values()), None)


class UserAS(AS):
    VM = 'VM'
    PKG = 'PKG'
    SRC = 'SRC'
    INSTALLATION_TYPES = (
        (VM,  format_html('Run SCION in a <em>Vagrant</em> virtual machine '
                          '<i class="text-muted">(simplest approach)</i>')),
        (PKG, 'SCION installation from packages'),
        (SRC, format_html('SCION installation from sources '
                          '<i class="text-muted">(for developers)</i>')),
    )

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

    def create_attachment(self,
                          ap,
                          public_port,
                          public_ip=None,
                          use_vpn=False,
                          bind_ip=None,
                          bind_port=None):
        """
        Attach a UserAS to the specified attachment point creating the Link and the Interfaces,
        and if needed a VPNClient
        :param 'AttachmentPoint' ap:
        :param int public_port:
        :param str public_ip:
        :param bool use_vpn:
        :param int bind_port:
        :param str bind_ip:
        :return Link link: The entity representing the relationship (UserAS, AttachmentPoint)
        """
        # XXX: Should we check if the isd is consistent?
        if self.isd != ap.AS.isd:
            self._change_isd(ap.AS.isd)
        if use_vpn:
            assert ap.vpn is not None
            # Reuse VPNClient if there's with this AttachmentPoint
            vpn_client = VPNClient.objects.filter(host=self.host, vpn=ap.vpn).first()
            if vpn_client is None:
                vpn_client = ap.vpn.create_client(host=self.host, active=True)
            interface_client = Interface.objects.create(
                border_router=BorderRouter.objects.first_or_create(self.host),
                public_port=public_port,
                vpn_client=vpn_client
            )
            interface_ap = Interface.objects.create(
                border_router=ap.get_border_router_for_useras_interface(),
                public_ip=ap.vpn.server_vpn_ip
            )
        else:
            interface_client = Interface.objects.create(
                border_router=BorderRouter.objects.first_or_create(self.host),
                public_ip=public_ip,
                public_port=public_port,
                bind_ip=_VAGRANT_VM_LOCAL_IP if self.installation_type == UserAS.VM else bind_ip,
                bind_port=bind_port
            )
            interface_ap = Interface.objects.create(
                border_router=ap.get_border_router_for_useras_interface(),
            )

        link = Link.objects.create(
            type=Link.PROVIDER,
            interfaceA=interface_ap,
            interfaceB=interface_client
        )
        ap.split_border_routers()
        ap.trigger_deployment()
        self.save()
        return link

    def update_attachment(self,
                          link: Link,
                          active: bool,
                          public_port: int,
                          public_ip,
                          use_vpn: bool,
                          bind_ip,
                          bind_port: int):
        """
        Update a Link and Interfaces(A and B) involved in a UserAS attachment
        """
        ap = link.interfaceA.AS.attachment_point_info
        # XXX: Should we check if the isd is consistent?
        if active and self.isd != ap.AS.isd:
            self._change_isd(ap.AS.isd)

        link.update(active=active)
        link.save()
        iface = link.interfaceB
        if ap.vpn is None:
            # We simply cannot have a VPN connection if the ap does not support VPN
            vpn_client = None
        else:
            vpn_client = VPNClient.objects.filter(host=self.host, vpn=ap.vpn).first()

        # Create or Update the vpn_client accordingly
        if use_vpn:
            if vpn_client is None:
                assert ap.vpn is not None
                # Create a brand new vpn_client
                vpn_client = ap.vpn.create_client(host=self.host, active=True)
            elif not vpn_client.active:
                # Activate the existing vpn_client
                vpn_client.active = True
                vpn_client.save()
        else:
            if vpn_client is not None and vpn_client.active:
                # Deactivate the existing vpn_client
                vpn_client.active = False
                vpn_client.save()
        iface.update(public_ip=public_ip,
                     public_port=public_port,
                     bind_ip=bind_ip,
                     bind_port=bind_port,
                     is_over_vpn=use_vpn)

        ap.split_border_routers()
        ap.trigger_deployment()
        self.save()

    def update(self,
               label,
               public_ip,
               bind_ip,
               installation_type):
        """
        Update this UserAS instance and immediately `save`.
        Updates the related host, interface and link instances and will trigger
        a configuration bump for the hosts of the affected attachment point(s).
        """
        # XXX: This is useless since the model instance has already got the updated fields
        self.label = label
        self.host.update(
            public_ip=public_ip,
            bind_ip=_VAGRANT_VM_LOCAL_IP if installation_type == UserAS.VM else bind_ip,
        )

        self.save()

    @property
    def host(self):
        return self.hosts.get()  # UserAS always has only one host

    def is_use_vpn(self):
        """
        Is this UserAS currently configured with VPN?
        """
        return VPNClient.objects.filter(host__AS=self, active=True).exists()

    def is_active(self):
        """
        Is this UserAS currently active?
        """
        return any(iface.link().active for iface in self.interfaces.all())

    def update_active(self, active):
        """
        Set the UserAS to be active/inactive.
        This will trigger a deployment of the attachment point configuration.
        """
        self.interfaces.get().link().update_active(active)
        self.attachment_point.trigger_deployment()

    def _get_ap_link(self):
        # FIXME(matzf): find the correct link to the AP if multiple links present!
        return self.interfaces.get().link()

    @property
    def attachment_points(self):
        def _ap_from_link(l):
            return l.interfaceA.AS.attachment_point_info

        # Boost query with related_values to avoid hitting the database multiple times
        ap_links = Link.objects.filter(interfaceB__AS=self)\
                               .select_related('interfaceA__AS__attachment_point_info')
        return [_ap_from_link(l) for l in ap_links]

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

        Note: the border router effectively used will be be overwritten by `split_border_routers`.

        :returns: a `BorderRouter` of the related `AS`
        """
        host = self._get_host_for_useras_attachment()
        return BorderRouter.objects.first_or_create(host)

    def check_vpn_available(self):
        """
        Raise ValidationError if the attachment point does not support VPN.
        """
        if self.vpn is None:
            raise ValidationError("Selected attachment point does not support VPN",
                                  code='attachment_point_no_vpn')

    def trigger_deployment(self):
        """
        Trigger the deployment for the attachment point configuration (after the current transaction
        is successfully committed).

        The deployment is rate limited, max rate controlled by
        settings.DEPLOYMENT_PERIOD.
        """
        for host in self.AS.hosts.iterator():
            transaction.on_commit(lambda: scionlab.tasks.deploy_host_config(host))

    def supported_ip_versions(self):
        """
        Returns the IP versions for the host where the user ASes will attach to
        """
        host = self._get_host_for_useras_attachment()
        return {ipaddress.ip_address(host.public_ip).version}

    def _get_host_for_useras_attachment(self):
        """
        Finds the host where user ASes would attach to
        """
        if self.vpn is not None:
            assert (self.vpn.server.AS == self.AS)
            host = self.vpn.server
        else:
            host = self.AS.hosts.filter(public_ip__isnull=False)[0]
        return host

    def split_border_routers(self, max_ifaces=10):
        """
        This is a workaround for an (apparent) issue with the border router, that cannot handle more
        than ~12 interfaces per process; this problem seemed to be fixed but is apparently still
        here. This is a hopefully temporary patch.

        Will create / remove border routers so no one of them has more than
        the specified limit of interfaces. The links to parent ASes will
        always remain in a different border router.
        :param int max_ifaces The maximum number of interfaces per BR
        """
        host = self._get_host_for_useras_attachment()
        # find the *active* interfaces attaching for UserASes (attaching_ifaces) and the rest
        # (infra_ifaces)
        ifaces = host.interfaces.active().order_by('interface_id')
        attaching_ifaces = ifaces.filter(
            link_as_interfaceA__type=Link.PROVIDER,
            link_as_interfaceA__interfaceB__AS__owner__isnull=False)
        infra_ifaces = ifaces.exclude(pk__in=attaching_ifaces)

        # attaching non children all to one BR:
        infra_br = BorderRouter.objects.first_or_create(host)
        brs_to_delete = list(
            host.border_routers.order_by('pk').exclude(pk=infra_br.pk).values_list('pk', flat=True))
        brs_to_delete.reverse()
        infra_ifaces.update(border_router=infra_br)
        # attaching children to several BRs:
        attaching_ifaces = attaching_ifaces.all()
        for i in range(0, len(attaching_ifaces), max_ifaces):
            if brs_to_delete:
                br = BorderRouter.objects.get(pk=brs_to_delete.pop())
            else:
                br = BorderRouter.objects.create(host=host)
            for j in range(i, min(len(attaching_ifaces), i + max_ifaces)):
                iface = attaching_ifaces[j]
                iface.border_router = br
                iface.save()
            br.save()
        # squirrel away the *inactive* interfaces somewhere...
        host.interfaces.inactive().update(border_router=infra_br)

        # delete old BRs
        if brs_to_delete:
            BorderRouter.objects.filter(pk__in=brs_to_delete).delete()


class AttachmentPointConf:
    """
    Helper class to keep the state of a UserAS attachment configuration
    """

    def __init__(self, attachment_point,
                 public_ip, public_port, bind_ip, bind_port,
                 use_vpn, active=True, link=None):
        self.attachment_point = attachment_point
        self.public_ip = public_ip
        self.public_port = public_port
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.use_vpn = use_vpn
        self.active = active
        self.link = link

    @staticmethod
    def attachment_points(aps_confs):
        return [ap_conf.attachment_point for ap_conf in aps_confs]

    def __repr__(self):
        _str = 'AttachmentPointConf('
        for k, v in self.__dict__.items():
            _str += '{}={}, '.format(k, v)
        return _str[:-2] + ')'
