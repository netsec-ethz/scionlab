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
:mod:`scionlab.models.user_as` --- Django models for User ASes and Attachment Points
====================================================================================
"""

import ipaddress
from typing import List, Set

from django import urls
from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.utils.html import format_html
from django.contrib.auth.models import User

import scionlab.tasks
from scionlab.models.core import (
    AS,
    Interface,
    Link,
    BorderRouter,
    Host
)
from scionlab.models.vpn import VPNClient
from scionlab.defines import (
    USER_AS_ID_BEGIN,
    USER_AS_ID_END,
)
from scionlab.scion import as_ids

_MAX_LEN_CHOICES_DEFAULT = 16
_VAGRANT_VM_LOCAL_IP = '10.0.2.15'


class UserASManager(models.Manager):
    def create(self,
               owner: User,
               installation_type: str,
               isd: int,
               as_id: str = None,
               label: str = None) -> 'UserAS':
        """Create a UserAS

        :param User owner: owner of this UserAS
        :param str installation_type:
        :param int isd:
        :param str as_id: optional as_id, if None is given, the next free ID is chosen
        :param str label: optional label

        :returns: UserAS
        """
        owner.check_as_quota()
        assert isd, "No ISD provided"

        if as_id:
            as_id_int = as_ids.parse(as_id)
        else:
            as_id_int = self.get_next_id()
            as_id = as_ids.format(as_id_int)

        user_as = super().create(
            owner=owner,
            label=label,
            isd=isd,
            as_id=as_id,
            as_id_int=as_id_int,
            installation_type=installation_type,
            master_as_key=AS._make_master_as_key()
        )

        user_as.init_keys()
        user_as.generate_certificate_chain()
        user_as.init_default_services()

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
        return self.aggregate(models.Max('as_id_int')).get('as_id_int__max', None)


class UserAS(AS):
    MAX_AP_PER_USERAS = 5
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

    def update(self, label: str, installation_type: str):
        """
        Updates the `UserAS` fields and immediately saves
        """
        self.label = label
        if installation_type != self.installation_type:
            if installation_type == UserAS.VM:
                self._set_bind_ips_for_vagrant()
            elif self.installation_type == UserAS.VM:
                self._unset_bind_ips_for_vagrant()
            self.installation_type = installation_type
        self.save()

    def update_attachments(self,
                           att_confs: List['AttachmentConf'] = [],
                           deleted_links: List[Link] = []):
        """
        Update the attachments of the UserAS handling their creation, update and deletion.
        Moreover, bumps the related host configuration

        :param att_confs: updated AttachmentConf for _modified_ links (can be a subset)
        :param deleted_links: links that should be deleted
        """
        aps_set = set(c.attachment_point for c in att_confs)
        # Attachment points of deleted connections
        aps_set |= set(link.interfaceA.AS.attachment_point_info for link in deleted_links)
        # ISDs of active attachment points
        isds = set(c.attachment_point.AS.isd for c in att_confs if c.active)
        assert len(isds) <= 1, "ISD consistency infringed"
        # Update ISD if needed
        if len(isds) == 1:
            isd = isds.pop()
            if isd != self.isd:
                self._change_isd(isd)

        for att_conf in att_confs:
            self._create_or_update_attachment(att_conf)
        for deleted_link in deleted_links:
            self._delete_attachment(deleted_link)
        for ap in aps_set:
            ap.split_border_routers()
            ap.trigger_deployment()
        self._deactivate_unused_vpn_clients(att_confs)

        self.save()

    def _create_or_update_attachment(self, att_conf: 'AttachmentConf'):
        """
        Proxy function which calls create or update over a UserAS attachment point
        configuration, based on the existence of `att_conf.link`
        """
        if att_conf.link is None:
            assert att_conf.active, "Cannot deactivate a non existing Link"
            return self._create_attachment(att_conf)
        else:
            return self._update_attachment(att_conf)

    def _create_attachment(self, att_conf: 'AttachmentConf'):
        """
        Attach a UserAS to the specified attachment point creating the `Link` and the `Interface`s,
        and if needed a `VPNClient`. The new `Link` is stored in `att_conf.link`
        """
        ap = att_conf.attachment_point
        host = self.host
        border_router = BorderRouter.objects.first_or_create(host)
        ap_border_router = ap.get_border_router_for_useras_interface()

        if att_conf.use_vpn:
            iface_ap = Interface.objects.create(ap_border_router, ap.vpn.server_vpn_ip)
            vpn_client = self._create_or_activate_vpn_client(att_conf)
            att_conf.public_ip = vpn_client.ip
            att_conf.bind_ip = att_conf.bind_port = None
        else:
            iface_ap = Interface.objects.create(ap_border_router)
            if self.installation_type == UserAS.VM:
                att_conf.bind_ip = _VAGRANT_VM_LOCAL_IP
                att_conf.bind_port = None

        iface_client = Interface.objects.create(
            border_router,
            att_conf.public_ip,
            att_conf.public_port,
            att_conf.bind_ip,
            att_conf.bind_port
        )
        link = Link.objects.create(
            type=Link.PROVIDER,
            interfaceA=iface_ap,
            interfaceB=iface_client
        )
        att_conf.link = link

    def _update_attachment(self, att_conf: 'AttachmentConf'):
        """
        Update the `Link` between the `UserAS` and the `AttachmentPoint`,
        and the respective `Interface`s (A and B)
        """
        ap = att_conf.attachment_point
        iface_ap = att_conf.link.interfaceA
        iface_client = att_conf.link.interfaceB
        ap_border_router = ap.get_border_router_for_useras_interface()

        if att_conf.use_vpn:
            iface_ap.update(ap_border_router, public_ip=ap.vpn.server_vpn_ip, public_port=None)
            vpn_client = self._create_or_activate_vpn_client(att_conf)
            att_conf.public_ip = vpn_client.ip
            att_conf.bind_ip = att_conf.bind_port = None
        else:
            iface_ap.update(ap_border_router, public_ip=None, public_port=None)
            if self.installation_type == UserAS.VM:
                att_conf.bind_ip = _VAGRANT_VM_LOCAL_IP
                att_conf.bind_port = None

        iface_client.update(public_ip=att_conf.public_ip,
                            public_port=att_conf.public_port,
                            bind_ip=att_conf.bind_ip,
                            bind_port=att_conf.bind_port)

        # Attribute already set if coming from AttachmentConfForm.save(...)
        att_conf.link.active = att_conf.active
        att_conf.link.save()

    def _delete_attachment(self, deleted_link: Link):
        deleted_link.delete()

    def _create_or_activate_vpn_client(self, att_conf: 'AttachmentConf') -> VPNClient:
        """
        Create or reuse a `VPNClient` to connect the `UserAS` to the `AttachmentPoint`.
        :return: return the VPNClient of the `UserAS` associated with the `AttachmentPoint`
        """
        assert att_conf.attachment_point.vpn, "VPN not supported by this attachment point"
        ap = att_conf.attachment_point
        host = self.hosts.get()
        # Reuse VPNClient if there's one with this AttachmentPoint
        vpn_client = host.vpn_clients.filter(vpn=ap.vpn).first()
        if not vpn_client:
            vpn_client = ap.vpn.create_client(host, active=True)
        elif not vpn_client.active:
            vpn_client.active = True
            vpn_client.save()
        return vpn_client

    def _deactivate_unused_vpn_clients(self, att_confs: List['AttachmentConf']):

        # TODO(matzf): combine this with _create_or_activate_vpn_client, to simplify & avoid a few
        # DB queries
        vpn_clients = self.host.vpn_clients.filter(active=True)

        # Find out which VPN clients should remain active for one of the un-modified interfaces
        modified_iface_pks = [a.link.interfaceB_id for a in att_confs if a.link]
        unmodified_ifaces = self.interfaces.active().exclude(pk__in=modified_iface_pks)
        unmodified_iface_ips = [iface.public_ip for iface in unmodified_ifaces]

        active_vpns = set(vpn_client.vpn_id for vpn_client in vpn_clients
                          if vpn_client.ip in unmodified_iface_ips)

        # and add the VPN clients for the modified interfaces that are set to use VPN
        active_vpns |= set(c.attachment_point.vpn_id for c in att_confs if c.active and c.use_vpn)

        for vpn_client in vpn_clients:
            if vpn_client.vpn_id not in active_vpns:
                vpn_client.active = False
                vpn_client.save()

    def _set_bind_ips_for_vagrant(self):
        """
        When changing to installation VM, all existing non-VPN interfaces need to be updated
        to use the vagrant local address.
        """
        vpn_ips = self.host.vpn_clients.filter(active=True).values_list('ip', flat=True)
        self.interfaces.exclude(
            public_ip__in=vpn_ips
        ).update(
            bind_ip=_VAGRANT_VM_LOCAL_IP,
            bind_port=None
        )

    def _unset_bind_ips_for_vagrant(self):
        """
        When changing away from installation VM, remove the vagrant local address.
        """
        self.interfaces.filter(
            bind_ip=_VAGRANT_VM_LOCAL_IP
        ).update(
            bind_ip=None,
            bind_port=None
        )

    @property
    def host(self):
        return self.hosts.get()  # UserAS always has only one host

    @staticmethod
    def is_link_over_vpn(iface: Interface) -> bool:
        """
        Returns whether this UserAS interface corresponds to a link over VPN.
        """
        assert hasattr(iface.AS, 'useras')
        return iface.host.vpn_clients.filter(ip=iface.public_ip).exists()

    def is_active(self) -> bool:
        """
        Does the user have any active `Interface`?
        """
        return any(self.attachment_links()
                       .values_list('active', flat=True)
                       .all())

    def _activate(self) -> Set['AttachmentPoint']:
        """
        Activate the first attachment point
        :return: attachment points that shall be updated
        """
        link = self.attachment_links().first()
        if link:
            link.update_active(True)
            return {link.interfaceA.AS.attachment_point_info}
        return set()

    def _deactivate(self) -> Set['AttachmentPoint']:
        """
        Deactivate all links with the attachment points
        :return: attachment points that shall be updated
        """
        attachment_points = set()
        for link in self.attachment_links():
            link.update_active(False)
            attachment_points.add(link.interfaceA.AS.attachment_point_info)
        return attachment_points

    def update_active(self, active: bool):
        """
        Set the `UserAS` to be active (or inactive) by activating (or deactivating) a consistent
        susbent (or all) the links with attachment points.
        This will trigger a deployment of all the attachment points configurations
        """
        if active:
            attachment_points = self._activate()
        else:
            attachment_points = self._deactivate()
        for ap in attachment_points:
            attachment_points = ap.trigger_deployment()

    @property
    def ip_port_labels(self):
        public_labels, vpn_labels = [], []
        for link in self.attachment_links().filter(active=True):
            iface = link.interfaceB
            if UserAS.is_link_over_vpn(iface):
                vpn_labels.append('VPN:{}'.format(iface.public_port))
            else:
                public_labels.append('{}:{}'.format(iface.public_ip, iface.public_port))
        return public_labels + vpn_labels

    def attachment_points(self, active: bool = True) -> List['AttachmentPoint']:
        """
        :active: consider attachment points with which the user has an active connection only
        :returns: a list of attachments points to which the user is attached to
        """
        query = self.attachment_links()
        if active:
            query = query.filter(active=True)
        query = query.select_related('interfaceA__AS__attachment_point_info').order_by('pk')
        return [link.interfaceA.AS.attachment_point_info for link in query]

    @property
    def attachment_points_labels(self):
        return [ap.AS.label for ap in self.attachment_points()]

    def attachment_links(self):
        """
        :returns: queryset for links to attachment points
        """
        return Link.objects.filter(
            interfaceB__AS=self
         ).exclude(
            interfaceA__AS__attachment_point_info=None
         )

    def fixed_links(self):
        """
        :returns: queryset for "fixed" links to non-AP ASes (created through the admin panel)
        that cannot be modified by the user
        """
        return (
            Link.objects.filter(interfaceB__AS=self, interfaceA__AS__attachment_point_info=None) |
            Link.objects.filter(interfaceA__AS=self)
        )

    def isd_fixed(self) -> bool:
        """
        :returns: whether the ISD is defined by the fixed links that cannot be modifed by the user.
        """
        return self.fixed_links().filter(type=Link.PROVIDER).exists()


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

    def get_border_router_for_useras_interface(self) -> BorderRouter:
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

    def supported_ip_versions(self) -> Set[int]:
        """
        Returns the IP versions for the host where the user ASes will attach to
        """
        host = self._get_host_for_useras_attachment()
        return {ipaddress.ip_address(host.public_ip).version}

    def _get_host_for_useras_attachment(self) -> Host:
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

    @staticmethod
    def from_link(link: Link) -> 'AttachmentPoint':
        """
        :returns: an attachment point given a link with a UserAS
        """
        assert hasattr(link.interfaceB.AS, 'useras')
        return link.interfaceA.AS.attachment_point_info


class AttachmentConf:
    """
    Helper class that reflects the state of a UserAS attachment configuration
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
    def attachment_points(att_confs: List['AttachmentConf']) -> List[AttachmentPoint]:
        """
        :returns List[AttachmentPoint]: the attachment points in a list of `AttachmentConf`s
        """
        return [att_conf.attachment_point for att_conf in att_confs]

    def __repr__(self) -> str:
        _str = 'AttachmentPointConf('
        for k, v in self.__dict__.items():
            _str += '{}={}, '.format(k, v)
        return _str[:-2] + ')'
