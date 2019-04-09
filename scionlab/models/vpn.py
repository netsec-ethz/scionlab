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
from django.db import models
from django.dispatch import receiver
from django.db.models.signals import pre_delete
from scionlab.models.network import (
    Host
)
from scionlab.openvpn_config import (
    generate_vpn_client_key_material,
    generate_vpn_server_key_material,
)
from scionlab.util.django import value_set


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

    objects = VPNManager()

    class Meta:
        verbose_name = 'VPN'
        verbose_name_plural = 'VPNs'

    def _pre_delete(self):
        """
        Called by the pre_delete signal handler `_vpn_server_pre_delete`.
        """
        self.server.bump_config()

    def init_key(self):
        key, cert = generate_vpn_server_key_material(self.server)
        self.private_key = key
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
            value_set(VPNClient.objects.filter(vpn=self), 'ip')
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
        host.bump_config()
        vpn.server.bump_config()
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

    class Meta:
        verbose_name = 'VPN Client'
        verbose_name_plural = 'VPN Clients'

    def _pre_delete(self):
        """
        Called by the pre_delete signal handler `_vpn_client_pre_delete`.
        """
        self.host.bump_config()
        self.vpn.server.bump_config()

    def init_key(self):
        key, cert = generate_vpn_client_key_material(self.host.AS)
        self.private_key = key
        self.cert = cert


@receiver(pre_delete, sender=VPN, dispatch_uid='vpn_delete_callback')
def _vpn_pre_delete(sender, instance, using, **kwargs):
    instance._pre_delete()


@receiver(pre_delete, sender=VPNClient, dispatch_uid='vpn_client_delete_callback')
def _vpn_client_pre_delete(sender, instance, using, **kwargs):
    instance._pre_delete()
