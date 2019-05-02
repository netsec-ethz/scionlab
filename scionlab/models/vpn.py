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
from django.core.exceptions import ValidationError
from scionlab.models.core import _placeholder, Host
from scionlab.openvpn_config import (
    generate_vpn_client_key_material,
    generate_vpn_server_key_material,
)
from scionlab.util.django import value_set


class VPNManager(models.Manager):
    def create(self, server, server_port, subnet, server_vpn_ip):
        vpn = VPN(
            server=server,
            server_port=server_port,
            subnet=subnet,
            server_vpn_ip=server_vpn_ip
        )
        vpn.init_key()
        vpn.save()
        server.bump_config()
        return vpn


class VPN(models.Model):
    server = models.ForeignKey(
        Host,
        related_name='vpn_servers',
        on_delete=models.CASCADE
    )
    server_port = models.PositiveIntegerField()
    subnet = models.CharField(max_length=15)
    server_vpn_ip = models.GenericIPAddressField()
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

    def create_client(self, host, active, client_ip=None):
        client_ip = client_ip or str(self._find_client_ip())
        return VPNClient.objects.create(vpn=self, host=host, ip=client_ip, active=active)

    def vpn_subnet(self):
        return ipaddress.ip_network(self.subnet)

    def _find_client_ip(self):
        used_ips = {self.server_vpn_ip} | value_set(VPNClient.objects.filter(vpn=self), 'ip')
        subnet = ipaddress.ip_network(self.subnet)
        for ip in subnet.hosts():
            if str(ip) not in used_ips:
                return ip
        raise RuntimeError('No free client IP available')

    def clean(self):
        try:
            subnet = ipaddress.ip_network(self.subnet)
        except ValueError:
            raise ValidationError('Invalid subnet', code='vpn_bad_subnet')
        try:
            server_vpn_ip = ipaddress.ip_address(self.server_vpn_ip)
        except ValueError:
            raise ValidationError('Invalid server VPN IP address', code='vpn_bad_server_vpn_ip')
        if server_vpn_ip not in subnet:
            raise ValidationError('Server VPN IP is not inside the specified subnet',
                                  code='server_vpn_ip_not_in_subnet')

    def save(self, **kwargs):
        self.clean()
        super().save(**kwargs)

    def update(self,
               server=_placeholder,
               server_port=_placeholder,
               subnet=_placeholder,
               server_vpn_ip=_placeholder,
               private_key=_placeholder,
               cert=_placeholder):
        """
        Updates all/any parameter. It always saves the object and bumps config, even when no changes
        """
        oldserver = self.server
        if server is not _placeholder:
            self.server = server
        if server_port is not _placeholder:
            self.server_port = server_port
        if subnet is not _placeholder:
            self.subnet = subnet
        if server_vpn_ip is not _placeholder:
            self.server_vpn_ip = server_vpn_ip
        if private_key is not _placeholder:
            self.private_key = private_key
        if cert is not _placeholder:
            self.cert = cert
        self.save()
        if self.server:
            self.server.bump_config()
        if oldserver and oldserver != self.server:
            oldserver.bump_config()


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
        unique_together = ('vpn', 'ip')
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
