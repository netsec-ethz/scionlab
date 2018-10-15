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
from django.contrib.auth.models import User

_MAX_LEN_DEFAULT = 255
""" Max length value for fields without specific requirments to max length """
_MAX_LEN_CHOICES_DEFAULT = 16
""" Max length value for choices fields without specific requirments to max length """

class ISD(models.Model):
    id = models.PositiveIntegerField(primary_key=True)
    label = models.CharField(max_length=_MAX_LEN_DEFAULT, null=True, blank=True)
    
    class Meta:
        verbose_name = 'ISD'
        verbose_name_plural = 'ISDs'

class AS(models.Model):
    isd = models.ForeignKey(
        ISD,
        related_name='ases',
        on_delete=models.CASCADE
    )

    as_id = models.CharField(max_length=15, primary_key=True)
    label = models.CharField(max_length=_MAX_LEN_DEFAULT, null=True, blank=True)

    owner = models.ForeignKey(
        User,
        on_delete=models.CASCADE
    )
    #subnet = models.CharField(max_length=15) # AS internal subnet
    #vpn = models.ForeignKey(                 # AS internal VPN
    #    'VPN',
    #    null=True,
    #    related_name='ases',
    #    on_delete=models.SET_NULL
    #)

    is_core = models.BooleanField(default=False)
    #commit_hash = models.CharField(max_length=_MAX_LEN_DEFAULT, default='')
# TBD: use separate CoreAS table instead (using "multi-table inheritance")
    sig_pub_key = models.CharField(max_length=_MAX_LEN_DEFAULT, null=True, blank=True)
    sig_priv_key = models.CharField(max_length=_MAX_LEN_DEFAULT, null=True, blank=True)
    enc_pub_key = models.CharField(max_length=_MAX_LEN_DEFAULT, null=True, blank=True)
    enc_priv_key = models.CharField(max_length=_MAX_LEN_DEFAULT, null=True, blank=True)
    master_as_key = models.CharField(max_length=_MAX_LEN_DEFAULT, null=True, blank=True)
    certificate = models.TextField(null=True, blank=True)
    trc = models.TextField(null=True, blank=True)
    #keys = jsonfield.JSONField(default=empty_dict)
    #core_keys = jsonfield.JSONField(default=empty_dict)
   
    allow_user_as_links = models.BooleanField(default=True)
    """ This is true for attachment point ASes """

    class Meta:
        verbose_name = 'AS'
        verbose_name_plural = 'ASes'

class Host(models.Model):
    """ 
    A host is a machine/vm/container running services for one AS.
    """
    config_version = models.PositiveIntegerField()
    AS = models.ForeignKey(
        AS,
        null=True,
        on_delete=models.SET_NULL,
    )
    ip = models.GenericIPAddressField()
    """ IP of the host IN the AS """

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
        on_delete=models.PROTECT # don't delete hosts with services configured
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

class Service(models.Model):
    """
        A SCION service, both for the control plane services (beacon, path, ...)
        and for any other service that communicates using SCION.
    """
    SERVICE_TYPES = (
        ('BS','Beacon Server'),
        ('PS','Path Server'),
        ('CS','Certificate Server'),
        ('ZK','Zookeeper (service discovery)'),
        ('BW','Bandwidth tester server'),
        ('PP','Pingpong server'),
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

