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

from django import forms
from django.conf import settings
from django.forms import BaseModelFormSet, modelformset_factory
from django.core.exceptions import ValidationError

from crispy_forms.helper import FormHelper
from crispy_forms.layout import Layout, Row, Column
from crispy_forms.bootstrap import AppendedText

from scionlab.defines import MAX_PORT
from scionlab.models.core import Link, Interface, BorderRouter
from scionlab.models.user_as import UserAS, AttachmentPoint


class AttachmentLinksFormSet(BaseModelFormSet):

    def __init__(self, *args, **kwargs):
        super(AttachmentLinksFormSet, self).__init__(*args, **kwargs)

    def clean(self):
        if any(self.errors):
            # Don't bother validating the formset unless each form is valid on its own
             return
        public_ports = {}
        # Check isd and ports clash
        isd_set = set()
        public_ports = {}
        bind_ports = {}
        for form in self.forms:
            if self.can_delete and self._should_delete_form(form):
                continue
            # Skip empty forms and deactivated connections
            if not form.cleaned_data or not form.cleaned_data['active']:
                continue
            isd_set.add(form.cleaned_data['attachment_point'].AS.isd)
            if not form.cleaned_data['use_vpn']:
                public_ports.setdefault(form.cleaned_data['public_port'], [])
                public_ports[form.cleaned_data['public_port']].append(form)
                if 'bind_port' in form.cleaned_data:
                    bind_ports.setdefault(form.cleaned_data['bind_port'], [])
                    bind_ports[form.cleaned_data['bind_port']].append(form)
        # Public ports clash check
        for port, forms in public_ports.items():
            if len(forms) > 1:
                for f in forms[1:]:
                    f.add_error('public_port',
                                ValidationError('The port is already in use',
                                                code='public_port_clash'))
        # Bind ports clash check
        for port, forms in bind_ports.items():
            if len(forms) > 1:
                for f in forms[1:]:
                    f.add_error('bind_port',
                                ValidationError('The port is already in use',
                                                code='bind_port_clash'))
        # Same ISD check
        if len(isd_set) > 1:
            raise ValidationError("All attachment points must belong to the "
                                  "same ISD")


    def save(self, userAS):
        for form in self.forms:
            if form.cleaned_data:
                form.save(userAS)


class AttachmentLinkForm(forms.ModelForm):
    """
    Form for creating and updating a Link involving a UserAS
    """
    class Meta:
        model = Link
        fields = ('active',)

    public_ip = forms.GenericIPAddressField(
        help_text="Public IP address",
        required=False
    )
    public_port = forms.IntegerField(
        min_value=1024,
        max_value=MAX_PORT,
        initial=50000,
        label="Public Port (UDP)",
        help_text="The attachment point will use this port for the overlay link to your AS."
    )
    bind_ip = forms.GenericIPAddressField(
        label="Bind IP address",
        help_text="(Optional) Specify the local IP/port "
                  "if your border router is behind a NAT/firewall etc.",
        required=False
    )
    bind_port = forms.IntegerField(
        min_value=1024,
        max_value=MAX_PORT,
        label="Bind port",
        required=False
    )
    use_vpn = forms.BooleanField(
        required=False,
        label="Use VPN",
        help_text="Use an OpenVPN connection for the overlay link between this attachment point "
                  "and the border router of my AS."
    )
    attachment_point = forms.ModelChoiceField(queryset=AttachmentPoint.objects)

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user')
        instance = kwargs.get('instance')
        initial = kwargs.pop('initial', {})
        if instance:
            initial['active'] = instance.active
            initial['attachment_point'] = AttachmentPoint.objects.get(AS=instance.interfaceA.AS)
            initial['use_vpn'] = instance.interfaceB.vpn_client is not  None
            initial['public_ip'] = instance.interfaceB.public_ip
            initial['public_port'] = instance.interfaceB.public_port
            initial['bind_ip'] = instance.interfaceB.bind_ip
            initial['bind_port'] = instance.interfaceB.bind_port
        self.helper = self._crispy_helper()
        super().__init__(*args, initial=initial, **kwargs)

    def clean(self):
        cleaned_data = super().clean()
        assert 'attachment_point' in cleaned_data, "At least an attachment point must be specified"
        if cleaned_data.get('use_vpn'):
            cleaned_data.get('attachment_point').check_vpn_available()
        elif 'public_ip' in self.errors:
            assert('public_ip' not in cleaned_data)
            return cleaned_data
        else:
            public_ip = cleaned_data.get('public_ip')
            if not public_ip:
                # public_ip cannot be empty when use_vpn is false
                raise ValidationError(
                    'Please provide a value for public IP, or enable "Use OpenVPN".',
                    code='missing_public_ip_no_vpn'
                )
            ip_addr = ipaddress.ip_address(public_ip)

            ap = cleaned_data['attachment_point']
            if ip_addr.version not in ap.supported_ip_versions():
                raise ValidationError('IP version {ipv} not supported by the selected '
                                      'attachment point'.format(ipv=ip_addr.version),
                                      code='unsupported_ip_version')

            if (not settings.DEBUG and (not ip_addr.is_global or ip_addr.is_loopback)) or \
                    ip_addr.is_multicast or \
                    ip_addr.is_reserved or \
                    ip_addr.is_link_local or \
                    (ip_addr.version == 6 and ip_addr.is_site_local) or \
                    ip_addr.is_unspecified:
                self.add_error('public_ip',
                               ValidationError("Public IP address must be a publically routable "
                                               "address. It cannot be a multicast, loopback or "
                                               "otherwise reserved address.",
                                               code='invalid_public_ip'))
        return cleaned_data

    def save(self, userAS, commit=True):
        active = self.cleaned_data['active']
        use_vpn = self.cleaned_data['use_vpn']
        attachment_point = self.cleaned_data['attachment_point'] 
        public_ip = self.cleaned_data['public_ip'] 
        public_port = self.cleaned_data['public_port'] 
        bind_ip = self.cleaned_data['bind_ip'] 
        bind_port = self.cleaned_data['bind_port'] 
        if self.instance.pk is None:
            userAS.create_attachment(attachment_point,
                                     public_port,
                                     public_ip=public_ip,
                                     use_vpn=use_vpn,
                                     bind_ip=bind_ip,
                                     bind_port=bind_port)
                                                   
        else:
            userAS.update_attachment(self.instance,
                                     active,
                                     public_port,
                                     public_ip,
                                     use_vpn,
                                     bind_ip,
                                     bind_port)

    def _crispy_helper(self):
        """
        Create the crispy-forms FormHelper. The form will then be rendered
        using {% crispy form %} in the template.
        """
        helper = FormHelper()
        helper.attrs['id'] = 'id_user_as_form'
        helper.layout = Layout(
            'use_vpn',
            Row(
                Column(
                    AppendedText('public_ip', '<span class="fa fa-external-link"/>'),
                    css_class='form-group col-md-6 mb-0',
                ),
                Column(
                    AppendedText('public_port', '<span class="fa fa-share-square-o"/>'),
                    css_class='form-group col-md-6 mb-0',
                ),
            ),
            Row(
                Column(
                    AppendedText('bind_ip', '<span class="fa fa-external-link-square"/>'),
                    css_class='form-group col-md-6 mb-0',
                ),
                Column(
                    AppendedText('bind_port', '<span class="fa fa-share-square"/>'),
                    css_class='form-group col-md-6 mb-0',
                ),
                css_id='row_id_bind_addr'
            ),
        )

        return helper
