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
from django.forms import BaseModelFormSet
from django.core.exceptions import ValidationError

from crispy_forms.helper import FormHelper
from crispy_forms.layout import Layout, Row, Column, Div
from crispy_forms.bootstrap import AppendedText

from scionlab.defines import MAX_PORT
from scionlab.models.core import Link
from scionlab.models.user_as import AttachmentPoint, AttachmentPointConf
from scionlab.util.portmap import PortMap


class AttachmentLinksFormSetHelper(FormHelper):
    """
    Create the crispy-forms FormHelper. The form will then be rendered
    using {% crispy form %} in the template.
    """

    def __init__(self, *args, **kwargs):
        super(AttachmentLinksFormSetHelper, self).__init__(*args, **kwargs)
        self.layout = Layout(
            Div(
                Div(
                    Row(
                        Column(
                            'active',
                            css_class='form-group col-md-2 mb-0',
                        ),
                        Column(
                            'use_vpn',
                            css_class='form-group col-md-5 mb-0',
                        ),
                        Column(
                            'attachment_point',
                            css_class='form-group col-md-5 mb-0',
                        ),
                    ),
                    css_class="card-header"
                ),
                Div(
                    Row(
                        Column(
                            AppendedText('public_ip', '<span class="fa fa-external-link"/>'),
                            css_class='form-group col-md-6 mb-0',
                        ),
                        Column(
                            AppendedText('public_port', '<span class="fa fa-share-square-o"/>'),
                            css_class='form-group col-md-6 mb-0',
                        ),
                        Column(
                            AppendedText('bind_ip', '<span class="fa fa-external-link-square"/>'),
                            css_class='form-group col-md-6 mb-0',
                        ),
                        Column(
                            AppendedText('bind_port', '<span class="fa fa-share-square"/>'),
                            css_class='form-group col-md-6 mb-0',
                        ),
                        Column(
                            'DELETE',
                            css_class='text-danger form-group col-md-6 mb-0'
                        )
                    ),
                    css_class="card-body"
                ),
                css_class="card attachment",
                style="margin-top: 16px;"
            )
        )
        # We need this to render the AttachmentLinksFormSet along with the UserASForm
        self.form_tag = False
        self.disable_csrf = True


class AttachmentLinksFormSet(BaseModelFormSet):

    def __init__(self, *args, **kwargs):
        super(AttachmentLinksFormSet, self).__init__(*args, **kwargs)
        self.helper = AttachmentLinksFormSetHelper()

    def clean(self):
        if any(self.errors):
            # Don't bother validating the formset unless each form is valid on its own
            return
        # Check isd and ports clash
        isd_set = set()
        public_ports_map = PortMap()
        public_port_clashing_forms = []
        bind_ports_map = PortMap()
        bind_port_clashing_forms = []
        for form in self.forms:
            if self.can_delete and self._should_delete_form(form):
                continue
            # Skip empty forms and deactivated connections
            if not form.cleaned_data or not form.cleaned_data['active']:
                continue
            isd_set.add(form.cleaned_data['attachment_point'].AS.isd)
            if not form.cleaned_data['use_vpn']:
                if public_ports_map.add(form.cleaned_data['public_ip'],
                                        form.cleaned_data['public_port']):
                    public_port_clashing_forms.append(form)
            if form.cleaned_data['bind_port']:
                if bind_ports_map.add(form.cleaned_data['bind_ip'],
                                      form.cleaned_data['bind_port']):
                    bind_port_clashing_forms.append(form)
        # Public ports clash errors adding
        for form in public_port_clashing_forms:
            form.add_error('public_port',
                           ValidationError('The port is already in use',
                                           code='public_port_clash'))
        # Bind ports clash errors adding
        for form in bind_port_clashing_forms:
            form.add_error('bind_port',
                           ValidationError('The port is already in use',
                                           code='bind_port_clash'))
        # Same ISD check
        if len(isd_set) > 1:
            raise ValidationError("All attachment points must belong to the "
                                  "same ISD")

    def save(self, user_as, commit=True):
        self.user_as = user_as
        for ap_conf in super().save(commit=False):
            AttachmentLinkForm._create_or_update(user_as, ap_conf)
        # We save the deleted AP in a set so we only call the cleaning/updating methods once per AP
        deleted_aps_set = set()
        for attachment_link in self.deleted_objects:
            deleted_aps_set.add(attachment_link.interfaceA.AS.attachment_point_info)
            attachment_link.delete()
        for ap in deleted_aps_set:
            ap.split_border_routers()
            ap.trigger_deployment()


class AttachmentLinkFormHelper(FormHelper):
    def __init__(self, *args, **kwargs):
        """
        Create the crispy-forms FormHelper. The form will then be rendered
        using {% crispy form %} in the template.
        """
        super(AttachmentLinkFormHelper, self).__init__(*args, **kwargs)
        self.attrs['id'] = 'id_attachment_link_form'
        self.layout = Layout(
            Row(
                Column(
                    'use_vpn',
                    css_class='form-group col-md-6 mb-0',
                ),
                Column(
                    'attachment_point',
                    css_class='form-group col-md-6 mb-0',
                ),
            ),
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
        # We need this to render the AttachmentLinkForm along with the UserASForm
        self.form_tag = False
        self.disable_csrf = True


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
        help_text="The attachment point will use this port"
                  "for the overlay link to your AS."
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
            initial['use_vpn'] = instance.interfaceB.is_over_vpn
            initial['public_ip'] = instance.interfaceB.public_ip
            initial['public_port'] = instance.interfaceB.public_port
            initial['bind_ip'] = instance.interfaceB.bind_ip
            initial['bind_port'] = instance.interfaceB.bind_port
        self.helper = AttachmentLinkFormHelper()
        super().__init__(*args, initial=initial, **kwargs)

    def clean(self):
        cleaned_data = super().clean()
        assert 'attachment_point' in cleaned_data, "At least an attachment point must be specified"
        if cleaned_data.get('use_vpn'):
            cleaned_data.get('attachment_point').check_vpn_available()
        elif 'public_ip' in self.errors:
            assert ('public_ip' not in cleaned_data)
            return cleaned_data
        else:
            public_ip = cleaned_data.get('public_ip')
            if not public_ip:
                # public_ip cannot be empty when use_vpn is false
                raise ValidationError(
                    'Please provide a value for public IP, or enable "Use VPN".',
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

    @staticmethod
    def _create_or_update(user_as, ap_conf):
        if ap_conf.link is None:
            # Create
            return user_as.create_attachment(ap_conf)
        else:
            # Update
            return user_as.update_attachment(ap_conf)

    def save(self, commit=True, user_as=None):
        """
        Create/update the attachment if `commit=True`, otherwise returns an
        `AttachmentPointConf` to hold the provided settings
        :return AttachmentPointConf:
        """
        ap_conf = AttachmentPointConf(self.cleaned_data['attachment_point'],
                                      self.cleaned_data['public_ip'],
                                      self.cleaned_data['public_port'],
                                      self.cleaned_data['bind_ip'],
                                      self.cleaned_data['bind_port'],
                                      self.cleaned_data['use_vpn'],
                                      self.cleaned_data['active'],
                                      self.instance if self.instance.pk is not None else None)
        if commit:
            assert user_as is not None
            self._create_or_update(user_as, ap_conf)
        else:
            # Just return an AttachmentPointConf representing the attachment
            return ap_conf
