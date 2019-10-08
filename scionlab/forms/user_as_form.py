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
from django.core.exceptions import ValidationError

from crispy_forms.helper import FormHelper
from crispy_forms.layout import Layout, Row, Column
from crispy_forms.bootstrap import AppendedText

from scionlab.models.user_as import UserAS, AttachmentPoint


class UserASForm(forms.ModelForm):
    """
    Form for UserAS creation and update.
    """

    prefix = 'userAS'

    class Meta:
        model = UserAS
        fields = (
            'label',
            'installation_type',
        )
        labels = {
            'label': "Label",
        }
        help_texts = {
            'label': "Optional short label for your AS",
        }
        widgets = {
            'installation_type': forms.RadioSelect(),
        }
    public_ip = forms.GenericIPAddressField(
        help_text="Public IP for this host",
        required=False
    )
    bind_ip = forms.GenericIPAddressField(
        help_text="Bind IP for this host",
        required=False
    )

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user')
        instance = kwargs.get('instance')
        self.attachment_points_vpn = kwargs.pop('attachment_points_vpn', None)
        initial = kwargs.pop('initial', {})
        if instance:
            initial['public_ip'] = instance.host.public_ip
            initial['bind_ip'] = instance.host.bind_ip
        #  self.helper = self._crispy_helper()
        super().__init__(*args, initial=initial, **kwargs)

    def clean(self):
        cleaned_data = super().clean()
        assert self.attachment_points_vpn
        if self.instance.pk is None:
            self.user.check_as_quota()
        for attachment_point, use_vpn in self.attachment_points_vpn: 
            if use_vpn:
                continue
            if 'public_ip' in self.errors:
                assert('public_ip' not in cleaned_data)
                return cleaned_data
            else:
                public_ip = cleaned_data.get('public_ip')
                if not public_ip:
                    # public_ip cannot be empty when use_vpn is false
                    raise ValidationError(
                        'Please provide a value for public IP when connecting to an attachment point without OpenVPN',
                        code='missing_public_ip_no_vpn'
                    )
                ip_addr = ipaddress.ip_address(public_ip)


                if ip_addr.version not in attachment_point.supported_ip_versions():
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

    def save(self, commit=True):
        if self.instance.pk is None:
            assert commit == False, """The creation of the UserAS must be carried out with \
                                       UserAS.objects.create(...)"""
            return UserAS(
                owner=self.user,
                label=self.cleaned_data['label'],
                installation_type=self.cleaned_data['installation_type'],
                public_ip=self.cleaned_data['public_ip']
            )
        else:
            self.instance.update(
                self.cleaned_data['label'],
                self.cleaned_data['public_ip'],
                self.cleaned_data['bind_ip'],
                self.cleaned_data['installation_type'],
            )
            return self.instance

    #  def _crispy_helper(self):
        #  """
        #  Create the crispy-forms FormHelper. The form will then be rendered
        #  using {% crispy form %} in the template.
        #  """
        #  helper = FormHelper()
        #  helper.attrs['id'] = 'id_user_as_form'
        #  helper.layout = Layout(
            #  AppendedText('label', '<span class="fa fa-pencil"/>'),
            #  'installation_type',
            #  Row(
                #  Column(
                    #  AppendedText('public_ip', '<span class="fa fa-external-link"/>'),
                    #  css_class='form-group col-md-6 mb-0',
                #  ),
                #  Column(
                    #  AppendedText('bind_ip', '<span class="fa fa-external-link-square"/>'),
                    #  css_class='form-group col-md-6 mb-0',
                #  ),
            #  ),
        #  )

        #  return helper
