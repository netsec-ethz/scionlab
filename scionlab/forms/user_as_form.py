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
from crispy_forms.bootstrap import AppendedText
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Layout, Field, Column, Row
from django import forms
from django.forms import modelformset_factory
from django.core.exceptions import ValidationError

from scionlab.forms.attachment_conf_form import AttachmentConfForm, AttachmentConfFormSet
from scionlab.models.core import Link, Host
from scionlab.models.user_as import UserAS, AttachmentPoint
from scionlab.models.vpn import VPN, VPNClient


def _crispy_helper(instance):
    """
    Create the crispy-forms FormHelper. The form will then be rendered
    using {% crispy form %} in the template.
    :param UserAS instance:
    """
    helper = FormHelper()
    helper.attrs['id'] = 'id_user_as_form'
    helper.layout = Layout(
        AppendedText('label', '<span class="fa fa-pencil"/>'),
        Field(
            'installation_type',
            template='scionlab/partials/installation_type_accordion.html',
        ),
        Field(
            'become_user_ap',
            Row(
                Column('public_ip', css_class='col-md-5'),
                Column('provide_vpn', css_class='col-md-5')
            ),
        ),
    )

    # We need this to render the UserASForm along with the AttachmentConfForm
    helper.form_tag = False
    helper.disable_csrf = True

    # Inject some helpers into the context (crispy does the magic):
    helper.accordion_templates = ["scionlab/partials/installation_type_vm.html",
                                  "scionlab/partials/installation_type_pkg.html",
                                  "scionlab/partials/installation_type_src.html"]

    if instance and instance.pk:
        host = instance.hosts.get()
        helper.host_id = host.uid
        helper.host_secret = host.secret

    return helper


class UserASForm(forms.Form):
    """
    Form responsible for the  UserAS model
    """

    prefix = 'user-as'

    label = forms.CharField(
        label="Label",
        help_text="Optional short label for your AS",
        required=False,
    )
    installation_type = forms.ChoiceField(
        choices=UserAS.INSTALLATION_TYPES,
        initial=UserAS.VM,
        required=True,
        widget=forms.RadioSelect(),
    )
    become_user_ap = forms.BooleanField(
        required=False,
        label="Become User AP",
        help_text="Activate this to become AP"
    )
    public_ip = forms.GenericIPAddressField(
        required=False,
        help_text="IP Address that will be used for the connections"
    )
    provide_vpn = forms.BooleanField(
        required=False,
        label="provide VPN",
        help_text="Allow Users to connect to your AP via VPN"
    )

    def _get_attachment_conf_form_set(self, data, instance: UserAS):
        """
        Returns an instance of  `AttachmentConfFormSet`
        :param UserAS instance:
        """
        attachment_conf_form_set = modelformset_factory(Link,
                                                        form=AttachmentConfForm,
                                                        fields=('active',),
                                                        formset=AttachmentConfFormSet,
                                                        max_num=UserAS.MAX_AP_PER_USERAS,
                                                        validate_max=True,
                                                        can_delete=True)
        if instance:
            attach_links = instance.attachment_links().order_by('pk')
        else:
            attach_links = Link.objects.none()
        return attachment_conf_form_set(data, queryset=attach_links,
                                        userASForm=self,
                                        form_kwargs={'user': self.user, 'userAS': instance})

    def __init__(self, data=None, *args, **kwargs):
        self.user = kwargs.pop('user')
        self.instance = kwargs.pop('instance', None)
        self.attachment_conf_form_set = self._get_attachment_conf_form_set(data, self.instance)
        initial = kwargs.pop('initial', {})
        if self.instance:
            host = Host.objects.filter(AS=self.instance).first()
            is_user_ap = False
            has_vpn = False
            if AttachmentPoint.objects.filter(AS=self.instance).first() != None:
                is_user_ap = True
                ap = AttachmentPoint.objects.filter(AS=self.instance).first()
                if ap.vpn != None:
                    has_vpn = True
            initial.update({
                'label': self.instance.label,
                'installation_type': self.instance.installation_type,
                'public_ip': host.public_ip,
                'become_user_ap': is_user_ap,
                'provide_vpn': has_vpn
            })
        self.helper = _crispy_helper(self.instance)
        super().__init__(data, *args, initial=initial, **kwargs)

    def clean(self):
        cleaned_data = super().clean()
        if self.instance is None:
            self.user.check_as_quota()
            
        if cleaned_data['become_user_ap'] and not cleaned_data.get('public_ip'):
            self.add_error(
                'public_ip',
                ValidationError('Please enter a public IP address to become User AP')
            )

        self.attachment_conf_form_set.full_clean()
        return cleaned_data

    def has_changed(self):
        # Note: avoid shortcut eval, to allow inspecting changed_data of the individual forms
        formset_changed = self.attachment_conf_form_set.has_changed()
        self_changed = super().has_changed()
        return self_changed or formset_changed

    def is_valid(self):
        """
        Validate the `UserASForm` (`self`) and the `AttachmentLinksFormSet` attached to it

        Note that the former needs to be validated first, since its fields
        (currently only `installtion_type`) are needed for the validation of the latter
        :returns: whether `UserASForm` (`self`) and the related `AttachmentLinksFormSet` are valid
        """
        # We first need to validate the `UserASForm` to then validate the `AttachmentLinksFormSet`
        return super().is_valid() and self.attachment_conf_form_set.is_valid()

    def save(self, commit=True):
        wants_user_ap = self.cleaned_data['become_user_ap']
        wants_vpn = self.cleaned_data['provide_vpn']
        if not self.instance:
            user_as = UserAS.objects.create(
                owner=self.user,
                isd=self.attachment_conf_form_set.isd,
                installation_type=self.cleaned_data['installation_type'],
                label=self.cleaned_data['label'],
            )
            self.attachment_conf_form_set.save(user_as)
            if wants_user_ap:
                ap = AttachmentPoint.objects.create(AS = user_as)
                host = user_as.hosts.first()
                host.update(public_ip = self.cleaned_data['public_ip'])
                if wants_vpn:
                    vpn = VPN.objects.create(server = host, server_port = 1194)
                    ap.vpn = vpn
                    ap.save()
            return user_as
        else:
            self.instance.update(
                installation_type=self.cleaned_data['installation_type'],
                label=self.cleaned_data['label']
            )
            host = self.instance.hosts.first()
            host.update(public_ip = self.cleaned_data['public_ip'])
                      
            if self.instance.is_attachment_point():
                # does the User already offer a VPN connection?
                has_vpn = False
                if VPN.objects.filter(server = self.instance.hosts.first()).first() != None:
                    has_vpn = True
                if not wants_user_ap:
                # User unchecks the 'become ap' box meaning he will not be AP anymore
                    if has_vpn:
                        vpn = VPN.objects.filter(server = self.instance.hosts.first()).delete()
                    AttachmentPoint.objects.filter(AS=self.instance).delete()
                    Link.objects.filter(interfaceA__AS=self.instance).delete()
                elif not has_vpn and wants_vpn:
                # User wants to provide a VPN for his already existing AP
                    ap = AttachmentPoint.objects.filter(AS = self.instance).first()
                    ap.vpn = VPN.objects.create(server = host, server_port = 1194)
                    ap.save()
            elif wants_user_ap:
                # a new User AP will be created
                ap = AttachmentPoint.objects.create(AS = self.instance)
                if wants_vpn:
                    ap.vpn = VPN.objects.create(server = host, server_port = 1194)
                    ap.save()
            self.attachment_conf_form_set.save(self.instance)
            return self.instance
