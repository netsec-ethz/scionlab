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
from crispy_forms.layout import Layout, Field, Column, Row, Div
from django import forms
from django.forms import modelformset_factory
from django.core.exceptions import ValidationError

from scionlab.forms.attachment_conf_form import AttachmentConfForm, AttachmentConfFormSet
from scionlab.models.core import Link
from scionlab.models.user_as import UserAS


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
        Div(
            Div(
                Row(
                    'become_user_ap',
                ),
                css_class="card-header",
            ),
            Div(
                Row(
                    Column('public_ip', css_class='col-md-5'),
                    Column('provide_vpn', css_class='col-md-5'),
                ),
                css_class="card-body", css_id="user-ap-card-body",
            ),
            css_class="card",
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
        label="Make this AS a publicly available Attachment Point",
        help_text="""If this option is enabled, this AS will show up in the list of available
        Attachment Points. All users will be able to create provider links to this AS.<br/> Your
        host will have to run the scionlab-config daemon, in order to refresh its configuration
        whenever other users create or modify links to your AS. Please refer to
        <a href='https://docs.scionlab.org' target='_blank'>Tutorials</a> for more details."""
    )
    public_ip = forms.GenericIPAddressField(
        required=False,
        label="Public IP",
        help_text="Public IP Address to be used for connections to child ASes"
    )
    provide_vpn = forms.BooleanField(
        required=False,
        label="Provide VPN",
        help_text="Allow Users to connect to your AP via VPN"
    )

    def _get_attachment_conf_form_set(self, data, instance: UserAS):
        """
        Returns an instance of  `AttachmentConfFormSet`
        :param UserAS instance:
        """
        attachment_conf_form_set = modelformset_factory(Link,
                                                        form=AttachmentConfForm,
                                                        fields=(),
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
        has_vpn = False
        if self.instance:
            host = self.instance.host
            is_ap = self.instance.is_attachment_point()
            has_vpn = is_ap and self.instance.attachment_point_info.vpn is not None
            initial.update({
                'label': self.instance.label,
                'installation_type': self.instance.installation_type,
                'public_ip': host.public_ip,
                'become_user_ap': is_ap,
                'provide_vpn': has_vpn
            })
        self.helper = _crispy_helper(self.instance)
        super().__init__(data, *args, initial=initial, **kwargs)
        if has_vpn:
            self.fields['provide_vpn'].widget.attrs['disabled'] = 'disabled'

    def clean(self):
        cleaned_data = super().clean()
        if self.instance is None:
            self.user.check_as_quota()

        self.attachment_conf_form_set.full_clean()

        if cleaned_data['become_user_ap']:
            if not cleaned_data.get('public_ip'):
                self.add_error(
                    'public_ip',
                    ValidationError('Please enter a public IP address to become User AP')
                )

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
        if not self.instance:
            user_as = UserAS.objects.create(
                owner=self.user,
                isd=self.attachment_conf_form_set.isd,
                installation_type=self.cleaned_data['installation_type'],
                label=self.cleaned_data['label'],
                public_ip=self.cleaned_data['public_ip'],
                wants_user_ap=self.cleaned_data['become_user_ap'],
                wants_vpn=self.cleaned_data['provide_vpn'],
            )
            self.attachment_conf_form_set.save(user_as)
            return user_as
        else:
            self.instance.update(
                installation_type=self.cleaned_data['installation_type'],
                label=self.cleaned_data['label'],
                public_ip=self.cleaned_data['public_ip'],
                wants_user_ap=self.cleaned_data['become_user_ap'],
                wants_vpn=self.cleaned_data['provide_vpn'],
            )
            self.attachment_conf_form_set.save(self.instance)
            return self.instance
