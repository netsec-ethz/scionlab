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
from crispy_forms.layout import Layout, Field
from django import forms
from django.forms import modelformset_factory

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
        attach_links = Link.objects.filter(
            interfaceB__AS=instance,
        ).exclude(  # ignore links to non-APs (can be added through the admin panel)
            interfaceA__AS__attachment_point_info=None,
        ).order_by('pk')
        return attachment_conf_form_set(data, queryset=attach_links,
                                        userASForm=self,
                                        form_kwargs={'user': self.user, 'userAS': instance})

    def __init__(self, data=None, *args, **kwargs):
        self.user = kwargs.pop('user')
        self.instance = kwargs.pop('instance', None)
        self.attachment_conf_form_set = self._get_attachment_conf_form_set(data, self.instance)
        initial = kwargs.pop('initial', {})
        if self.instance:
            initial.update({
                'label': self.instance.label,
                'installation_type': self.instance.installation_type,
            })
        self.helper = _crispy_helper(self.instance)
        super().__init__(data, *args, initial=initial, **kwargs)

    def clean(self):
        cleaned_data = super().clean()
        if self.instance is None:
            self.user.check_as_quota()

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
        if not self.instance:
            user_as = UserAS.objects.create(
                owner=self.user,
                isd=self.attachment_conf_form_set.isd,
                installation_type=self.cleaned_data['installation_type'],
                label=self.cleaned_data['label'],
            )
            self.attachment_conf_form_set.save(user_as)
            return user_as
        else:
            self.instance.update(
                installation_type=self.cleaned_data['installation_type'],
                label=self.cleaned_data['label']
            )
            self.attachment_conf_form_set.save(self.instance)
            return self.instance
