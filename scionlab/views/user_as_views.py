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

from django.core.exceptions import ValidationError
from django.http import HttpResponseRedirect, HttpResponseForbidden
from django.urls import reverse, reverse_lazy
from django.views import View
from django.views.generic import CreateView, UpdateView, DeleteView, ListView
from django.views.generic.detail import SingleObjectMixin
from django import forms
from django.conf import settings
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Layout, Row, Column
from crispy_forms.bootstrap import AppendedText

from scionlab.defines import MAX_PORT
from scionlab.models.user_as import UserAS, AttachmentPoint
from scionlab.util.http import HttpResponseAttachment
from scionlab import config_tar


class UserASForm(forms.ModelForm):
    """
    Form for UserAS creation and update.
    """
    class Meta:
        model = UserAS
        fields = (
            'label',
            'attachment_point',
            'installation_type',
            'public_ip',
            'bind_ip',
            'bind_port'
        )
        labels = {
            'label': "Label",
            'attachment_point': "Attachment Point",
            'public_ip': "Public IP address",
            'bind_ip': "Bind IP address",
            'bind_port': "Bind Port",
        }
        help_texts = {
            'label': "Optional short label for your AS",
            'attachment_point': "This SCIONLab-infrastructure AS will be the provider for your AS.",
            'public_ip': "The attachment point will use this IP for the overlay link to your AS.",
            'bind_ip': "(Optional) Specify the local IP/port "
                       "if your border router is behind a NAT/firewall etc.",
        }
        widgets = {
            'installation_type': forms.RadioSelect(),
        }
    use_vpn = forms.BooleanField(
        required=False,
        label="Use VPN",
        help_text="Use an OpenVPN connection for the overlay link between the attachment point "
                  "and the border router of my AS."
    )
    public_port = forms.IntegerField(
        min_value=1024,
        max_value=MAX_PORT,
        initial=50000,
        label="Public Port (UDP)",
        help_text="The attachment point will use this port for the overlay link to your AS."
    )

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user')
        instance = kwargs.get('instance')
        initial = kwargs.pop('initial', {})
        if instance:
            initial['use_vpn'] = instance.is_use_vpn()
            initial['public_port'] = instance.get_public_port()
        self.helper = self._crispy_helper()
        super().__init__(*args, initial=initial, **kwargs)

    def clean(self):
        cleaned_data = super().clean()
        if self.instance.pk is None:
            self.user.check_as_quota()
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

    def save(self, commit=True):
        if self.instance.pk is None:
            return UserAS.objects.create(
                owner=self.user,
                label=self.cleaned_data['label'],
                attachment_point=self.cleaned_data['attachment_point'],
                installation_type=self.cleaned_data['installation_type'],
                use_vpn=self.cleaned_data['use_vpn'],
                public_ip=self.cleaned_data['public_ip'],
                public_port=self.cleaned_data['public_port'],
                bind_ip=self.cleaned_data['bind_ip'],
                bind_port=self.cleaned_data['bind_port'],
            )
        else:
            self.instance.update(
                label=self.cleaned_data['label'],
                attachment_point=self.cleaned_data['attachment_point'],
                installation_type=self.cleaned_data['installation_type'],
                use_vpn=self.cleaned_data['use_vpn'],
                public_ip=self.cleaned_data['public_ip'],
                public_port=self.cleaned_data['public_port'],
                bind_ip=self.cleaned_data['bind_ip'],
                bind_port=self.cleaned_data['bind_port'],
            )
            return self.instance

    def _crispy_helper(self):
        """
        Create the crispy-forms FormHelper. The form will then be rendered
        using {% crispy form %} in the template.
        """
        helper = FormHelper()
        helper.attrs['id'] = 'id_user_as_form'
        helper.layout = Layout(
            'attachment_point',
            AppendedText('label', '<span class="fa fa-pencil"/>'),
            'installation_type',
            'use_vpn',
            AppendedText('public_ip', '<span class="fa fa-external-link"/>'),
            AppendedText('public_port', '<span class="fa fa-share-square-o"/>'),
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


class UserASCreateView(CreateView):
    template_name = "scionlab/user_as_add.html"
    model = UserAS
    form_class = UserASForm

    def get(self, request, *args, **kwargs):
        user = self.request.user
        if user.num_ases() >= user.max_num_ases():
            return HttpResponseForbidden()
        return super().get(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        user = self.request.user
        if user.num_ases() >= user.max_num_ases():
            return HttpResponseForbidden()
        return super().post(request, *args, **kwargs)

    def get_success_url(self):
        return reverse('user_as_detail', kwargs={'pk': self.object.pk})

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.request.user
        return kwargs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        _add_attachment_point_data(context)
        return context


class OwnedUserASQuerysetMixin:
    """
    Defines get_queryset to get only the UserASes owned by
    the current user.
    To be used in a View that uses `django.views.generic.detail.SingleObjectMixin`
    """
    def get_queryset(self):
        return UserAS.objects.filter(owner=self.request.user)


class UserASDetailView(OwnedUserASQuerysetMixin, UpdateView):
    template_name = "scionlab/user_as_details.html"
    model = UserAS
    form_class = UserASForm

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.request.user
        return kwargs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        _add_attachment_point_data(context)
        return context


class UserASDeleteView(OwnedUserASQuerysetMixin, DeleteView):
    template_name = "scionlab/user_as_confirm_delete.html"
    model = UserAS
    success_url = reverse_lazy('user')


class UserASActivateView(OwnedUserASQuerysetMixin, SingleObjectMixin, View):
    """
    Activate or deactivate the UserAS
    """
    model = UserAS
    active = None

    def __init__(self, active, *args, **kwargs):
        self.active = active
        super().__init__(*args, **kwargs)

    def get_success_url(self):
        return reverse('user_as_detail', kwargs={'pk': self.object.pk})

    def post(self, request, *args, **kwargs):
        self.object = self.get_object()
        success_url = self.get_success_url()
        self.object.update_active(self.active)
        return HttpResponseRedirect(success_url)


class UserASGetConfigView(OwnedUserASQuerysetMixin, SingleObjectMixin, View):
    """
    Download the configuration tar for the UserAS
    """

    def get(self, request, *args, **kwargs):
        user_as = self.get_object()
        filename = 'scion_lab_{user}_{ia}.tar.gz'.format(
                        user=user_as.owner.email,
                        ia=user_as.isd_as_path_str())
        resp = HttpResponseAttachment(filename=filename, content_type='application/gzip')
        config_tar.generate_user_as_config_tar(user_as, resp)
        return resp


class UserASesView(OwnedUserASQuerysetMixin, ListView):
    template_name = "scionlab/user.html"
    model = UserAS


def _add_attachment_point_data(context):
    """
    Helper for UserASCreateView and UserASDetailView.
    Add attachment point data to context dict.
    """
    ap_data = {
        str(ap.pk): {
            'has_vpn': bool(ap.vpn)
        }
        for ap in AttachmentPoint.objects.all()
    }
    context['attachment_points'] = ap_data
