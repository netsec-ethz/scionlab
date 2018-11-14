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

import pdb
from django.conf import settings
from django.core.exceptions import ValidationError
from django.urls import reverse, reverse_lazy
from django.views.generic import CreateView, UpdateView, DeleteView, ListView
from django import forms

from scionlab.models import UserAS, AttachmentPoint, MAX_PORT

class UserASForm(forms.ModelForm):
    class Meta:
        model = UserAS
        fields = ('label', 'attachment_point', 'installation_type', 'public_ip', 'bind_ip', 'bind_port')
        labels = {
            'label': "Label for this AS (optional)",
            'attachment_point': "Attachment point to connect to",
            'public_ip': "My host's public IP address",
        }
        widgets = {
            'installation_type': forms.RadioSelect(),
        }

    use_vpn = forms.BooleanField(
        initial=False, 
        required=False,
        label="Use OpenVPN connection for this AS"
    )
    public_port = forms.IntegerField(
        min_value=1024,
        max_value=MAX_PORT,
        initial=50000,
        label="Port where this AS accepts traffic"
    )

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user')
        instance = kwargs.get('instance')
        initial = kwargs.pop('initial')
        if instance:
            initial['use_vpn'] = instance.is_use_vpn()
            initial['public_port'] = instance.get_public_port()
        super().__init__(*args, **kwargs)

    def clean(self):
        cleaned_data = super().clean()
        if not cleaned_data.get('use_vpn') and not self.cleaned_data.get('public_ip'):
            raise ValidationError(
                "Please provide a value for public IP, or enable 'Use VPN'.",
                code='missing_public_ip_no_vpn'
            )
        return self.cleaned_data

    def save(self, commit=True):
        return UserAS.objects.create(
            user = self.user,
            label = self.cleaned_data['label'],
            attachment_point = self.cleaned_data['attachment_point'],
            use_vpn = self.cleaned_data['use_vpn'],
            public_ip = self.cleaned_data['public_ip'],
            public_port = self.cleaned_data['public_port'],
            bind_ip = self.cleaned_data['bind_ip'],
            bind_port = self.cleaned_data['bind_port'],
        )


class UserASCreateView(CreateView):
    template_name = "scionlab/user_as_add.html"
    model = UserAS
    form_class = UserASForm

    def get_success_url(self):
        return reverse('user_as_detail', kwargs={'pk': self.object.pk})

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.request.user
        return kwargs

class UserASDetailView(UpdateView):
    template_name = "scionlab/user_as_details.html"
    model = UserAS
    form_class = UserASForm

    def get_queryset(self):
        return UserAS.objects.filter(owner=self.request.user)
    
    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.request.user
        return kwargs


class UserASDeleteView(DeleteView):
    model = UserAS
    sucess_url = reverse_lazy('user')

    def get_queryset(self):
        return UserAS.objects.filter(owner=self.request.user)


class UserASesView(ListView):
    template_name = "scionlab/user.html"
    model = UserAS

    def get_queryset(self):
        return UserAS.objects.filter(owner=self.request.user)
