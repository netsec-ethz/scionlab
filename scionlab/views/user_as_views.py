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
from os import path
import tarfile

import io
from django.core.exceptions import ValidationError
from django.http import HttpResponse
from django.http import HttpResponseRedirect, HttpResponseForbidden
from django.urls import reverse, reverse_lazy
from django.views import View
from django.views.generic import CreateView, UpdateView, DeleteView, ListView
from django.views.generic.detail import SingleObjectMixin
from django import forms

from django.conf import settings
from scionlab.models import UserAS, MAX_PORT
from scionlab.util.generate import create_gen_AS


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
            'label': "Label for this AS (optional)",
            'attachment_point': "Attachment point to connect to",
            'public_ip': "My host's public IP address",
        }
        widgets = {
            'installation_type': forms.RadioSelect(),
        }

    use_vpn = forms.BooleanField(
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
        initial = kwargs.pop('initial', {})
        if instance:
            initial['use_vpn'] = instance.is_use_vpn()
            initial['public_port'] = instance.get_public_port()
        super().__init__(*args, initial=initial, **kwargs)

    def clean(self):
        cleaned_data = super().clean()
        self.user.check_as_quota()
        if cleaned_data.get('use_vpn'):
            cleaned_data.get('attachment_point').check_vpn_available()
        if not cleaned_data.get('use_vpn') and not self.cleaned_data.get('public_ip'):
            raise ValidationError(
                "Please provide a value for public IP, or enable 'Use OpenVPN'.",
                code='missing_public_ip_no_vpn'
            )
        return self.cleaned_data

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
        self.object.set_active(self.active)
        return HttpResponseRedirect(success_url)


class UserASGetConfigView(OwnedUserASQuerysetMixin, SingleObjectMixin, View):
    """
    Download the configuration tar for the first Host of a UserAS
    """

    def get(self, request, *args, **kwargs):
        as_ = self.get_object()
        create_gen_AS(as_.as_id)
        first_host = as_.hosts.first()

        resp = HttpResponse()
        resp['content-disposition'] = 'attachment; filename="{}.tar.gz"'.format(first_host.path_str())
        resp['content-type'] = 'application/gzip'

        tar = tarfile.open(mode='w:gz', fileobj=resp)
        host_gen_dir = path.join(settings.GEN_ROOT, first_host.path_str())
        tar.add(host_gen_dir, arcname="gen")

        if as_.is_use_vpn():
            # Get file from issue #10
            #client_file = path.join(first_host.path_str(), "client.conf")
            #tar.add(client_file, arcname="client.conf")
            raise NotImplementedError('Missing OpenVPN client.conf generation.')

        hostfiles_dir = path.join(settings.BASE_DIR, "scionlab", "hostfiles")
        if as_.installation_type == UserAS.VM:
            readme_file = path.join(hostfiles_dir, "README_vm.md")
            tar.add(readme_file, arcname="README.md")
            if not as_.is_use_vpn():
                forwarding_string = 'config.vm.network "forwarded_port",' \
                                    ' guest: {0}, host: {0}, protocol: "udp"'. \
                    format(first_host.interfaces.first().public_port)
            else:
                forwarding_string = ''
            with open(path.join(hostfiles_dir, "Vagrantfile.tmpl")) as f:
                vagrant_tmpl = f.read()
                vagrant_file_content = vagrant_tmpl.\
                    replace("{{.PortForwarding}}", forwarding_string).\
                    replace("{{.ASID}}", as_.as_id).encode('utf-8')
                vagrant_file = io.BytesIO()
                f_size = vagrant_file.write(vagrant_file_content)
                vagrant_file.seek(0)
                t_info = tarfile.TarInfo("Vagrantfile")
                t_info.size = f_size
                tar.addfile(t_info, vagrant_file)
        elif as_.installation_type == UserAS.DEDICATED:
            readme_file = path.join(hostfiles_dir, "README_standalone.md")
            tar.add(readme_file, arcname="README.md")

        service_files = ["scion.service", "scionupgrade.service", "scion-viz.service", "scionupgrade.timer"]
        script_files = ["run.sh", "scionupgrade.sh"]
        for f in service_files + script_files:
            file_path = path.join(hostfiles_dir, f)
            tar.add(file_path, arcname=f)

        tar.close()

        return resp


class UserASesView(OwnedUserASQuerysetMixin, ListView):
    template_name = "scionlab/user.html"
    model = UserAS
