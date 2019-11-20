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
import tarfile
from contextlib import closing

from django.http import HttpResponseRedirect, HttpResponseForbidden
from django.urls import reverse, reverse_lazy
from django.views import View
from django.views.generic import CreateView, UpdateView, DeleteView, ListView
from django.views.generic.detail import SingleObjectMixin

from scionlab import config_tar
from scionlab.util.http import HttpResponseAttachment
from scionlab.models.user_as import UserAS, AttachmentPoint
from scionlab.forms.user_as_form import UserASForm
from scionlab.util.archive import TarWriter


class _AttachmentPointsContextData:
    """
    Helper mixin to add attachment points info to context dict
    """
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        ap_data = {
            str(ap.pk): {
                'has_vpn': bool(ap.vpn)
            }
            for ap in AttachmentPoint.objects.all()
        }
        context['attachment_points'] = ap_data
        return context


class UserASCreateView(_AttachmentPointsContextData, CreateView):
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

        return super(UserASCreateView, self).post(request, *args, **kwargs)

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
        return super().get_queryset().filter(owner=self.request.user)


class UserASDetailView(_AttachmentPointsContextData, OwnedUserASQuerysetMixin, UpdateView):
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
        with closing(tarfile.open(mode='w:gz', fileobj=resp)) as tar:
            config_tar.generate_user_as_config_tar(user_as, TarWriter(tar))
        return resp


class UserASesView(OwnedUserASQuerysetMixin, ListView):
    template_name = "scionlab/user.html"
    model = UserAS
    ordering = ['as_id']
