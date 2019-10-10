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
from collections import namedtuple

from django.http import HttpResponseRedirect, HttpResponseForbidden
from django.urls import reverse, reverse_lazy
from django.shortcuts import render
from django.views import View
from django.views.generic import CreateView, UpdateView, DeleteView, ListView
from django.views.generic.detail import SingleObjectMixin
from django.forms import BaseModelFormSet, modelformset_factory

from scionlab import config_tar
from scionlab.util.http import HttpResponseAttachment
from scionlab.models.core import Link
from scionlab.models.user_as import UserAS, AttachmentPoint
from scionlab.forms.user_as_form import UserASForm
from scionlab.forms.attachment_link_form import AttachmentLinkForm, AttachmentLinksFormSet


# TODO: How much should this be?
MAX_AP_PER_USERAS = 50
AttachmentPointVPN = namedtuple('AttachmentPointVPN', ['attachment_point', 'vpn'])


class UserASCreateView(CreateView):
    template_name = "scionlab/user_as_add.html"
    model = UserAS
    form_class = UserASForm

    def get(self, request, *args, **kwargs):
        user = self.request.user
        if user.num_ases() >= user.max_num_ases():
            return HttpResponseForbidden()
        context = {
                'userASForm': UserASForm(user=user),
                'addAttachmentLinkForm': AttachmentLinkForm(user=user)
        }
        return render(request, self.template_name, context=context)

    def post(self, request, *args, **kwargs):
        user = self.request.user
        if user.num_ases() >= user.max_num_ases():
            return HttpResponseForbidden()
        attachmentLinkForm = AttachmentLinkForm(request.POST, user=user)
        # Trigger clean with `is_valid()' on attachmentLinkForm since 
        # data from it are needed to validate the userASForm
        attachmentLinkForm.is_valid()
        attachment_point_vpn = AttachmentPointVPN(attachmentLinkForm.cleaned_data['attachment_point'],
                                attachmentLinkForm.cleaned_data['use_vpn'])
        userASForm = UserASForm(request.POST, user=user,
                                attachment_points_vpn=[attachment_point_vpn]
                               )
        if not attachmentLinkForm.is_valid() or not userASForm.is_valid():
            context = {
                    'userASForm': userASForm,
                    'addAttachmentLinkForm': attachmentLinkForm
            }
            return render(request, self.template_name, context=context)
        else:
            isd = attachment_point_vpn.attachment_point.AS.isd
            userAS = UserAS.objects.create(user, userASForm.cleaned_data['installation_type'], isd,
                                           public_ip=userASForm.cleaned_data['public_ip'],
                                           label=userASForm.cleaned_data['label'])
            attachmentLink = attachmentLinkForm.save(userAS)
            return HttpResponseRedirect(reverse('user_as_detail', kwargs={'pk': userAS.pk}))

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

    def get(self, request, *args, **kwargs):
        user = self.request.user
        userAS = self.get_object()
        attachmentLinksFormSet = modelformset_factory(Link,
                                                      form=AttachmentLinkForm,
                                                      fields=('active',),
                                                      formset=AttachmentLinksFormSet,
                                                      max_num=MAX_AP_PER_USERAS,
                                                      validate_max=True)
        attachmentLinksFormSet = attachmentLinksFormSet(queryset=Link.objects.filter(interfaceB__AS=userAS),
                                                        form_kwargs={'user': user}
                                                       )
        context = {
                'object': userAS,
                'userASForm': UserASForm(user=user, instance=userAS),
                'attachmentLinksFormSet': attachmentLinksFormSet
        }
        return render(request, self.template_name, context=context)

    def post(self, request, *args, **kwargs):
        user = self.request.user
        userAS = self.get_object()
        attachmentLinksFormSet = modelformset_factory(Link,
                                                      form=AttachmentLinkForm,
                                                      fields=('active',),
                                                      formset=AttachmentLinksFormSet,
                                                      max_num=MAX_AP_PER_USERAS,
                                                      validate_max=True)
        attachmentLinksFormSet = attachmentLinksFormSet(request.POST, request.FILES,
                                                        queryset=Link.objects.filter(interfaceB__AS=userAS),
                                                        form_kwargs={'user': user}
                                                       )
        if not attachmentLinksFormSet.is_valid():
            context = {
                    'object': userAS,
                    'userASForm': UserASForm(user=user),
                    'attachmentLinksFormSet': attachmentLinksFormSet
            }
            return render(request, self.template_name, context=context)
        else:
            attachment_points_vpn = [AttachmentPointVPN(form.cleaned_data['attachment_point'],
                                                        form.cleaned_data['use_vpn'])
                                     for form in attachmentLinksFormSet.forms
                                     if form.cleaned_data
                                    ]
            userASForm = UserASForm(request.POST, user=user, instance=userAS,
                                    attachment_points_vpn=attachment_points_vpn,
                                   )
            if not userASForm.is_valid():
                context = {
                        'object': userAS,
                        'userASForm': userASForm,
                        'attachmentLinksFormSet': attachmentLinksFormSet
                }
                return render(request, self.template_name, context=context)
            isd = attachment_points_vpn[0].attachment_point.AS.isd
            userASForm.save()
            attachmentLinksFormSet.save(userAS)
            return HttpResponseRedirect(reverse('user_as_detail', kwargs={'pk': userAS.pk}))


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
