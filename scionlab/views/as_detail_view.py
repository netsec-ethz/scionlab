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

from django.conf import settings
from django.views.generic import TemplateView

from scionlab.models import AS, AttachmentPoint, User


class ASDetailView(TemplateView):
    template_name = "scionlab/as_details.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        username = self.request.user
        current_user = User.objects.filter(username=username).first()
        ASes = AS.objects
        user_AS = ASes.filter(owner=current_user).filter(as_id=context['as_id']).first()
        attachment_points = AttachmentPoint.objects.prefetch_related('AS').all()
        attachment_points_ASes = [ap.AS for ap in attachment_points]

        # Context
        context['grafana_url'] = settings.GRAFANA_URL
        context['user_as'] = user_AS
        context['attachment_points'] = attachment_points_ASes
        context['vpn_support_enabled'] = False
        context['iot_images'] = settings.IOT_IMAGES
        return context
