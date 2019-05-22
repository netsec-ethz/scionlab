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

from django.views.generic.base import TemplateView
from django.contrib import admin
from django.contrib.auth.decorators import login_required
from django.urls import include, path

from scionlab.views.user_as_views import (
    UserASesView,
    UserASCreateView,
    UserASDeleteView,
    UserASActivateView,
    UserASDetailView,
    UserASGetConfigView)
from scionlab.views.registration_view import UserRegistrationView, UserRegistrationResendView
from scionlab.views.api import GetHostConfig, PostHostDeployedConfigVersion
from scionlab.views.topology import topology_png

urlpatterns = [
    path('', TemplateView.as_view(template_name='scionlab/home.html'), name='home'),

    # Admin space
    path('admin/', admin.site.urls),

    # Authentication
    # django.contrib.auth: auth views for logout, password reset/change
    path('', include('django.contrib.auth.urls')),

    # django-registration patterns
    path('registration/register/',
         UserRegistrationView.as_view(),
         name='registration_form'),
    path('registration/resend',
         UserRegistrationResendView.as_view(),
         name='registration_resend'),
    path('registration/confirm',
         TemplateView.as_view(template_name='django_registration/registration_confirm.html'),
         name='registration_confirm'),
    path('registration/', include('django_registration.backends.activation.urls')),

    # user pages
    path('user/', login_required(UserASesView.as_view()), name='user'),
    path('user/as/add', login_required(UserASCreateView.as_view()), name='user_as_add'),
    # TODO(matzf): maybe we need a slugified AS-id to use in the URL instead of the PK
    path('user/as/<int:pk>/delete',
         login_required(UserASDeleteView.as_view()),
         name='user_as_delete'),
    path('user/as/<int:pk>/activate',
         login_required(UserASActivateView.as_view(active=True)),
         name='user_as_activate'),
    path('user/as/<int:pk>/deactivate',
         login_required(UserASActivateView.as_view(active=False)),
         name='user_as_deactivate'),
    path('user/as/<int:pk>/config',
         login_required(UserASGetConfigView.as_view()),
         name='user_as_config'),
    path('user/as/<int:pk>',
         login_required(UserASDetailView.as_view()),
         name='user_as_detail'),

    path('topology.png', topology_png, name='topology.png'),

    # API:
    path('api/host/<slug:uid>/config',
         GetHostConfig.as_view(),
         name='api_get_config'),
    path('api/host/<slug:uid>/deployed_config_version',
         PostHostDeployedConfigVersion.as_view(),
         name='api_post_deployed_version'),
]
