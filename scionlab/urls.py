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

from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.contrib.auth.decorators import login_required
from django.urls import include, path, reverse_lazy

from scionlab.ases_view import ASesView
from scionlab.registration_view import UserRegistrationView

urlpatterns = [
    path('login/', auth_views.LoginView.as_view(template_name='registration/login.html'), name="login_page"),
    path('admin/', admin.site.urls),
    # django.contrib.auth built-in auth views for login, logout and password config
    path('user/<username>/', include('django.contrib.auth.urls')),
    # django-registration patterns
    path('registration/', include('django_registration.backends.activation.urls')),
    path('registration/', UserRegistrationView.as_view(template_name='django_registration/registration_form.html')),
    # user pages
    path('user/ASes/', login_required(ASesView.as_view(), login_url=reverse_lazy('login_page'))),
]
