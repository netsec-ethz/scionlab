"""scionlab URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.contrib.auth.decorators import login_required
from django.urls import include, path, reverse_lazy

from scionlab.ases_view import ASesView
from scionlab.registration_view import UserRegistrationView

urlpatterns = [
    path('', auth_views.LoginView.as_view(template_name='scionlab/login.html'), name="login_page"),
    path('admin/', admin.site.urls),
    # django.contrib.auth built-in auth views for login, logout and password config
    path('user/<username>/', include('django.contrib.auth.urls')),
    # django-registration patterns
    path('registration/', include('django_registration.backends.activation.urls')),
    path('registration/', UserRegistrationView.as_view(template_name='django_registration/registration_form.html')),
    # user pages
    path('user/ASes/', login_required(ASesView.as_view(), login_url=reverse_lazy('login_page'))),
]
