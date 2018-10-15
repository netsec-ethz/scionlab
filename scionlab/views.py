from django.http import HttpResponse
from django.views import View
from django.contrib.auth.mixins import LoginRequiredMixin

class PlaceholderView(View):
    def get(self, request, *args, **kwargs):
        if request.user.id:
            return HttpResponse('Hello, this is a placeholder. You are logged in as %s.' % request.user.username)
        else:
            return HttpResponse('Hello, this is a placeholder. You are not logged in.')


class PlaceholderUserView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        return HttpResponse('Hello, this is a placeholder view with login required. You are logged in as %s' % request.user.username)


