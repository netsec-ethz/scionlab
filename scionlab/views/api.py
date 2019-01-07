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

import hmac
from django.views import View
from django.views.generic.detail import SingleObjectMixin
from django.http import (
    HttpResponse,
    HttpResponseBadRequest,
    HttpResponseForbidden,
    HttpResponseNotModified
)

from scionlab.models import Host
from scionlab.util.http import HttpResponseAttachment
from scionlab.util import config_tar


class GetHostConfig(SingleObjectMixin, View):
    model = Host

    def get(self, request, *args, **kwargs):
        host = self.get_object()
        err = _check_host_request(host, request.GET)
        if err:
            return err

        if 'version' in request.GET:
            if int(request.GET['version']) >= host.config_version:
                return HttpResponseNotModified()

        if config_tar.is_empty_config(host):
            return HttpResponse(status=204)

        # All good, return generate and return the config
        # Use the response as file-like object to write the tar
        filename = '{host}_v{version}.tar.gz'.format(
                        host=host.path_str(),
                        version=host.config_version)
        resp = HttpResponseAttachment(filename=filename, content_type='application/gzip')
        config_tar.generate_host_config_tar(host, resp)
        return resp


class PostHostConfigVersion(SingleObjectMixin, View):
    model = Host

    def post(self, request, *args, **kwargs):
        host = self.get_object()
        err = _check_host_request(host, request.GET)
        if err:
            return err

        if 'version' not in request.POST:
            return HttpResponseBadRequest()
        version = int(request.POST['version'])
        if version > host.config_version \
                or version < host.deployed_config_version:
            return HttpResponseNotModified()

        host.deployed_config_version = version
        host.save()


def _check_host_request(host, request_params):
    if 'secret' not in request_params \
            or not hmac.compare_digest(request_params['secret'], host.secret):
        return HttpResponseForbidden()
    if 'version' in request_params and not request_params['version'].isnumeric():
        return HttpResponseBadRequest()
    return None
