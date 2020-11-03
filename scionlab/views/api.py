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
import tarfile
from contextlib import closing

from django.views import View
from django.views.generic.detail import SingleObjectMixin
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.utils import timezone
from django.http import (
    HttpResponse,
    HttpResponseBadRequest,
    HttpResponseGone,
    HttpResponseNotModified
)

from scionlab import config_tar
from scionlab.models.core import Host
from scionlab.models.user_as import  AttachmentPoint
from scionlab.util.http import HttpResponseAttachment, basicauth
from scionlab.util.archive import TarWriter


def _authenticate_host(uid, secret):
    """
    Check the authentication for an api/host request.
    The request is authenticated by the hosts uid and a random secret.
    :param str uid:
    :param str secret:
    :returns: True iff host authenticated successfully with secret
    """
    host_secrets = Host.objects.filter(uid=uid).values_list('secret', flat=True)
    if not host_secrets:  # no such host
        return False
    return hmac.compare_digest(secret, host_secrets[0])


_basicauth_host = basicauth(_authenticate_host, realm='host')


@method_decorator(_basicauth_host, name='dispatch')
class GetHostConfig(SingleObjectMixin, View):
    """
    Get the host configuration as a tar.gz file.
    The request is authenticated via a per-Host secret field, included in the request parameters.
    """
    model = Host
    slug_field = 'uid'
    slug_url_kwarg = 'uid'

    def get(self, request, *args, **kwargs):
        host = self.get_object()

        version = _get_version_param(request.GET)
        if version is _BAD_VERSION:
            return HttpResponseBadRequest()
            
        ap = AttachmentPoint.objects.filter(AS = host.AS).first()
        if ap != None:
            host.update_timestamps()

        if version and version >= host.config_version:
            return HttpResponseNotModified()

        if config_tar.is_empty_config(host):
            return HttpResponse(status=204)

        # All good, return generate and return the config
        return get_host_config_tar_response(host)


def get_host_config_tar_response(host):
    """
    Build the tar.gz attachment response for the GetHostConfig view.

    Note: This is re-used to download host config from the admin interface.

    :returns: HttpResponseAttachment
    """
    filename = '{host}_v{version}.tar.gz'.format(
                    host=host.path_str(),
                    version=host.config_version)

    # Use the response as file-like object to write the tar
    resp = HttpResponseAttachment(filename=filename, content_type='application/gzip')
    with closing(tarfile.open(mode='w:gz', fileobj=resp)) as tar:
        config_tar.generate_host_config_tar(host, TarWriter(tar))
    return resp


@method_decorator(csrf_exempt, name='dispatch')
@method_decorator(_basicauth_host, name='dispatch')
class PostHostDeployedConfigVersion(SingleObjectMixin, View):
    """
    Post a version to set the `config_version_deployed` of a Host object.
    This informs the scionlab webserver that a configuration, previously obtained from
    GetHostConfig, has been successfully installed on a host.
    """
    model = Host
    slug_field = 'uid'
    slug_url_kwarg = 'uid'

    def post(self, request, *args, **kwargs):
        version = _get_version_param(request.POST)
        if version is None or version is _BAD_VERSION:
            return HttpResponseBadRequest()

        host = self.get_object()
        if version > host.config_version or version < host.config_version_deployed:
            return HttpResponseNotModified()

        host.config_version_deployed = version
        host.save()
        return HttpResponse()


_BAD_VERSION = object()


def _get_version_param(request_params):
    """
    Extract the 'version' parameter from the request if available. Returns _BAD_VERSION
    if the version cant be parsed to an int.
    :param dict request_params: request.GET or request.POST
    :returns: int or None or _BAD_VERSION
    """
    version_str = request_params.get('version')
    if version_str:
        if version_str.isnumeric():
            return int(version_str)
        else:
            return _BAD_VERSION
    return None


def gone(request):
    """
    View for removed versions of the API. Responds with 410 Gone.
    """
    return HttpResponseGone()
