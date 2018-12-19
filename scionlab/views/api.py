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
import shutil
import tarfile
import tempfile
from django.views import View
from django.views.generic.detail import SingleObjectMixin
from django.http import (
    HttpResponse,
    HttpResponseBadRequest,
    HttpResponseForbidden,
    HttpResponseNotModified
)

from scionlab.models import Host


def _create_config(host, tarfileobj):
    from scionlab.util import generate

    gen_dir = tempfile.mkdtemp()
    generate.create_gen(host, gen_dir)

    tar = tarfile.open(mode='w:gz', fileobj=tarfileobj)
    tar.add(gen_dir, arcname="gen")
    # TODO(matzf):
    # - VPN config
    # - README, Vagrantfile,
    # - etc.
    tar.close()

    shutil.rmtree(gen_dir)


def _is_empty_config(host):
    return (not host.services.exists()
            and not host.interfaces.exists()
            and not host.vpn_clients.exists()
            and not host.vpn_servers.exists())


class GetHostConfig(SingleObjectMixin, View):
    model = Host

    def get(self, request, *args, **kwargs):
        host = self.get_object()
        if 'secret' not in request.GET \
                or not hmac.compare_digest(request.GET['secret'], host.secret):
            return HttpResponseForbidden()
        if 'version' in request.GET:
            version_str = request.GET['version']
            if not version_str.isnumeric():
                return HttpResponseBadRequest()
            version = int(version_str)
            if version >= host.config_version:
                return HttpResponseNotModified()

        if _is_empty_config(host):
            return HttpResponse(status=204)

        # All good, return generate and return the config
        filename = "%s_v%i.tar.gz" % (host.path_str(), host.config_version)

        # Note: not using FileResponse as streaming is not expected to be beneficial for small file
        # size
        response = HttpResponse()
        response['Content-Disposition'] = 'attachment; filename="%s"' % filename
        response['Content-Type'] = 'application/gzip'
        _create_config(host, response)  # Use the response as file-like object to write the tar
        return response
