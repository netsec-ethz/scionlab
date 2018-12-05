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

import tempfile
import tarfile
import shutil
from django.views import View
from django.views.generic.detail import SingleObjectMixin
from django.http import (
    FileResponse,
    HttpResponseBadRequest,
    HttpResponseForbidden,
    HttpResponseNotModified
)

from scionlab.models import Host
from scionlab.util import generate


def _create_config(host, tarfilename):
    gen_dir = tempfile.mkdtemp()

    # XXX: should be the entry point of generate. And no tar!
    tp, service_name_map = generate.generate_topology_from_DB(host.AS)
    generate.create_gen(host, gen_dir, tp, service_name_map)

    tar = tarfile.open(tarfilename, 'w:gz')
    tar.add(gen_dir, arcname="gen")
    # TODO(matzf):
    # - VPN config
    # - README, Vagrantfile,
    # - etc.
    tar.close()

    shutil.rmtree(gen_dir)


class GetHostConfig(SingleObjectMixin, View):
    model = Host

    def get(self, request, *args, **kwargs):
        host = self.get_object()
        if 'secret' not in request.GET or request.GET['secret'] != host.secret:
            return HttpResponseForbidden()
        if 'version' in request.GET:
            version_str = request.GET['version']
            if not version_str.isnumeric():
                return HttpResponseBadRequest()
            version = int(version_str)
            if version >= host.config_version:
                return HttpResponseNotModified()

        # All good, return generate and return the config
        # TODO(matzf): check this HEAD handling works
        tarball = ()
        if request.method != 'HEAD':
            tarball = tempfile.NamedTemporaryFile(suffix='.tar.gz')
            _create_config(host, tarball.name)

        filename = "%s_v%i.tar.gz" % (host.path_str(), host.config_version)
        return FileResponse(tarball, as_attachment=True, filename=filename)
