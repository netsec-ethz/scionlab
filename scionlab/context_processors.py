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


def grafana_url(request):
    """
    Inject the `settings.GRAFANA_URL` into the request context to make
    it available for the navbar in the scionlab/base.html template
    """
    from django.conf import settings
    return {'grafana_url': settings.GRAFANA_URL}


def instance_indicator(request):
    """
    Inject a `instance_indicator` string to indicate dev/testing instances.
    If set, this is rendered into a ribbon in the scionlab/base.html template
    """
    from django.conf import settings
    mode = ''
    if hasattr(settings, 'INSTANCE_NAME'):
        mode = settings.INSTANCE_NAME
    if settings.DEBUG:
        mode += '[debug]'
    return {'instance_indicator': mode}
