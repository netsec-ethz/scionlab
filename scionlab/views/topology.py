# Copyright 2019 ETH Zurich
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

from django.http import HttpResponse
from graphviz import Graph

from scionlab.models.core import ISD, Link


def topology_png(request):
    # TODO(matzf): this queries can/should be optimized...
    # TODO(matzf): this queries can/should be optimized...
    # TODO(matzf): cache this!?
    g = Graph()
    for isd in ISD.objects.iterator():
        g_isd = _make_isd_graph(isd)
        for as_ in isd.ases.filter(owner=None):
            g_isd.node(str(as_.pk), _as_label(as_), _attributes={
                       'shape': 'box', 'color': _as_color(as_)})
        g.subgraph(g_isd)
    for link in Link.objects.iterator():
        as_a = link.interfaceA.AS
        as_b = link.interfaceB.AS
        if as_a.owner or as_b.owner:
            continue
        g.edge(str(as_a.pk), str(as_b.pk))

    imgdata = g.pipe(format='png', renderer='cairo', formatter='cairo')

    response = HttpResponse(content_type="image/png")
    response.write(imgdata)
    return response


def _make_isd_graph(isd):
    return Graph("cluster_ISD_%i" % isd.isd_id,
                 graph_attr={'color': 'blue', 'label': _isd_label(isd), 'style': 'rounded'})


def _isd_label(isd):
    return "ISD %i\n%s" % (isd.isd_id, isd.label)


def _as_label(as_):
    return "%s\n%s" % (as_.as_id, as_.label)


def _as_color(as_):
    if as_.is_core:
        return 'red'
    if hasattr(as_, 'attachment_point_info'):
        return 'darkgreen'
    return 'black'
