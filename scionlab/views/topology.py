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
from django.views.decorators.cache import cache_page, cache_control
from graphviz import Graph

from scionlab.models.core import ISD, Link


@cache_page(1 * 60 * 60)
@cache_control(public=True, max_age=24 * 60 * 60)
def topology_png(request):
    """
    Create graph with infrastructure ASes and links and draw it with dot a png.
    """
    g = _topology_graph()
    imgdata = g.pipe(format='png')

    response = HttpResponse(content_type="image/png")
    response.write(imgdata)
    return response


def _topology_graph():
    g = Graph(engine='dot', graph_attr={'ratio': '0.41'})
    for isd in ISD.objects.iterator():
        g_isd = _make_isd_graph(isd)
        for as_ in isd.ases.filter(owner=None):
            _add_as_node(g_isd, as_)
        g.subgraph(g_isd)
    for link in Link.objects.filter(interfaceA__AS__owner=None, interfaceB__AS__owner=None):
        _add_link(g, link)

    return g


def _make_isd_graph(isd):
    return Graph("cluster_ISD_%i" % isd.isd_id,
                 graph_attr={'color': 'blue',
                             'label': _isd_label(isd),
                             'style': 'rounded'})


def _add_link(g, link):
    as_a = link.interfaceA.AS
    as_b = link.interfaceB.AS
    attrs = None
    if link.type == Link.PEER:
        attrs = {'style': 'dashed',
                 'constraint': 'false'}  # Don't rank peers
    elif link.type == Link.CORE:
        if as_a.isd == as_b.isd:
            attrs = {'constraint': 'false'}  # Don't rank core ASes of one ISD
        elif as_a.isd.isd_id > as_b.isd.isd_id:  # Keep min ISD (i.e. 16) on top
            as_a, as_b = as_b, as_a
    g.edge(str(as_a.pk), str(as_b.pk), _attributes=attrs)


def _add_as_node(g, as_):
    g.node(str(as_.pk),
           _as_label(as_),
           _attributes={'width': '1.33',
                        'fixedsize': 'true',
                        'shape': 'circle',
                        'color': _as_color(as_)})


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
