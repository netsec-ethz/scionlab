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

from django.http import HttpResponse, JsonResponse
from django.views.decorators.cache import cache_page, cache_control
from graphviz import Graph
from textwrap import fill

from scionlab.models.core import ISD, Link, BorderRouter


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
    g = Graph(engine='dot', graph_attr={'ratio': '0.41', 'pad': '0.7 ', 'newrank': 'false',
                                        'splines': 'compound'})

    for isd in ISD.objects.iterator():
        g_isd = _make_isd_graph(isd)

        # hard-coding backbone ISDs to be at the top
        if isd.isd_id in [16, 26]:
            g_isd.attr(rank='source')

        # putting core ASes into a subgraph, laid out at the top
        with g_isd.subgraph() as s:
            s.attr(rank='min')
            for as_ in isd.ases.filter(owner=None, is_core=True):
                _add_as_node(s, as_)

        # putting non-core ASes into a subgraph, without rank
        with g_isd.subgraph() as s:
            s.attr(rank='none')
            for as_ in isd.ases.filter(owner=None, is_core=False):
                _add_as_node(s, as_)

        g.subgraph(g_isd)

    for link in Link.objects.filter(interfaceA__AS__owner=None, interfaceB__AS__owner=None):
        _add_link(g, link)

    return g


def _make_isd_graph(isd):
    return Graph("cluster_ISD_%i" % isd.isd_id,
                 graph_attr={'color': 'gray33',
                             'label': _isd_label(isd),
                             'fontname': 'roboto',
                             'fontsize': '16pt',
                             'penwidth': '1.8pt',
                             'style': 'rounded,filled',
                             'fillcolor': 'gray93'})


def _add_link(g, link):
    as_a = link.interfaceA.AS
    as_b = link.interfaceB.AS
    attrs = None
    if link.type == Link.PEER:
        attrs = {'style': 'dashed',
                 'constraint': 'false'}  # Don't rank peers
    g.edge(str(as_a.pk), str(as_b.pk), _attributes=attrs)


def _add_as_node(g, as_):
    g.node(str(as_.pk),
           _as_label(as_),
           _attributes={'width': '1.33',
                        'fixedsize': 'true',
                        'shape': 'circle',
                        'penwidth': '1.5pt',
                        'color': _as_color(as_),
                        'style': 'filled',
                        'fontname': 'roboto',
                        'fillcolor': _as_fill_color(as_)})


def _isd_label(isd):
    return "ISD %i\n%s" % (isd.isd_id, isd.label)


def _as_label(as_):
    return "%s\n%s" % (as_.as_id, fill(as_.label, 10))


def _as_color(as_):
    if as_.is_core:
        return 'orangered'
    if hasattr(as_, 'attachment_point_info'):
        return 'darkgreen'
    return 'black'


def _as_fill_color(as_):
    if as_.is_core:
        return 'seashell1'
    if hasattr(as_, 'attachment_point_info'):
        return 'darkseagreen1'
    return 'gray99'


@cache_page(5)
@cache_control(public=True, max_age=5)
def topology_json(request):
    """
    Create JSON with information about infrastructure ASes.
    """

    def json_service(s):
        service_type = 'BR' if isinstance(s, BorderRouter) else s.type
        return {
            'type': service_type,
            'metrics_port': s.metrics_port,
            'ssh_host': s.host.ssh_host,
        }

    def json_as(as_):
        services = as_.services.all()
        # we want only non-empty BRs
        brs = [r for r in as_.border_routers.all() if r.interfaces.active().exists()]
        return {
            'as': as_.as_id,
            'label': as_.label,
            'is_core': as_.is_core,
            'services': [json_service(s) for s in list(services)+list(brs)],
        }

    def json_isd(isd):
        return {
            'isd': isd.isd_id,
            'label':  isd.label,
            # we want only infrastructure ASes
            'ases':   [json_as(as_) for as_ in isd.ases.filter(owner=None)],
        }

    data = {'isds': [json_isd(isd) for isd in ISD.objects.iterator()]}
    return JsonResponse(data)
