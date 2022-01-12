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

from scionlab.defines import SIG_CTRL_PORT, SIG_DATA_PORT
from scionlab.models.core import Service, Link

KEY_BR = 'border_routers'
KEY_CS = 'control_service'
KEY_DS = 'discovery_service'
KEY_CO = 'colibri_service'


TYPES_TO_KEYS = {
    "CS": KEY_CS,
    "CO": KEY_CO,
}

CORE_ATTRIBUTES = [
    "authoritative",
    "core",
    "issuing",
    "voting"
]


class TopologyInfo:
    """
    TopologyInfo creates the router/service-IDs and the topology.json-dict for an AS.

    The routers/services in `self.routers` and `self.services` are
    scionlab.models.core.BorderRouter/Service objects, with instance_id pre-populated.
    """

    def __init__(self, as_, with_sig_dummy_entry=False):
        self.AS = as_
        self._make_topo(with_sig_dummy_entry)

    def _make_topo(self, with_sig_dummy_entry):
        self.routers = _fetch_routers(self.AS)
        self.services = _fetch_services(self.AS)

        # add a dummy SIG entry (for user ASes).
        if with_sig_dummy_entry and not any(s.type == Service.SIG for s in self.services):
            sig = Service(AS=self.AS,
                          host=self.AS.hosts.first(),
                          type=Service.SIG)
            sig.__dict__['instance_id'] = 1
            self.services.append(sig)

        # AS wide entries
        self.topo = {}
        self.topo["isd_as"] = self.AS.isd_as_str()
        self.topo["mtu"] = self.AS.mtu
        self.topo["attributes"] = CORE_ATTRIBUTES if self.AS.is_core else []

        _topo_add_routers(self.topo, self.routers)
        _topo_add_control_services(self.topo, self.services)
        _topo_add_sigs(self.topo, self.services)


def _fetch_routers(as_):
    routers = []
    for id, router in enumerate(as_.border_routers.order_by('pk').iterator(), start=1):
        router.__dict__['instance_id'] = id
        if router.interfaces.active().exists():  # skip empty BRs
            routers.append(router)
    return routers


def _fetch_services(as_):
    services = []
    for stype, _ in Service.SERVICE_TYPES:
        for id, service in enumerate(as_.services.filter(type=stype).order_by('pk'), start=1):
            service.__dict__['instance_id'] = id
            services.append(service)
    return services


def _topo_add_routers(topo_dict, routers):
    """
    Add entries for border routers to topology dict
    """

    topo_dict[KEY_BR] = {}
    for router in routers:
        interfaces = router.interfaces.active()
        if not interfaces:
            continue

        router_entry = _topo_add_router_entry(topo_dict, router)

        for interface in interfaces:
            _topo_add_interface(router_entry, interface)


def _topo_add_router_entry(topo_dict, router):
    return topo_dict[KEY_BR].setdefault(router.instance_name, {
        "internal_addr": _join_host_port(router.host.internal_ip, router.internal_port),
        "interfaces": {},
    })


def _topo_add_interface(router_entry, interface):
    """
    Add an entry for the given interface to the BorderRouter-entry `router_entry` in the topo dict.
    """
    remote_interface = interface.remote_interface()

    interface_entry = {
        "isd_as": remote_interface.AS.isd_as_str(),
        "link_to": _get_linkto_relation(interface),
        "mtu": interface.link().mtu,
        "underlay": {
            "public": _join_host_port(interface.get_public_ip(), interface.public_port),
            "remote": _join_host_port(remote_interface.get_public_ip(),
                                      remote_interface.public_port),
        },
    }
    if interface.get_bind_ip():
        interface_entry["underlay"].update({
            "bind": interface.get_bind_ip(),
        })
    router_entry["interfaces"][interface.interface_id] = interface_entry


def _topo_add_control_services(topo_dict, services):
    control_services = (s for s in services if s.type in Service.CONTROL_SERVICE_TYPES)
    for service in control_services:
        service_instance_entry = {
            "addr": _join_host_port(service.host.internal_ip, service.port),
        }
        service_type_entry = topo_dict.setdefault(TYPES_TO_KEYS[service.type], {})
        service_type_entry[service.instance_name] = service_instance_entry
        # Add discovery service, as copy of control service (because the control service implements
        # the discovery service, but there is still a separate entry in the topology file. Gee...).
        if service.type == Service.CS:
            ds_entry = topo_dict.setdefault(KEY_DS, {})
            instance_name = f"ds-{service.instance_id}"
            ds_entry[instance_name] = service_instance_entry


def _topo_add_sigs(topo_dict, services):
    """
    Add SIG entries to the topology, with default ports.
    Note that we do not actually include any configuration for the SIG (out of scope).
    This is added to reduce the number of files that a scionlab user needs to modify when
    configuring the SIG.
    Note: this entry allows the border router to resolve SIG service address; this changes the
    error behaviour slighly when receiving packets addressed to the SIG without the SIG running.
    """
    sigs = (s for s in services if s.type == Service.SIG)
    for sig in sigs:
        topo_dict["sigs"] = {
            sig.instance_name: {
                "ctrl_addr": _join_host_port(sig.host.internal_ip, SIG_CTRL_PORT),
                "data_addr": _join_host_port(sig.host.internal_ip, SIG_DATA_PORT),
            }
        }


def _join_host_port(host, port):
    """
    Returns joined host:port, wrapping host in brackets if it looks like an IPv6 address
    :param str host:
    :param int port:
        :return str:
    """
    if ':' in host:
        return '[%s]:%s' % (host, port)
    else:
        return '%s:%s' % (host, port)


def _get_linkto_relation(interface):
    link = interface.link()
    if link.type == Link.PROVIDER:
        # By definition, interfaceA is on the parent side
        if link.interfaceA == interface:
            return "CHILD"
        else:
            return "PARENT"
    else:
        return link.type
