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

from scionlab.models.core import Service, Link
import ipaddress

KEY_BR = 'BorderRouters'
KEY_BS = 'BeaconService'
KEY_CS = 'CertificateService'
KEY_PS = 'PathService'
KEY_DI = 'Discovery'

TYPES_TO_KEYS = {
    "BR": KEY_BR,
    "BS": KEY_BS,
    "CS": KEY_CS,
    "PS": KEY_PS,
}


class TopologyInfo:
    """
    TopologyInfo creates the router/service-IDs and the topology.json-dict for an AS.

    The routers/services in `self.routers` and `self.services` are
    scionlab.models.core.BorderRouter/Service objects, marked up with the additional attributes
        `instance_name`
        `instance_id`

    """

    def __init__(self, as_):
        self.AS = as_
        self._make_topo()

    def _make_topo(self):
        self.routers = _fetch_routers(self.AS)
        self.services = _fetch_services(self.AS)

        # get overlay type inside AS from IPs used by hosts
        address_type = _get_ip_type_str(self.AS.hosts.first().internal_ip)
        overlay_type = "UDP/" + address_type

        # AS wide entries
        self.topo = {}
        self.topo["ISD_AS"] = self.AS.isd_as_str()
        self.topo["MTU"] = self.AS.mtu
        self.topo["Core"] = self.AS.is_core
        self.topo["Overlay"] = overlay_type

        _topo_add_routers(self.topo, self.routers, address_type)
        _topo_add_control_services(self.topo, self.services, address_type)
        self.topo[KEY_DI] = {}


def _fetch_routers(as_):
    routers = []
    for id, router in enumerate(as_.border_routers.order_by('pk').iterator(), start=1):
        if router.interfaces.active().exists():  # skip empty BRs
            router.instance_id = id
            router.instance_name = "br%s-%s" % (as_.isd_as_path_str(), id)
            routers.append(router)
    return routers


def _fetch_services(as_):
    services = []
    for stype, _ in [x for x in Service.SERVICE_TYPES if x[0] not in Service.STATIC_SERVICE_TYPES]:
        for id, service in enumerate(as_.services.filter(type=stype).order_by('pk'), start=1):
            service.instance_id = id
            service.instance_name = "%s%s-%s" % (stype.lower(), as_.isd_as_path_str(), id)
            services.append(service)
    return services


def _topo_add_routers(topo_dict, routers, as_address_type):
    """
    Add entries for border routers to topology dict
    """

    topo_dict[KEY_BR] = {}
    for router in routers:
        interfaces = router.interfaces.active()
        if not interfaces:
            continue

        router_entry = _topo_add_router_entry(topo_dict, router, as_address_type)

        for interface in interfaces:
            _topo_add_interface(router_entry, interface)


def _topo_add_router_entry(topo_dict, router, as_address_type):
    return topo_dict[KEY_BR].setdefault(router.instance_name, {
        "InternalAddrs": {
            as_address_type: {
                "PublicOverlay": {
                    "Addr": router.host.internal_ip,
                    "OverlayPort": router.internal_port
                }
            }
        },
        "CtrlAddr": {
            as_address_type: {
                "Public": {
                    "Addr": router.host.internal_ip,
                    "L4Port": router.control_port
                }
            }
        },
        "Interfaces": {}
    })


def _topo_add_interface(router_entry, interface):
    """
    Add an entry for the given interface to the BorderRouter-entry `router_entry` in the topo dict.
    """
    remote_interface = interface.remote_interface()

    address_type = _get_ip_type_str(interface.get_public_ip())
    link_overlay = "UDP/" + address_type

    interface_entry = {
        "ISD_AS": remote_interface.AS.isd_as_str(),
        "LinkTo": _get_linkto_relation(interface),
        "Bandwidth": interface.link().bandwidth,
        "PublicOverlay": {
            "Addr": interface.get_public_ip(),
            "OverlayPort": interface.public_port
        },
        "MTU": interface.link().mtu,
        "RemoteOverlay": {
            "Addr": remote_interface.get_public_ip(),
            "OverlayPort": remote_interface.public_port
        },
        "Overlay": link_overlay
    }
    if interface.get_bind_ip():
        interface_entry.update({
            "BindOverlay": {
                "Addr": interface.get_bind_ip(),
                "OverlayPort": interface.bind_port or interface.public_port
            }
        })
    router_entry["Interfaces"][interface.interface_id] = interface_entry


def _topo_add_control_services(topo_dict, services, as_address_type):
    control_services = (s for s in services if s.type in TYPES_TO_KEYS)  # ignore other services
    for service in control_services:
        service_type_entry = topo_dict.setdefault(TYPES_TO_KEYS[service.type], {})
        addrs = {
            "Public": {
                "Addr": service.host.internal_ip,
                "L4Port": service.port()
            }
        }
        # XXX(matzf): use optional bind_ip, but only if the internal_ip matches public_ip;
        #   the reason is that the bind_ip is only really defined for the public_ip. If the
        #   internal_ip is different from public_ip, e.g. if it's 127.0.0.1, then it doesn't make
        #   sense to use bind_ip.
        #   We'd need an internal_bind_ip to represent this correctly -- luckily we don't seem to
        #   need this.
        if service.host.bind_ip and service.host.internal_ip == service.host.public_ip:
            addrs["Bind"] = {
                "Addr": service.host.bind_ip,
                "L4Port": service.port(),
            }
        service_type_entry[service.instance_name] = {
            "Addrs": {
                as_address_type: addrs
            }
        }


def _get_ip_type_str(ip):
    """
    Return the type of the given IP address as string to be used in the scion topology
    files; returns either "IPv4" or "IPv6"
    :param str ip: IP address
    :return str: "IPv4" or "IPv6"
    """
    ip = ipaddress.ip_address(ip)
    if isinstance(ip, ipaddress.IPv6Address):
        return "IPv6"
    else:
        return "IPv4"


def _get_link_overlay_type_str(interface):
    ip_type = _get_ip_type_str(interface.get_public_ip())
    return "UDP/" + ip_type


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
