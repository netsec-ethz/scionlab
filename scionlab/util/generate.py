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

import ipaddress

from scionlab.models import Service
import scionlab.util.local_config_util as generator


SERVICE_TYPES_CONTROL_PLANE = [Service.BS, Service.CS, Service.PS]


def create_gen(host, archive):
    """
    Generate the gen/ folder for the :host: in the given archive-writer
    :param host: Host object
    :param scionlab.util.archive.BaseArchiveWriter archive: output archive-writer
    """
    topo_dict, router_names, service_names = _generate_topology_from_DB(host.AS)  # topology file
    _create_gen(host, archive, topo_dict, router_names, service_names)


def _create_gen(host, archive, topo_dict, router_names, service_names):
    """
    Generate the gen folder for the :host: in the :directory:
    :param host: Host object
    :param gen_dir: output directory string, as an absolute path to an existing directory
    :param tp: topology dict
    :param service_name_map: map from Service object to instance name
    :return:
    """

    as_ = host.AS

    processes = []

    for router in host.border_routers.iterator():
        instance_name = router_names[router]
        generator.generate_instance_dir(archive, as_, 'BR', topo_dict, instance_name)
        processes.append(instance_name)

    for service in host.services.filter(type__in=SERVICE_TYPES_CONTROL_PLANE):
        instance_name = service_names[service]
        generator.generate_instance_dir(archive, as_, service.type, topo_dict, instance_name)
        processes.append(instance_name)

    sciond_name = "sd%s" % as_.isd_as_path_str()
    generator.generate_sciond_config(archive, as_, topo_dict, sciond_name)
    processes.append(sciond_name)

    generator.write_supervisord_group_config(archive, as_, processes)

    generator.write_dispatcher_config(archive)


def _generate_topology_from_DB(as_):
    """
    Generate the topology.conf from the database values
    :param AS as_: AS object
    :return: topo_dict: topology dict, service_name_map: map from Service object to instance name
    """
    topo_dict = {}

    # get overlay type inside AS from IPs used by hosts
    address_type = _get_internal_address_type_str(as_)
    overlay_type = "UDP/" + address_type

    # AS wide entries
    topo_dict["ISD_AS"] = as_.isd_as_str()
    topo_dict["MTU"] = as_.mtu
    topo_dict["Core"] = as_.is_core
    topo_dict["Overlay"] = overlay_type

    router_names = _get_router_names(as_)
    _topo_add_routers(topo_dict, router_names, address_type)

    service_names = _get_service_names(as_)
    _topo_add_control_services(topo_dict, service_names, address_type)

    _topo_add_zookeeper(topo_dict, as_)

    return topo_dict, router_names, service_names


def _topo_add_routers(topo_dict, routers, as_address_type):
    """
    Add entries for border routers to topology dict
    """

    topo_dict[generator.KEY_BR] = {}
    for router, router_name in routers.items():
        interfaces = router.interfaces.active()
        if not interfaces:
            continue

        router_entry = _topo_add_router_entry(topo_dict, router, router_name, as_address_type)

        for interface in interfaces:
            remote_if_obj = interface.remote_interface()
            remote_AS_obj = interface.remote_as()

            link_overlay = _get_link_overlay_type_str(interface)

            interface_entry = {
                "ISD_AS": remote_AS_obj.isd_as_str(),
                "LinkTo": str(interface.link_relation()),
                "Bandwidth": interface.link().bandwidth,
                "PublicOverlay": {
                    "Addr": interface.get_public_ip(),
                    "OverlayPort": interface.public_port
                },
                "MTU": interface.link().bandwidth,
                "RemoteOverlay": {
                    "Addr": remote_if_obj.get_public_ip(),
                    "OverlayPort": remote_if_obj.public_port
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


def _topo_add_router_entry(topo_dict, router, router_name, as_address_type):
    return topo_dict[generator.KEY_BR].setdefault(router_name, {
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


def _topo_add_control_services(topo_dict, service_names, as_address_type):
    for service, service_name in service_names.items():
        service_type_entry = topo_dict.setdefault(generator.TYPES_TO_KEYS[service.type], {})
        service_type_entry[service_name] = {
            "Addrs": {
                as_address_type: {
                    "Public": {
                        "Addr": service.host.internal_ip,
                        "L4Port": service.port
                    }
                }
            }
        }


def _topo_add_zookeeper(topo_dict, as_):
    for id, service in enumerate(as_.services.filter(type=Service.ZK), start=1):
        zookeeper_dict = topo_dict.setdefault(generator.KEY_ZK, {})
        zookeeper_dict[str(id)] = {
            "Addr": service.host.internal_ip,
            "L4Port": service.port
        }


def _get_internal_address_type_str(as_):
    host = as_.hosts.first()
    ip = ipaddress.ip_address(host.internal_ip)
    if isinstance(ip, ipaddress.IPv6Address):
        return "IPv6"
    else:
        return "IPv4"


def _get_link_overlay_type_str(interface):
    ip = ipaddress.ip_address(interface.get_public_ip())
    if isinstance(ip, ipaddress.IPv6Address):
        return "UDP/IPv6"
    else:
        return "UDP/IPv4"


def _get_router_names(as_):
    router_names = {}
    for id, router in enumerate(as_.border_routers.iterator(), start=1):
        router_name = "br%s-%s" % (as_.isd_as_path_str(), id)
        router_names[router] = router_name
    return router_names


def _get_service_names(as_):
    service_names = {}
    for stype in SERVICE_TYPES_CONTROL_PLANE:
        for id, service in enumerate(as_.services.filter(type=stype), start=1):
            service_name = "%s%s-%s" % (service.type.lower(), as_.isd_as_path_str(), id)
            service_names[service] = service_name
    return service_names
