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

from scionlab.models import Service, Interface
import scionlab.util.local_config_util as generator


def create_gen(host, host_gen_dir):
    """
    Generate the gen folder for the :host: in the :directory:
    :param host: Host object
    :param host_gen_dir: output directory string, as an absolute path to an existing directory
    """
    archive = generator.FileArchive(host_gen_dir)
    tp, service_name_map = generate_topology_from_DB(host.AS)  # topology file
    _create_gen(host, archive, tp, service_name_map)


def _create_gen(host, archive, tp, service_name_map):
    """
    Generate the gen folder for the :host: in the :directory:
    :param host: Host object
    :param gen_dir: output directory string, as an absolute path to an existing directory
    :param tp: topology dict
    :param service_name_map: map from Service object to instance name
    :return:
    """
    as_ = host.AS
    for service in host.services.exclude(type=Service.ZK).iterator():
        instance_name = service_name_map.get(service)
        if instance_name:
            generator.generate_instance_dir(archive, as_, service.type, tp, instance_name)

    border_router_names = tp[generator.KEY_BR].keys()
    for border_router in border_router_names:
        generator.generate_instance_dir(archive, as_, 'BR', tp, border_router)

    generator.generate_sciond_config(archive, as_, tp)
    generator.write_supervisord_group_config(archive, as_, tp)

    generator.write_dispatcher_config(archive)


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


def generate_topology_from_DB(as_):
    """
    Generate the topology.conf from the database values
    :param AS as_: AS object
    :return: topo_dict: topology dict, service_name_map: map from Service object to instance name
    """
    topo_dict = {}
    service_name_map = {}

    # get overlay type inside AS from IPs used by hosts
    address_type = _get_internal_address_type_str(as_)
    overlay_type = "UDP/" + address_type

    # AS wide entries
    topo_dict["ISD_AS"] = as_.isd_as_str()
    topo_dict["MTU"] = as_.mtu
    topo_dict["Core"] = as_.is_core
    topo_dict["Overlay"] = overlay_type

    topo_dict[generator.KEY_BR] = {}
    interface_enumerator = Interface.get_interface_router_instance_ids(as_)
    for router_instance_id, interface in interface_enumerator:
        if not interface.link().active:
            continue
        router_instance_name = "%s%s-%s" % ("br", as_.isd_as_path_str(), router_instance_id)
        router_instance_entry = topo_dict[generator.KEY_BR].setdefault(router_instance_name, {})
        if router_instance_entry == {}:
            router_instance_entry.update({
                "InternalAddrs": {
                    address_type: {
                        "PublicOverlay": {
                            "Addr": interface.host.internal_ip,
                            "OverlayPort": interface.internal_port  # FIXME(matzf)
                        }
                    }
                },
                "CtrlAddr": {
                    address_type: {
                        "Public": {
                            "Addr": interface.host.internal_ip,
                            "L4Port": interface.internal_port + 1000  # FIXME(matzf)
                        }
                    }
                },
                "Interfaces": {}
            })

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
            interface_entry["BindOverlay"] = {
                "Addr": interface.get_bind_ip(),
                "OverlayPort": interface.bind_port or interface.public_port
            }
        router_instance_entry["Interfaces"][interface.interface_id] = interface_entry

    for stype in [Service.BS, Service.CS, Service.PS]:
        service_enumerator = Service.get_service_type_ids(as_, stype)
        for service_instance_id, service in service_enumerator:
            service_instance_name = "%s%s-%s" % (service.type.lower(), as_.isd_as_path_str(),
                                                 service_instance_id)
            service_name_map[service] = service_instance_name
            service_dict = topo_dict.setdefault(generator.TYPES_TO_KEYS[stype], {})
            service_dict[service_instance_name] = {
                "Addrs": {
                    address_type: {
                        "Public": {
                            "Addr": service.host.internal_ip,
                            "L4Port": service.port
                        }
                    }
                }
            }

    for service_instance_id, service in Service.get_service_type_ids(as_, Service.ZK):
        zookeeper_dict = topo_dict.setdefault(generator.KEY_ZK, {})
        zookeeper_dict[str(service_instance_id)] = {
            "Addr": service.host.internal_ip,
            "L4Port": service.port
        }

    return topo_dict, service_name_map
