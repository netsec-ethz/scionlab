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
import os
import os.path as path

from django.conf import settings

from scionlab.models import AS, Service, Interface
import scionlab.util.local_config_util as generator


def create_gen_AS(AS_id):
    """
    Generate gen folders for all the hosts in the AS
    :param str AS_id: AS identifier string
    :return:
    """
    if not path.exists(settings.GEN_ROOT):
        raise ValueError("GEN_ROOT %s does not exist" % settings.GEN_ROOT)
    as_ = AS.objects.get(as_id=AS_id)
    hosts = as_.hosts.all()

    tp, service_name_map = generate_topology_from_DB(as_)  # topology file

    for host in hosts:
        host_gen_dir = path.join(settings.GEN_ROOT, host.path_str())
        os.makedirs(host_gen_dir, mode=0o755, exist_ok=True)
        _create_gen(host, host_gen_dir, tp, service_name_map)


def create_gen(host, host_gen_dir):
    """
    Generate the gen folder for the :host: in the :directory:
    :param host: Host object
    :param host_gen_dir: output directory string, as an absolute path to an existing directory
    """
    tp, service_name_map = generate_topology_from_DB(host.AS)  # topology file
    _create_gen(host, host_gen_dir, tp, service_name_map)


def _create_gen(host, gen_dir, tp, service_name_map):
    """
    Generate the gen folder for the :host: in the :directory:
    :param host: Host object
    :param gen_dir: output directory string, as an absolute path to an existing directory
    :param tp: topology dict
    :param service_name_map: map from Service object to instance name
    :return:
    """
    if not path.exists(gen_dir):
        raise ValueError("gen_dir %s output directory does not exist" % gen_dir)

    for service in host.services.iterator():
        service_nick = service.type
        if service_nick not in generator.JOB_NAMES.values():
            continue
        service_type = generator.NICKS_TO_TYPES[service_nick]
        instance_name = service_name_map[service]
        generator.generate_instance_dir(service.AS, gen_dir, service_type, tp, instance_name)

    border_router_nick = 'BR'
    border_router_names = tp[generator.NICKS_TO_KEYS[border_router_nick]].keys()
    for border_router in border_router_names:
        service_type = generator.NICKS_TO_TYPES[border_router_nick]
        generator.generate_instance_dir(host.AS, gen_dir, service_type, tp, border_router)

    generator.generate_sciond_config(host.AS, tp, gen_dir)
    generator.write_dispatcher_config(gen_dir)
    generator.write_overlay_config(gen_dir)


def _get_internal_address_type_str(as_):
    host = as_.hosts.first()
    ip = ipaddress.ip_address(host.internal_ip)
    if isinstance(ip, ipaddress.IPv6Address):
        return "IPv6"
    else:
        return "IPv4"


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

    topo_dict[generator.TYPES_TO_KEYS['router']] = {}
    interface_enumerator = Interface.get_interface_router_instance_ids(as_)
    for router_instance_id, interface in interface_enumerator:
        if not interface.link().active:
            continue
        router_instance_name = "%s%s-%s" % ("br", as_.isd_as_path_str(), router_instance_id)
        router_instance_entry = topo_dict['BorderRouters'].setdefault(router_instance_name, {})
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

        link_overlay = interface.link().overlay()

        interface_entry = {
            "ISD_AS": remote_AS_obj.isd_as_str(),
            "LinkTo": str(interface.link_relation()),
            "Bandwidth": interface.link().bandwidth,
            "PublicOverlay": [{
                "Addr": interface.get_public_ip(),
                "OverlayPort": interface.public_port
            }],
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
                "L4Port": interface.bind_port
            }
        router_instance_entry["Interfaces"][interface.interface_id] = interface_entry

    for stype, _ in Service.SERVICE_TYPES:
        if stype not in generator.JOB_NAMES.values():
            continue
        service_key = generator.TYPES_TO_KEYS[generator.NICKS_TO_TYPES[stype]]
        service_enumerator = Service.get_service_type_ids(as_, stype)
        for service_instance_id, service in service_enumerator:
            service_instance_name = "%s%s-%s" % (service.type.lower(), as_.isd_as_path_str(),
                                                 service_instance_id)
            service_name_map[service] = service_instance_name
            if service_key not in topo_dict.keys():
                topo_dict[service_key] = {}
            topo_dict[service_key][service_instance_name] = {
                "Addrs": {
                    address_type: {
                        "Public": {
                            "Addr": service.host.internal_ip,
                            "L4Port": service.port
                        }
                    }
                }
            }
    return topo_dict, service_name_map
