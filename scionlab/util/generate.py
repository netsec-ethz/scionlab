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

import base64
import ipaddress
import os
import os.path as path
import tarfile

from lib.packet.scion_addr import ISD_AS
from nacl.signing import SigningKey
from topology.generator import TopoID
from django.conf import settings

from scionlab.models import AS, Host, Interface, ISD, Service
import scionlab.util.local_config_util as generator


def create_gen_AS(AS_id):
    """
    Generate gen folders for all the hosts in the AS
    :param str AS_id: AS identifier string
    :return:
    """
    if not os.path.exists(settings.GEN_ROOT):
        return
    as_ = AS.objects.get(as_id=AS_id)
    hosts = as_.hosts.all()

    tp, host_service_id_map = generate_topology_from_DB(as_)  # topology file

    for host in hosts:
        host_gen_dir = path.join(settings.GEN_ROOT, host.path_str())
        os.makedirs(host_gen_dir, mode=0o755, exist_ok=True)
        create_gen(host, host_gen_dir, tp, host_service_id_map)
    return


def create_gen(host, host_gen_dir, tp, host_service_id_map):
    """
    Generate the gen folder for the :host: in the :directory:
    :param host: Host object
    :param host_gen_dir: output directory string, as an absolute path to an existing directory
    :param tp: topology dict
    :param host_service_id_map: map from (Host, Service.type) to instance id
    :return:
    """
    if not os.path.exists(host_gen_dir):
        return

    interfaces = Interface.objects.filter(host=host)
    for interface in interfaces:
        ia = ISD_AS(interface.AS.isd_as_str())
        service_nick = 'BR'

        #instance_id = get_router_instance_id(AS.objects.get(as_id=ia.as_str()), interface.host)
        instance_name = host_service_id_map[(interface.host, service_nick)]
        service_type = generator.NICKS_TO_TYPES[service_nick]
        generate_instance_dir(ia, host_gen_dir, service_type, tp, instance_name)

    services = Service.objects.filter(host=host)
    for service in services:
        ISD_id = service.AS.isd.id
        AS_id = service.AS.as_id
        ia = ISD_AS("%s-%s" % (ISD_id, AS_id))
        service_nick = service.type
        if service_nick not in generator.JOB_NAMES.values():
            continue

        #instance_id = get_service_instance_id(AS.objects.get(as_id=ia.as_str()),
        #                                      service.host, service_nick)
        service_type = generator.NICKS_TO_TYPES[service_nick]
        instance_name = host_service_id_map[(service.host, service_nick)]
        generate_instance_dir(ia, host_gen_dir, service_type, tp, instance_name)

    tar_gen(host_gen_dir, path.join(host_gen_dir, "%s.%s" % (host_gen_dir.split("/")[-1], "tgz")))
    return


def get_router_instance_id(as_, host):
    """
    Get the service instance identifier for a router
    :param AS as_: AS object
    :param Host host: host on which the router instance runs
    :return:
    """
    # Get instance id from DB order:
    AS_interfaces = [(e.id, e.host.id) for e in
                     Interface.objects.filter(AS=as_)]
    AS_interfaces.sort()
    instance_id = 1
    for instance in AS_interfaces:
        if instance[1] == host.id:
            break
        instance_id += 1
    return instance_id


def get_service_instance_id(as_, host, service_type):
    """
    Get the service instance identifier for a service
    :param str AS_id: AS identifier
    :param Host host: host on which the service instance runs
    :param str service_type: service type
    :return:
    """
    # Get instance id from DB order:
    AS_service_instances = [(e.id, e.host.id) for e in
                            Service.objects.filter(type=service_type,
                                                   AS=as_)]
    AS_service_instances.sort()
    instance_id = 1
    for instance in AS_service_instances:
        if instance[1] == host.id:
            break
        instance_id += 1
    return instance_id


def generate_instance_dir(ia, directory, stype, tp, instance_name):
    """
    Generate the service instance directory for the gen folder
    :param ISD_AS ia: ISD_AS in which the instance runs
    :param str directory: base directory of the gen folder
    :param str stype: service type
    :param tp: topology dict
    :param str instance_name: instance name
    :return:
    """
    topo_id = TopoID(str(ia))
    as_base_dir = topo_id.base_dir(directory)
    os.makedirs(as_base_dir, mode=0o755, exist_ok=True)

    instance_path = path.join(as_base_dir, instance_name)
    os.makedirs(instance_path, mode=0o755, exist_ok=True)

    # Generate service configuration to directory, with certs and keys
    as_ = AS.objects.get(as_id=ia.as_str())
    as_crypto_obj = AScrypto.from_AS(as_)
    generator.write_certs_trc_keys(ia, as_crypto_obj, instance_path)
    generator.write_as_conf_and_path_policy(ia, as_crypto_obj, instance_path)
    executable_name = generator.TYPES_TO_EXECUTABLES[stype]
    type_key = generator.TYPES_TO_KEYS[stype]

    config = generator.prep_supervisord_conf(tp[type_key][instance_name], executable_name,
                                             stype, str(instance_name), ia)
    generator.write_supervisord_config(config, instance_path)
    generator.write_topology_file(tp, stype, instance_path)
    generator.write_zlog_file(stype, instance_name, instance_path)


def generate_topology_from_DB(as_):
    """
    Generate the topology.conf from the database values
    :param AS as_: AS object
    :return: topo_dict: topology dict, host_service_id_map: map from (Host, stype) to instance id
    """
    interfaces = as_.interfaces.active()
    services = as_.services.all()
    topo_dict = {}
    host_service_id_map = {}

    # AS wide entries
    topo_dict["ISD_AS"] = str(ISD_AS("%s-%s" % (as_.isd_id, as_.as_id)))
    topo_dict["MTU"] = as_.mtu
    topo_dict["Core"] = as_.is_core

    # get overlay type inside AS from IPs used by hosts
    AS_internal_overlay = as_.AS_internal_overlay()
    topo_dict["Overlay"] = AS_internal_overlay

    topo_dict[generator.TYPES_TO_KEYS['router']] = {}
    for interface in interfaces:
        router_instance_id = get_router_instance_id(as_,
                                                    interface.host)
        router_instance_name = "%s%s-%s" % ("br", as_.isd_as_path_str(),router_instance_id)
        host_service_id_map[(interface.host, "BR")] = router_instance_name
        if router_instance_name not in topo_dict[generator.TYPES_TO_KEYS['router']].keys():
            topo_dict[generator.TYPES_TO_KEYS['router']][router_instance_name] = {}
        router_instance_entry = topo_dict[generator.TYPES_TO_KEYS['router']][router_instance_name]
        if "Interfaces" not in router_instance_entry.keys():
            router_instance_entry = {"Interfaces": {}}
        remote_if_obj = interface.remote_interface()
        remote_AS_obj = interface.remote_as()

        link_overlay = "UDP/IPv6"  # FIXME(FR4NK-W): add value to the model and get it from there
        if interface.public_ip and \
                remote_if_obj.public_ip and \
                isinstance(ipaddress.ip_address(interface.public_ip), ipaddress.IPv4Address) and \
                isinstance(ipaddress.ip_address(remote_if_obj.public_ip), ipaddress.IPv4Address):
            link_overlay = "UDP/IPv4"

        router_instance_entry["Interfaces"][interface.interface_id] = {
            "InternalAddrIdx": 0,
            "ISD_AS": str(ISD_AS("%s-%s" % (remote_AS_obj.isd_id, remote_AS_obj.as_id))),
            "LinkTo": str(interface.link_relation()),
            "Bandwidth": interface.link().bandwidth,
            "Public": [{
                "L4Port": interface.public_port,
                "Addr": interface.public_ip
            }],
            "MTU": interface.link().bandwidth,
            "Remote": {
                "L4Port": remote_if_obj.public_port,
                "Addr": remote_if_obj.public_ip
            },
            "Overlay": link_overlay
        }
        if interface.bind_ip:
            router_instance_entry["Interfaces"][interface.interface_id]["Bind"] = {
                "L4Port": interface.bind_port,
                "Addr": interface.bind_ip
            }

    for service in services:
        if service.type not in generator.JOB_NAMES.values():
            continue
        service_key = generator.TYPES_TO_KEYS[generator.NICKS_TO_TYPES[service.type]]
        service_instance_id = get_service_instance_id(as_, service.host, service.type)
        service_instance_name = "%s%s-%s" % (service.type.lower(), as_.isd_as_path_str(),
                                             service_instance_id)
        host_service_id_map[(service.host, service.type)] = service_instance_name
        if service_key not in topo_dict.keys():
            topo_dict[service_key] = {}
        topo_dict[service_key][service_instance_name] = {
            "Public": [{"L4Port": service.port,
                        "Addr": service.host.ip}]
        }
    return topo_dict, host_service_id_map


class AScrypto:
    """
    Class representing an AS with the crypto information required to generate the gen folder
    """
    certificate = None
    trc = None
    keys = {}
    core_keys = {}

    @classmethod
    def from_AS(cls, as_):
        """
        Build AS_crypto from a model.AS object
        :param AS as_: AS object of the target AS
        :return:
        """
        inst = cls()
        inst.certificate = str(as_.certificates)
        inst.trc = str(ISD.objects.get(id=as_.isd.id).trc)
        inst.keys = {
            'sig_key': as_.sig_priv_key,
            'sig_key_raw': as_.enc_priv_key,

            'enc_key': as_.master_as_key,
            'master_as_key': as_.master_as_key,
        }
        if as_.is_core:
            inst.core_keys = {
                'core_sig_key': as_.core_sig_priv_key,
                'online_key': as_.core_online_priv_key,
                'offline_key': as_.core_offline_priv_key,

                'core_sig_key_raw': generate_raw_key(as_.core_sig_priv_key),
                'online_key_raw': generate_raw_key(as_.core_online_priv_key),
                'offline_key_raw': generate_raw_key(as_.core_offline_priv_key),
            }
        return inst


def generate_raw_key(key_seed):
    """
    Generate raw key from input seed
    :param str key_seed: base64 encoded key seed
    :return: str base64 encoded raw key derived from the seed
    """
    # FIXME(FR4NK-W): do not access protected member _signing_key
    return base64.b64encode(SigningKey(base64.b64decode(key_seed))._signing_key).decode()


def tar_gen(directory, output):
    """
    Create gzipped tar file at :output: with the content of :directory:
    :param str directory: input directory
    :param str output: output file
    :return:
    """
    tar = tarfile.open(output, 'w:gz')
    tar.add(directory, arcname="gen")
    tar.close()
    return
