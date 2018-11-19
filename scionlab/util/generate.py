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
from django.core.validators import EmailValidator

from scionlab.models import AS, Host, Interface, ISD, Service
from scionlab.settings.common import GEN_ROOT
import scionlab.util.local_config_util as generator


def create_gen_AS(AS_id):
    """
    Generate gen folders for all the hosts in the AS
    :param str AS_id: AS identifier string
    :return:
    """
    if not os.path.exists(GEN_ROOT):
        return
    as_obj = AS.objects.filter(as_id=AS_id).first()
    hosts = Host.objects.filter(AS_id=as_obj)

    email_validator = EmailValidator()
    for host in hosts:
        try:
            user_email = as_obj.owner.email
            email_validator(user_email)
            host_ip = ipaddress.ip_address(host.ip)
            host_id = "%s__%s" % (user_email, str(host_ip))
        except:
            raise ValueError("cannot build valid host id from user email and host IP address.")
        host_gen_dir = path.join(GEN_ROOT, host_id)
        os.makedirs(host_gen_dir, mode=0o755, exist_ok=True)
        create_gen(host, host_gen_dir)
    return


def create_gen(host, host_gen_dir):
    """
    Generate the gen folder for the :host: in the :directory:
    :param host: Host object
    :param host_gen_dir: output directory string, as an absolute path to an existing directory
    :return:
    """
    if not os.path.exists(host_gen_dir):
        return

    interfaces = Interface.objects.filter(host=host)
    for interface in interfaces:
        ISD_id = interface.AS.isd.id
        AS_id = interface.AS.as_id
        ia = ISD_AS("%s-%s" % (ISD_id, AS_id))
        stype = 'router'

        instance_id = get_router_instance_id(AS_id, interface.host)
        generate_instance_dir(ia, host_gen_dir, stype, instance_id)

    services = Service.objects.filter(host=host)
    for service in services:
        ISD_id = service.AS.isd.id
        AS_id = service.AS.as_id
        ia = ISD_AS("%s-%s" % (ISD_id, AS_id))
        service_type = service.type
        if service_type not in generator.JOB_NAMES.values():
            continue

        instance_id = get_service_instance_id(AS_id, service.host, service_type)
        service_mapping = {}  # FIXME(FR4NK-W): fix model to following naming pattern
        # as used in generator and topo file
        for entry in Service.SERVICE_TYPES:
            service_mapping[entry[0]] = entry[1].lower().replace(" ", "_")
        stype = service_mapping[service_type]
        generate_instance_dir(ia, host_gen_dir, stype, instance_id)

    tar_gen(host_gen_dir, path.join(host_gen_dir, "%s.%s" % (host_gen_dir.split("/")[-1], "tgz")))
    return


def get_router_instance_id(AS_id, host):
    """
    Get the service instance identifier for a router
    :param str AS_id: AS identifier
    :param Host host: host on which the router instance runs
    :return:
    """
    # Get instance id from DB order:
    AS_interfaces = [(e.id, e.host.id) for e in
                     Interface.objects.filter(AS_id=AS.objects.filter(as_id=AS_id).first())]
    AS_interfaces.sort()
    instance_id = 1
    for instance in AS_interfaces:
        if instance[1] == host.id:
            break
        instance_id += 1
    return instance_id


def get_service_instance_id(AS_id, host, service_type):
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
                                                   AS=AS.objects.filter(as_id=AS_id).first())]
    AS_service_instances.sort()
    instance_id = 1
    for instance in AS_service_instances:
        if instance[1] == host.id:
            break
        instance_id += 1
    return instance_id


def generate_instance_dir(ia, directory, stype, instance_id):
    """
    Generate the service instance directory for the gen folder
    :param ISD_AS ia: ISD_AS in which the instance runs
    :param str directory: base directory of the gen folder
    :param str stype: service type
    :param str instance_id: instance identifier
    :return:
    """
    topo_id = TopoID(str(ia))
    as_base_dir = topo_id.base_dir(directory)
    os.makedirs(as_base_dir, mode=0o755, exist_ok=True)

    nick = generator.JOB_NAMES[generator.TYPES_TO_KEYS[stype]].lower()
    elem_id = "%s%s-%s" % (nick, ia.file_fmt(), instance_id)
    instance_path = path.join(as_base_dir, elem_id)
    os.makedirs(instance_path, mode=0o755, exist_ok=True)

    # Generate service configuration to directory, with certs and keys
    as_crypto_obj = AScrypto.from_AS(isd=ia.isd_str(), as_id=ia.as_str())
    generator.write_certs_trc_keys(ia, as_crypto_obj, instance_path)
    generator.write_as_conf_and_path_policy(ia, as_crypto_obj, instance_path)
    executable_name = generator.TYPES_TO_EXECUTABLES[stype]
    tp = generate_topology_from_DB(as_id=ia.as_str())  # topology file
    type_key = generator.TYPES_TO_KEYS[stype]

    config = generator.prep_supervisord_conf(tp[type_key][instance_id], executable_name,
                                             stype, str(instance_id), ia)
    generator.write_supervisord_config(config, instance_path)
    generator.write_topology_file(tp, stype, instance_path)
    generator.write_zlog_file(stype, elem_id, instance_path)


def generate_topology_from_DB(as_id=None):
    """
    Generate the topology.conf from the database values
    :param str as_id: AS identifier
    :return:
    """
    interfaces = Interface.objects.filter(AS=AS.objects.filter(as_id=as_id).first())
    services = Service.objects.filter(AS=AS.objects.filter(as_id=as_id).first())
    topo_dict = {}

    as_obj = AS.objects.filter(as_id=as_id).first()
    # AS wide entries
    topo_dict["ISD_AS"] = str(ISD_AS("%s-%s" % (as_obj.isd_id, as_obj.as_id)))
    topo_dict["MTU"] = as_obj.mtu
    topo_dict["Core"] = as_obj.is_core

    # get overlay type inside AS from IPs used by hosts
    hosts = Host.objects.filter(AS_id=AS.objects.filter(as_id=as_id).first())
    AS_internal_overlay = "UDP/IPv6"  # FIXME(FR4NK-W): add value to the model and get it from there
    for host in hosts:
        ip = ipaddress.ip_address(host.ip)
        if isinstance(ip, ipaddress.IPv4Address):
            AS_internal_overlay = "UDP/IPv4"
            break
    topo_dict["Overlay"] = AS_internal_overlay

    topo_dict[generator.TYPES_TO_KEYS['router']] = {}
    for interface in interfaces:
        router_instance_id = get_router_instance_id(as_id,
                                                    interface.host)
        if router_instance_id not in topo_dict[generator.TYPES_TO_KEYS['router']].keys():
            topo_dict[generator.TYPES_TO_KEYS['router']][router_instance_id] = {}
        router_instance_entry = topo_dict[generator.TYPES_TO_KEYS['router']][router_instance_id]
        if "Interfaces" not in router_instance_entry.keys():
            router_instance_entry = {"Interfaces": {}}
        remote_if_obj = interface.remote_interface()
        remote_AS_obj = interface.remote_as()

        link_overlay = "UDP/IPv6"  # FIXME(FR4NK-W): add value to the model and get it from there
        if isinstance(ipaddress.ip_address(interface.public_ip), ipaddress.IPv4Address) and \
                isinstance(ipaddress.ip_address(remote_if_obj.public_ip), ipaddress.IPv4Address):
            link_overlay = "UDP/IPv4"

        router_instance_entry["Interfaces"][interface.interface_id] = {
            "InternalAddrIdx": 0,
            "ISD_AS": str(ISD_AS("%s-%s" % (remote_AS_obj.isd_id, remote_AS_obj.as_id))),
            "LinkTo": str(interface.link().type),
            "Bandwidth": interface.link().bandwidth,
            "Bind": {
                "L4Port": interface.bind_port,
                "Addr": interface.bind_ip
            },
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

    service_mapping = {}  # FIXME(FR4NK-W): fix model to following naming pattern
    # as in generator and topo file
    for entry in Service.SERVICE_TYPES:
        service_mapping[entry[0]] = entry[1].lower().replace(" ", "_")
    for service in services:
        if service.type == "ZK":
            continue
        service_key = generator.TYPES_TO_KEYS[service_mapping[service.type]]
        service_instance_id = get_service_instance_id(as_id, service.host, service.type)
        if service_key not in topo_dict.keys():
            topo_dict[service_key] = {}
        topo_dict[service_key][service_instance_id] = {
            "Public": [{"L4Port": service.port,
                        "Addr": service.host.ip}]
        }
    return topo_dict


class AScrypto:
    """
    Class representing an AS with the crypto information required to generate the gen folder
    """
    certificate = None
    trc = None
    keys = {}
    core_keys = {}

    @classmethod
    def from_AS(cls, isd=None, as_id=None):
        """
        Build AS_crypto from a model.AS object
        :param str isd: ISD identifier of the target AS
        :param str as_id: AS identifier of the target AS
        :return:
        """
        inst = cls()
        as_obj = AS.objects.filter(isd=isd, as_id=as_id).first()
        inst.certificate = str(as_obj.certificates)
        inst.trc = str(ISD.objects.filter(id=as_obj.isd.id).first().trc)
        inst.keys = {
            'sig_key': as_obj.sig_priv_key,
            'sig_key_raw': as_obj.enc_priv_key,

            'enc_key': as_obj.master_as_key,
            'master_as_key': as_obj.master_as_key,
        }
        if as_obj.is_core:
            inst.core_keys = {
                'core_sig_key': as_obj.core_sig_priv_key,
                'online_key': as_obj.core_online_priv_key,
                'offline_key': as_obj.core_offline_priv_key,

                'core_sig_key_raw': generate_raw_key(as_obj.core_sig_priv_key),
                'online_key_raw': generate_raw_key(as_obj.core_online_priv_key),
                'offline_key_raw': generate_raw_key(as_obj.core_offline_priv_key),
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
