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


from scionlab.models.user_as import AttachmentPoint


def generate_link_info(host):
    """
    Generate the dictionary that holds the necessary information to do the bandwidth limit enforcement
    :param host: Host that is hosting the AP
    :return: dictionary holding all the necessary information about the links
    """
    link_info = {}

    aps = AttachmentPoint.objects.filter(AS__as_id=host.AS.as_id).first()
    interfaces = list(aps.AS.interfaces.all())

    for interface in interfaces:
        link = interface.link()
        if link.active:
            remote_as = interface.remote_interface().AS.isd_as_str()
            as_id = get_id_from_isd_as(remote_as)
            user_as = is_user_as(remote_as)
            bandwidth = interface.link().bandwidth
            ip_addr = interface.remote_interface().get_public_ip()
            link_entry = {
                "AS_ID": as_id,
                "IsUserAS": user_as,
                "Bandwidth": bandwidth,
                "IP-Address": ip_addr
            }
            link_info[interface.interface_id] = link_entry
    return link_info


def is_user_as(isd_as):
    """
    Parse the ISD_AS string and determine if the AS with the corresponding ISD_AS field is a user AS
    :param isd_as: String holding ISD_AS
    :return: True iff AS is a user AS, False otherwise
    """
    parts = isd_as.split(':')
    if int(parts[len(parts) - 2]) == 1:
        return True
    else:
        return False


def get_id_from_isd_as(isd_as):
    """
    Since the number after the last : is unique for each user AS we use that as an ID to identify the links
    :param isd_as: String holding ISD_AS
    :return: The number after the last :
    """
    parts = isd_as.split(':')
    return int(parts[len(parts) - 1])
