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

from typing import List

from django import template
from scionlab.models.core import Interface
from scionlab.models.user_as import UserAS

register = template.Library()


@register.filter(name='is_link_over_vpn')
def is_link_over_vpn_filter(iface):
    """
    A Django template filter to use `UserAS:is_link_over_vpn(...)` inside templates
    """
    return UserAS.is_link_over_vpn(iface)


@register.filter
def active_interfaces(ifaces: List[Interface]) -> List[Interface]:
    """
    A Django template filter to use `UserAS:is_link_over_vpn(...)` inside templates
    """
    return [iface for iface in ifaces if iface.link().active]
