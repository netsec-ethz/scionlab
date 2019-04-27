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

import ipaddress
from django import forms
from django.core.exceptions import ValidationError


class GenericIPNetworkField(forms.Field):
    def __init__(self, *args, **kwargs):
        kwargs.pop('max_length', 0)  # parent is not length aware
        super().__init__(*args, **kwargs)

    def to_python(self, value):
        if not value:
            return None
        try:
            subnet = ipaddress.ip_network(value)
        except ValueError:
            raise ValidationError('Invalid network address')
        return subnet
