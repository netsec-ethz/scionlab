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
from django.db import transaction
from django.core import management

def value_set(query_set, field_name):
    """
    Short-hand for creating a set out of a values-query for a single model field
    """
    return set(query_set.values_list(field_name, flat=True))

class FakeException(Exception):
    pass

def with_fixtures(fixtures):
    """
    A decorator to execute the decorated function in an environment where the 
    specified fixtures are loaded temporarily
    """
    def decorator(func):
        def wrapped(*args, **kwargs):
            parameters = []
            try:
                with transaction.atomic():
                    for fixture in fixtures:
                        management.call_command('loaddata', fixture)
                    parameters = func(*args, **kwargs)
                    raise FakeException()
            except FakeException:
                pass
            return parameters
        return wrapped
    return decorator

