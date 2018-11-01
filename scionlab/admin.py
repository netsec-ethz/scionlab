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

from django.contrib import admin
from django import forms
from .models import (
    ISD,
    AS,
    UserAS,
    AttachmentPoint,
    Host,
    ManagedHost,
    Interface,
    Link,
    Service,
    VPN,
    VPNClient,
)

admin.site.register([
    ISD,
    AttachmentPoint,
    Host,
    ManagedHost,
    Interface,
    Link,
    Service,
    VPN,
    VPNClient,
])


class ASCreationForm(forms.ModelForm):
    """
    Specialised ModelForm for AS creation which will
    initialise keys on creation
    """

    def save(self, commit=True):
        """
        Initialise keys on form save
        """
        _as = super().save(commit=False)
        _as.init_keys()
        if commit:
            _as.save()
        return _as


@admin.register(AS, UserAS)
class ASAdmin(admin.ModelAdmin):

    readonly_fields = ('as_id',)
    list_display = ('isd_as_str', 'label', 'is_core', 'is_ap', 'is_userAS')
    list_filter = ('isd', 'is_core',)

    def get_fieldsets(self, request, obj=None):
        """
        Don't show key field during AS creation;
        the keys are initialised in `AS.init_keys` called in
        `ASCreationForm.save()`.
        """
        base_fields = (
            None, {
                'fields': ('isd', 'as_id', 'label', 'owner',)
            }
        )
        key_fields = (
            'Keys', {
                'classes': ('collapse',),
                'fields': (
                    ('sig_pub_key', 'sig_priv_key'),
                    ('enc_pub_key', 'enc_priv_key'),
                )
            }
        )
        if not obj:
            return (base_fields,)
        return (base_fields, key_fields)

    def get_form(self, request, obj=None, **kwargs):
        """
        Use custom form during AS creation
        """
        if obj is None:
            kwargs['form'] = ASCreationForm
        return super().get_form(request, obj, **kwargs)

    def is_ap(self, obj):
        """ Is the AS `obj` an attachment point? """
        return hasattr(obj, 'attachment_point')

    is_ap.boolean = True

    def is_userAS(self, obj):
        """ Is the AS `obj` a user AS? """
        return isinstance(obj, UserAS)

    is_userAS.boolean = True
