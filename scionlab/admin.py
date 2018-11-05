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
    AttachmentPoint,
    Host,
    ManagedHost,
    Interface,
    Link,
    Service,
    VPN,
    VPNClient,
])


@admin.register(ISD)
class ISDAdmin(admin.ModelAdmin):
    readonly_fields = ('id',)
    fieldsets = (
        (None, {
            'fields': ('id', 'label',)
        }),
        ('TRC', {
            'classes': ('collapse',),
            'fields': ('trc', 'trc_priv_keys',)
        }),
    )
    list_display = ('id', 'label',)
    list_editable = ('label',)
    ordering = ['id']


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

    actions = ['update_keys']
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
                'fields': ('isd', 'as_id', 'label', 'is_core', 'owner',)
            }
        )
        key_fields = (
            'Keys & Certificates', {
                'classes': ('collapse',),
                'fields': (
                    ('sig_pub_key', 'sig_priv_key'),
                    ('enc_pub_key', 'enc_priv_key'),
                    'master_as_key',
                    ('core_sig_pub_key', 'core_sig_priv_key'),
                    ('core_online_pub_key', 'core_online_priv_key'),
                    ('core_offline_pub_key', 'core_offline_priv_key'),
                    'certificates',
                    'certificates_needs_update'
                )
            }
        )
        if not obj:
            return (base_fields,)
        return (base_fields, key_fields)

    def get_readonly_fields(self, request, obj):
        """
        Don't allow editing isd or as_id after the object has
        been created.
        """
        # FIXME(matzf) conceptually, an AS can change the ISD. Not allowed for now
        # as I anticipate this may unnecessarily complicate the TRC/certificate
        # update logic. Should be revisited.
        if obj:
            return ('isd', 'as_id',)
        return ()

    def get_form(self, request, obj=None, **kwargs):
        """
        Use custom form during AS creation
        """
        if not obj:
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

    def update_keys(self, request, queryset):
        """
        Admin action: generate new keys for the selected ASes.
        """
        for as_ in queryset.iterator():
            as_.update_keys()
