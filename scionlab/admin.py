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
    Interface,
    Link,
    Service,
    VPN,
    VPNClient,
    MAX_PORT,
)

admin.site.register([
    AttachmentPoint,
    Host,
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
            'fields': ('trc', 'trc_priv_keys', 'trc_needs_update')
        }),
    )
    list_display = ('id', 'label',)
    list_editable = ('label',)
    ordering = ['id']


class _AlwaysChangedModelForm(forms.ModelForm):
    """
    Helper form: allows to save ModelInlines with default values.
    """
    def has_changed(self, *args, **kwargs):
        if self.instance.pk is None:
            return True
        return super().has_changed(*args, **kwargs)


class HostInline(admin.TabularInline):
    model = Host
    extra = 0
    form = _AlwaysChangedModelForm


class ServiceInline(admin.TabularInline):
    model = Service
    extra = 0
    form = _AlwaysChangedModelForm
    # TODO(matzf): restrict hosts or revisit data model
    fields = ('type', 'host', 'port')


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
        _as.save()
        _as.init_default_services()
        return _as


@admin.register(AS, UserAS)
class ASAdmin(admin.ModelAdmin):

    inlines = [HostInline, ServiceInline]
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
        # TODO(matzf): Changing is_core should also be possible, not yet implemented
        #              Requires removing core links etc, bump signed certificates
        if obj:
            return ('isd', 'is_core', 'as_id',)
        return ()

    def get_inline_instances(self, request, obj):
        """
        Hide the Host, Service and Interface/Link inlines during creation.
        """
        if obj:
            return super().get_inline_instances(request, obj)
        return []

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


class LinkAdminForm(forms.ModelForm):
    class Meta:
        model = Link
        exclude = ['interfaceA', 'interfaceB']

    # TODO(matzf): avoid duplication, make naming consistent (to/from vs. a/b)?
    from_host = forms.ModelChoiceField(queryset=Host.objects.all())
    from_port = forms.IntegerField(min_value=1, max_value=MAX_PORT, required=False)
    from_public_ip = forms.GenericIPAddressField(required=False)
    from_public_port = forms.IntegerField(min_value=1, max_value=MAX_PORT, required=False)
    from_bind_ip = forms.GenericIPAddressField(required=False)
    from_bind_port = forms.IntegerField(min_value=1, max_value=MAX_PORT, required=False)

    to_host = forms.ModelChoiceField(queryset=Host.objects.all())
    to_port = forms.IntegerField(min_value=1, max_value=MAX_PORT, required=False)
    to_public_ip = forms.GenericIPAddressField(required=False)
    to_public_port = forms.IntegerField(min_value=1, max_value=MAX_PORT, required=False)
    to_bind_ip = forms.GenericIPAddressField(required=False)
    to_bind_port = forms.IntegerField(min_value=1, max_value=MAX_PORT, required=False)

    def __init__(self, data=None, files=None, initial=None, instance=None, **kwargs):
        if instance:
            initial = initial or {}
            if instance.interfaceA:
                self._init_interface_form_data(initial, instance.interfaceA, 'from_')
            if instance.interfaceB:
                self._init_interface_form_data(initial, instance.interfaceB, 'to_')

        super().__init__(data=data, files=files, initial=initial, instance=instance, **kwargs)

    def _init_interface_form_data(self, initial, interface, prefix):
        initial[prefix+'host'] = interface.host_id
        initial[prefix+'port'] = interface.port
        initial[prefix+'public_ip'] = interface.public_ip
        initial[prefix+'public_port'] = interface.public_port
        initial[prefix+'bind_ip'] = interface.bind_ip
        initial[prefix+'bind_port'] = interface.bind_port

    def _save_interface_form_data(self, interface, prefix):
        kwargs = dict(
            host=self.cleaned_data[prefix+'host'],
            port=self.cleaned_data[prefix+'port'],
            public_ip=self.cleaned_data[prefix+'public_ip'],
            public_port=self.cleaned_data[prefix+'public_port'],
            bind_ip=self.cleaned_data[prefix+'bind_ip'],
            bind_port=self.cleaned_data[prefix+'bind_port'],
        )
        if interface:
            interface.update(**kwargs)
        else:
            interface = Interface.objects.create(**kwargs)
        return interface

    def save(self, commit=True):
        link = super().save(commit=False)
        link.interfaceA = self._save_interface_form_data(link.get_interface_a(), 'from_')
        link.interfaceB = self._save_interface_form_data(link.get_interface_b(), 'to_')
        link.save()
        return link


@admin.register(Link)
class LinkAdmin(admin.ModelAdmin):
    form = LinkAdminForm

    list_display = ('__str__', 'type', 'active', 'public_ip_a', 'public_port_a', 'bind_ip_a',
                    'bind_port_a', 'public_ip_b', 'public_port_b', 'bind_ip_b', 'bind_port_b')
    list_filter = ('type', 'active', 'interfaceA__AS', 'interfaceB__AS',)

    def public_ip_a(self, obj):
        return obj.interfaceA.public_ip

    def public_port_a(self, obj):
        return obj.interfaceA.public_port

    def bind_ip_a(self, obj):
        return obj.interfaceA.public_ip

    def bind_port_a(self, obj):
        return obj.interfaceA.public_port

    def public_ip_b(self, obj):
        return obj.interfaceB.public_ip

    def public_port_b(self, obj):
        return obj.interfaceB.public_port

    def bind_ip_b(self, obj):
        return obj.interfaceB.public_ip

    def bind_port_b(self, obj):
        return obj.interfaceB.public_port
