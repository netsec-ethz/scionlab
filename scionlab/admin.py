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

from django import urls
from django.utils.html import format_html
from django.core.exceptions import ValidationError
from django.contrib import admin
from django.shortcuts import get_object_or_404
from django import forms
from django.urls import resolve, path

from scionlab.models import (
    ISD,
    AS,
    UserAS,
    AttachmentPoint,
    Host,
    Interface,
    Link,
    BorderRouter,
    Service,
    VPN,
    VPNClient,
    MAX_PORT,
    DEFAULT_HOST_INTERNAL_IP,
)
from scionlab.util.http import HttpResponseAttachment
from scionlab.util import config_tar

admin.site.register([
    AttachmentPoint,
])


class _AlwaysChangedModelForm(forms.ModelForm):
    """
    Helper form: allows to save newly created ModelInlines with default values.
    """
    def has_changed(self, *args, **kwargs):
        if self.instance.pk is None:
            return True
        return super().has_changed(*args, **kwargs)


class _CreateUpdateModelForm(_AlwaysChangedModelForm):
    """
    Helper form class: because most of our models require explicit
    create or update logic to be executed, it seems easier to explicitly
    call the appropriate model logic, than using ModelForm's default behaviour of
    setting all fields and trying to find what's changed later.

    Note that this form class problably has severe restrictions over ModelForm.

    Note that, while it may be cleaner to use a fully custom form instead of
    adapting the already convoluted logic of ModelForms, using ModelAdmin
    requires using ModelForms.
    """

    def create(self):
        """
        Entry point for subclass for when creating a new objects.
        Use the information in self.cleaned_data to create a new object.
        :returns: new object
        """
        pass

    def update(self):
        """
        Entry point for subclass for when updating an existing object.
        Use the information in `self.cleaned_data` to update `self.instance`.
        Default implementation is to update the object based on ModelForm's logic.
        :returns: updated object
        """
        pass

    def _post_clean(self):
        # This is the hook were ModelForm does part of its magic; here
        # it calls `construct_instance(self, self.instance, self.instance._meta.fields,...)`
        # which is the call that we want to replace with a call to the model logic.
        # Note (for our purposes minor) difference: ModelForm does *not* save to the DB yet, but we
        # do.
        if self.errors:
            return

        try:
            if self.instance.pk is None:
                self.instance = self.create()
            elif self.has_changed():
                self.update()
        except ValidationError as e:
            self._update_errors(e)

        # Call more stuff that ModelForm usually does.
        try:
            self.instance.full_clean(validate_unique=False)
        except ValidationError as e:
            self._update_errors(e)
        self.validate_unique()

    def save(self, commit=True):
        # We override this hook too, because we have already saved our model at this point.
        # calling super().save(commit=False) is a no-op as far as we're concerned, but
        # has some side-effects:
        #  - it checks that no errors are present. This should never occur (ModelAdmin checks this)
        #  - it sets up a method self.save_m2m, which is required for the ModelAdmin to function
        #    properly
        super().save(commit=False)
        return self.instance


@admin.register(ISD)
class ISDAdmin(admin.ModelAdmin):
    list_display = ('isd_id', 'label',)
    list_editable = ('label',)
    ordering = ['isd_id']

    def get_fieldsets(self, request, obj=None):
        """
        Don't show trc fields during ISD creation
        """
        base_fields = (None, {
            'fields': ('isd_id', 'label',)
        })
        trc_fields = ('TRC', {
            'classes': ('collapse',),
            'fields': ('trc', 'trc_priv_keys')
        })
        if not obj:
            return (base_fields,)
        return (base_fields, trc_fields)

    def get_readonly_fields(self, request, obj):
        """
        Don't allow editing the ISD-id after creation.
        """
        if obj:
            return ('isd_id',)
        return ()


class HostAdminForm(_CreateUpdateModelForm):
    class Meta:
        fields = ('internal_ip', 'public_ip', 'bind_ip', 'label', 'managed', 'management_ip',
                  'secret')

    def create(self):
        return Host.objects.create(
            AS=self.instance.AS,    # Hmmm...
            internal_ip=self.cleaned_data['internal_ip'],
            public_ip=self.cleaned_data['public_ip'],
            bind_ip=self.cleaned_data['bind_ip'],
            label=self.cleaned_data['label'],
            managed=self.cleaned_data['managed'],
            management_ip=self.cleaned_data['management_ip'],
            secret=self.cleaned_data['secret']
        )

    def update(self):
        self.instance.update(
            internal_ip=self.cleaned_data['internal_ip'],
            public_ip=self.cleaned_data['public_ip'],
            bind_ip=self.cleaned_data['bind_ip'],
            label=self.cleaned_data['label'],
            managed=self.cleaned_data['managed'],
            management_ip=self.cleaned_data['management_ip'],
            secret=self.cleaned_data['secret']
        )


class HostAdminMixin:
    """
    Helper class for shared functionality in HostAdmin (the ModelAdmin for Host) and
    HostInline (the ModelInline for Host in ASAdmin).
    This is simply a bag of methods that can be used in readonly_fields/list_display.
    """
    def latest_config_deployed(self, obj):
        return not obj.needs_config_deployment()

    latest_config_deployed.boolean = True

    def get_config_link(self, obj):
        url = urls.reverse('admin:scionlab_host_config', args=[obj.pk])
        return format_html('<a class="viewlink" href="%s"></a>' % url)

    get_config_link.short_description = 'Config'


class HostInline(HostAdminMixin, admin.TabularInline):
    model = Host
    extra = 0
    form = HostAdminForm
    readonly_fields = ('latest_config_deployed', 'get_config_link')


class ServiceAdminForm(_CreateUpdateModelForm):
    def __init__(self, instance=None, *args, **kwargs):
        super().__init__(instance=instance, *args, **kwargs)
        if self.instance and self.instance.pk:
            self.fields['type'].disabled = True

    def create(self):
        return Service.objects.create(
            host=self.cleaned_data['host'],
            type=self.cleaned_data['type'],
            port=self.cleaned_data['port']
        )

    def update(self):
        self.instance.update(
            host=self.cleaned_data['host'],
            port=self.cleaned_data['port']
        )


class ServiceInline(admin.TabularInline):
    model = Service
    extra = 0
    form = ServiceAdminForm
    fields = ('type', 'host', 'port')

    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        if db_field.name == "host":
            as_ = self.get_parent_object_from_request(request)
            kwargs["queryset"] = as_.hosts.all()
        return super().formfield_for_foreignkey(db_field, request, **kwargs)

    def get_parent_object_from_request(self, request):
        """
        Returns the parent object from the request or None.
        """
        resolved = resolve(request.path_info)
        if 'object_id' in resolved.kwargs:
            return self.parent_model.objects.get(pk=resolved.kwargs['object_id'])
        return None


class BorderRouterAdminForm(_CreateUpdateModelForm):
    def create(self):
        return BorderRouter.objects.create(
            host=self.cleaned_data['host'],
            internal_port=self.cleaned_data['internal_port'],
            control_port=self.cleaned_data['control_port']
        )

    def update(self):
        self.instance.update(
            host=self.cleaned_data['host'],
            internal_port=self.cleaned_data['internal_port'],
            control_port=self.cleaned_data['control_port']
        )


class BorderRouterInline(admin.TabularInline):
    model = BorderRouter
    extra = 0
    form = BorderRouterAdminForm
    fields = ('host', 'internal_port', 'control_port')

    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        if db_field.name == "host":
            as_ = self.get_parent_object_from_request(request)
            kwargs["queryset"] = as_.hosts.all()
        return super().formfield_for_foreignkey(db_field, request, **kwargs)

    def get_parent_object_from_request(self, request):
        """
        Returns the parent object from the request or None.
        """
        resolved = resolve(request.path_info)
        if 'object_id' in resolved.kwargs:
            return self.parent_model.objects.get(pk=resolved.kwargs['object_id'])
        return None


class InterfaceAdminForm(_CreateUpdateModelForm):
    def update(self):
        self.instance.update(
            border_router=self.cleaned_data['border_router'],
        )


class InterfaceInline(admin.TabularInline):
    """
    Inline to show the interface and the associated link in the AS change page.

    This is mostly read-only for now.
    """

    # TODO(matzf): extending this to allow creation and editing of links seemed impossible at first
    # but looking at the LinkAdmin/LinkAdminForm setup, it actually seems doable now using a similar
    # setup.

    form = InterfaceAdminForm
    model = Interface
    extra = 0
    fields = ('link', 'interface_id', 'border_router', 'host', 'public_ip_', 'public_port',
              'bind_ip_', 'bind_port', 'type', 'active', )
    readonly_fields = tuple([f for f in fields if f != 'border_router'])

    def link(self, obj):
        url = urls.reverse('admin:scionlab_link_change', args=[obj.link().pk])
        return format_html('<a class="changelink" href="%s">%s</a>' % (url, obj.link()))

    def type(self, obj):
        return obj.link().type

    def active(self, obj):
        return obj.link().active

    active.boolean = True

    def public_ip_(self, obj):
        return obj.get_public_ip()

    def bind_ip_(self, obj):
        return obj.get_bind_ip() or '-'  # XXX(matzf): don't know why *this* prints 'None' otherwise

    def has_add_permission(self, *args, **kwargs):
        return False

    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        if db_field.name == "border_router":
            as_ = self.get_parent_object_from_request(request)
            kwargs["queryset"] = as_.border_routers.all()
        return super().formfield_for_foreignkey(db_field, request, **kwargs)

    def get_parent_object_from_request(self, request):
        """
        Returns the parent object from the request or None.
        """
        resolved = resolve(request.path_info)
        if 'object_id' in resolved.kwargs:
            return self.parent_model.objects.get(pk=resolved.kwargs['object_id'])
        return None


class ASCreationForm(_CreateUpdateModelForm):
    """
    Specialised ModelForm for AS creation which will initialise keys and initialise default AS
    services. Also allows to define the internal/public and bind IPs for the first host of the AS.
    """
    class Meta:
        fields = ('isd', 'as_id', 'label', 'mtu', 'is_core', 'owner',)

    internal_ip = forms.GenericIPAddressField(required=False, initial=DEFAULT_HOST_INTERNAL_IP)
    public_ip = forms.GenericIPAddressField()
    bind_ip = forms.GenericIPAddressField(required=False)

    def create(self):
        """
        Create the AS, initialise keys and create a first host with default services.
        """
        return AS.objects.create_with_default_services(
            isd=self.cleaned_data['isd'],
            as_id=self.cleaned_data['as_id'],
            label=self.cleaned_data['label'],
            mtu=self.cleaned_data['mtu'],
            is_core=self.cleaned_data['is_core'],
            owner=self.cleaned_data['owner'],
            internal_ip=self.cleaned_data['internal_ip'],
            public_ip=self.cleaned_data['public_ip'],
            bind_ip=self.cleaned_data['bind_ip'],
        )


@admin.register(AS, UserAS)
class ASAdmin(admin.ModelAdmin):
    inlines = [InterfaceInline, BorderRouterInline, ServiceInline, HostInline]
    actions = ['update_keys']
    list_display = ('isd', 'as_id', 'label', 'is_core', 'is_ap', 'is_userAS')
    list_display_links = ('as_id', 'label')
    list_filter = ('isd', 'is_core')
    ordering = ('isd', 'as_id')

    def get_fieldsets(self, request, obj=None):
        """
        Don't show key field during AS creation;
        the keys are initialised in `AS.init_keys` called in
        `ASCreationForm.save()`.
        """
        base_fields = (
            None, {
                'fields': ASCreationForm.Meta.fields
            }
        )
        host_ip_fields = (
            'Host IPs', {
                'fields': ('internal_ip', 'public_ip', 'bind_ip', )
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
                    'certificate_chain',
                    'core_certificate',
                )
            }
        )
        if not obj:
            return (base_fields, host_ip_fields)
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

    def is_userAS(self, obj):
        """ Is the AS `obj` a user AS? """
        return UserAS.objects.filter(as_ptr=obj).exists()

    # Mark the is_ap and is_userAS functions as boolean, so they show
    # as tick/cross in the list view
    is_ap.boolean = True
    is_userAS.boolean = True

    def update_keys(self, request, queryset):
        """
        Admin action: generate new keys for the selected ASes.
        """
        for as_ in queryset.iterator():
            as_.update_keys()


class VPNCreationForm(_CreateUpdateModelForm):
    """
    Specialised ModelForm for VPN creation which will initialise key and cert
    """
    class Meta:
        fields = ('server', 'server_port', 'subnet')

    def create(self):
        """
        Create the VPN, initialise key
        Initialize Certificate Authority when first VPN instance is created
        """
        return VPN.objects.create(
            server=self.cleaned_data['server'],
            server_port=self.cleaned_data['server_port'],
            subnet=self.cleaned_data['subnet'],
        )


@admin.register(VPNClient)
class VPNClientAdmin(admin.ModelAdmin):
    def get_form(self, request, obj=None, **kwargs):
        """
        Use custom form during AS creation
        """
        if not obj:
            kwargs['form'] = VPNClientCreationForm
        return super().get_form(request, obj, **kwargs)


class VPNClientCreationForm(_CreateUpdateModelForm):
    """
    Specialised ModelForm for VPN creation which will initialise key and cert
    """
    class Meta:
        fields = ('vpn', 'host', 'active')

    def create(self):
        """
        Create the VPN client instance, initialise key and cert
        """
        vpn = self.cleaned_data['vpn']
        return vpn.create_client(self.cleaned_data['host'],
                                 self.cleaned_data['active'])


@admin.register(VPN)
class VPNAdmin(admin.ModelAdmin):
    def get_form(self, request, obj=None, **kwargs):
        """
        Use custom form during AS creation
        """
        if not obj:
            kwargs['form'] = VPNCreationForm
        return super().get_form(request, obj, **kwargs)


class LinkAdminForm(_CreateUpdateModelForm):
    class Meta:
        model = Link
        exclude = ['interfaceA', 'interfaceB']

    # TODO(matzf): avoid duplication, make naming consistent (to/from vs. a/b)?
    from_host = forms.ModelChoiceField(queryset=Host.objects.all())
    from_public_ip = forms.GenericIPAddressField(required=False)
    from_public_port = forms.IntegerField(min_value=1, max_value=MAX_PORT, required=False)
    from_bind_ip = forms.GenericIPAddressField(required=False)
    from_bind_port = forms.IntegerField(min_value=1, max_value=MAX_PORT, required=False)

    to_host = forms.ModelChoiceField(queryset=Host.objects.all())
    to_public_ip = forms.GenericIPAddressField(required=False)
    to_public_port = forms.IntegerField(min_value=1, max_value=MAX_PORT, required=False)
    to_bind_ip = forms.GenericIPAddressField(required=False)
    to_bind_port = forms.IntegerField(min_value=1, max_value=MAX_PORT, required=False)

    def __init__(self, data=None, files=None, initial=None, instance=None, **kwargs):
        initial = initial or {}
        if instance and instance.interfaceA:
            self._init_interface_form_data(initial, instance.interfaceA, 'from_')
        else:
            self._init_default_form_data(initial, 'from_')

        if instance and instance.interfaceB:
            self._init_interface_form_data(initial, instance.interfaceB, 'to_')
        else:
            self._init_default_form_data(initial, 'to_')

        super().__init__(data=data, files=files, initial=initial, instance=instance, **kwargs)

    def _init_interface_form_data(self, initial, interface, prefix):
        initial[prefix+'host'] = interface.host_id
        initial[prefix+'public_ip'] = interface.public_ip
        initial[prefix+'public_port'] = interface.public_port
        initial[prefix+'bind_ip'] = interface.bind_ip
        initial[prefix+'bind_port'] = interface.bind_port

    def _init_default_form_data(self, initial, prefix):
        pass

    def _get_interface_form_data(self, prefix):
        return dict(
            border_router=BorderRouter.objects.first_or_create(self.cleaned_data[prefix+'host']),
            public_ip=self.cleaned_data[prefix+'public_ip'],
            public_port=self.cleaned_data[prefix+'public_port'],
            bind_ip=self.cleaned_data[prefix+'bind_ip'],
            bind_port=self.cleaned_data[prefix+'bind_port'],
        )

    def create(self):
        interfaceA = Interface.objects.create(**self._get_interface_form_data('from_'))
        interfaceB = Interface.objects.create(**self._get_interface_form_data('to_'))
        return Link.objects.create(
            type=self.cleaned_data['type'],
            active=self.cleaned_data['active'],
            bandwidth=self.cleaned_data['bandwidth'],
            mtu=self.cleaned_data['mtu'],
            interfaceA=interfaceA,
            interfaceB=interfaceB
        )

    def update(self):
        self.instance.interfaceA.update(**self._get_interface_form_data('from_'))
        self.instance.interfaceB.update(**self._get_interface_form_data('to_'))
        self.instance.update(
            type=self.cleaned_data['type'],
            active=self.cleaned_data['active'],
            bandwidth=self.cleaned_data['bandwidth'],
            mtu=self.cleaned_data['mtu'],
        )


@admin.register(Link)
class LinkAdmin(admin.ModelAdmin):
    form = LinkAdminForm

    list_display = ('__str__', 'type', 'active', 'public_ip_a', 'public_port_a', 'bind_ip_a',
                    'bind_port_a', 'public_ip_b', 'public_port_b', 'bind_ip_b', 'bind_port_b')
    list_filter = ('type', 'active', 'interfaceA__AS', 'interfaceB__AS',)

    def public_ip_a(self, obj):
        return obj.interfaceA.get_public_ip()

    def public_port_a(self, obj):
        return obj.interfaceA.public_port

    def bind_ip_a(self, obj):
        return obj.interfaceA.get_bind_ip()

    def bind_port_a(self, obj):
        return obj.interfaceA.bind_port

    def public_ip_b(self, obj):
        return obj.interfaceB.get_public_ip()

    def public_port_b(self, obj):
        return obj.interfaceB.public_port

    def bind_ip_b(self, obj):
        return obj.interfaceB.get_bind_ip()

    def bind_port_b(self, obj):
        return obj.interfaceB.bind_port


@admin.register(Host)
class HostAdmin(HostAdminMixin, admin.ModelAdmin):
    form = HostAdminForm
    list_display = ('__str__', 'AS',
                    'internal_ip', 'public_ip', 'bind_ip', 'managed', 'management_ip',
                    'latest_config_deployed', 'get_config_link')
    list_filter = ('AS__isd', 'AS', )
    ordering = ['AS']

    def get_urls(self):
        urls = super().get_urls()
        urls += [
            path('<path:object_id>/config',
                 self.admin_site.admin_view(self.get_config),
                 name='scionlab_host_config'),
        ]
        return urls

    def get_config(self, request, object_id):
        """
        View to retrieve configuration tar ball for a host.
        Returns same content as api/host/<int:pk>/config, but authentication is by user (admin), not
        host/secret.
        """
        host = get_object_or_404(Host, pk=object_id)
        filename = '{host}_v{version}.tar.gz'.format(
                        host=host.path_str(),
                        version=host.config_version)
        resp = HttpResponseAttachment(filename=filename, content_type='application/gzip')
        config_tar.generate_host_config_tar(host, resp)
        return resp
