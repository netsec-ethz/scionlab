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

import ipaddress
from django import urls
from django.utils.html import format_html
from django import forms
from django.contrib import admin
from django.core.exceptions import ValidationError
from django.db.models import Count
from django.shortcuts import get_object_or_404
from django.urls import resolve, path

from scionlab.defines import (
    MAX_PORT,
    DEFAULT_HOST_INTERNAL_IP,
)
from scionlab.forms.fields import GenericIPNetworkField
from scionlab.models.core import (
    ISD,
    AS,
    Host,
    Interface,
    Link,
    BorderRouter,
    Service,
)
from scionlab.models.user import User
from scionlab.models.user_as import UserAS, AttachmentPoint
from scionlab.models.vpn import VPN, VPNClient
from scionlab.views.api import get_host_config_tar_response
# Needs to be after import of scionlab.models.user.User
from django.contrib.auth.admin import UserAdmin as auth_UserAdmin


# TODO(matzf): This User model shows up under scionlab now in the admin index page, pitty.
@admin.register(User)
class UserAdmin(auth_UserAdmin):
    """Define admin model for custom User model with no email field."""

    class NumASesFilter(admin.SimpleListFilter):
        title = "Number of ASes"
        parameter_name = 'num_ases'

        def lookups(self, request, model_admin):
            return (
                ('0', '0'),
                ('1', '1'),
                ('>0', '> 0'),
                ('>1', '> 1'),
            )

        def queryset(self, request, queryset):
            if self.value():
                if self.value().startswith('>'):
                    v = self.value()[1:]
                    queryset = queryset.filter(_num_ases__gt=v)
                else:
                    queryset = queryset.filter(_num_ases=self.value())
            return queryset

    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name', 'organisation')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2'),
        }),
    )
    list_display = ('email', 'first_name', 'last_name', 'organisation', 'date_joined', 'last_login',
                    'is_staff', 'is_superuser', 'is_active', 'num_ases')
    list_filter = ('is_staff', 'is_superuser', 'is_active', NumASesFilter)
    search_fields = ('email', 'first_name', 'last_name')
    ordering = ('email',)

    def get_queryset(self, request):
        queryset = super().get_queryset(request)
        queryset = queryset.annotate(
            _num_ases=Count('ases'),
        )
        return queryset

    def num_ases(self, obj):
        return obj._num_ases

    num_ases.admin_order_field = '_num_ases'


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
        exclude = self._get_validation_exclusions()
        try:
            self.instance.full_clean(exclude=exclude, validate_unique=False)
        except ValidationError as e:
            self._update_errors(e)

        if self._validate_unique:
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

    def get_readonly_fields(self, request, obj):
        """
        Don't allow editing the ISD-id after creation.
        """
        if obj:
            return ('isd_id',)
        return ()


class HostAdminForm(_CreateUpdateModelForm):
    class Meta:
        fields = ('AS', 'internal_ip', 'public_ip', 'bind_ip', 'label', 'ssh_host')

    secret = forms.CharField(required=False, widget=forms.TextInput(attrs={'size': '32'}))

    def create(self):
        return Host.objects.create(
            AS=self.instance.AS if self.instance.AS else self.cleaned_data['AS'],    # Hmmm...
            internal_ip=self.cleaned_data['internal_ip'],
            public_ip=self.cleaned_data['public_ip'],
            bind_ip=self.cleaned_data['bind_ip'],
            label=self.cleaned_data['label'],
            ssh_host=self.cleaned_data['ssh_host'],
            secret=self.cleaned_data['secret']
        )

    def update(self):
        self.instance.update(
            internal_ip=self.cleaned_data['internal_ip'],
            public_ip=self.cleaned_data['public_ip'],
            bind_ip=self.cleaned_data['bind_ip'],
            label=self.cleaned_data['label'],
            ssh_host=self.cleaned_data['ssh_host'],
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

    def get_scionlab_config_cmd(self, obj):
        return ('scionlab-config'
                ' --host-id {host_id}'
                ' --host-secret {host_secret}'.format(
                    host_id=obj.uid,
                    host_secret=obj.secret)
                )

    get_scionlab_config_cmd.short_description = 'Commandline'


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
        )

    def update(self):
        self.instance.update(
            host=self.cleaned_data['host'],
        )


class ServiceInline(admin.TabularInline):
    model = Service
    extra = 0
    form = ServiceAdminForm
    fields = ('type', 'host')

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
        )

    def update(self):
        self.instance.update(
            host=self.cleaned_data['host'],
        )


class BorderRouterInline(admin.TabularInline):
    model = BorderRouter
    extra = 0
    form = BorderRouterAdminForm
    fields = ('host',)

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
              'bind_ip_', 'type', 'active', )
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


@admin.register(AS)
class ASAdmin(admin.ModelAdmin):
    class InfrastructureASFilter(admin.SimpleListFilter):
        title = "Infrastructure AS"
        parameter_name = 'infrastructure_as'

        def lookups(self, request, model_admin):
            return (
                (True, 'Infrastructure'),
                (False, 'User AS'),
            )

        def queryset(self, request, queryset):
            if self.value() == 'True':
                queryset = queryset.filter(owner=None)
            elif self.value() == 'False':
                queryset = queryset.exclude(owner=None)
            return queryset

    inlines = [InterfaceInline, BorderRouterInline, ServiceInline, HostInline]
    actions = ['update_keys', 'update_core_keys']
    list_display = ('isd', 'as_id', 'owner', 'label', 'is_core', 'is_ap', 'is_userAS')
    list_display_links = ('as_id', 'label')
    list_filter = ('isd', 'is_core', InfrastructureASFilter)
    ordering = ('isd', 'as_id')
    search_fields = ('label', 'as_id', 'owner__email', 'owner__first_name', 'owner__last_name')

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
                    'master_as_key',
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
        return hasattr(obj, 'attachment_point_info')

    def is_userAS(self, obj):
        """ Is the AS `obj` a user AS? """
        # Some other places simply check for owner=None.
        return UserAS.objects.filter(as_ptr=obj).exists()

    # Mark the is_ap and is_userAS functions as boolean, so they show
    # as tick/cross in the list view
    is_ap.boolean = True
    is_userAS.boolean = True

    def update_keys(self, request, queryset):
        """
        Admin action: generate new keys for the selected ASes.
        """
        AS.update_cp_as_keys(queryset)

    def update_core_keys(self, request, queryset):
        """
        Updates the core keys and update the corresponding TRCs and certificates.
        """
        AS.update_core_as_keys(queryset)


class VPNCreationForm(_CreateUpdateModelForm):
    """
    Specialised ModelForm for VPN creation which will initialise key and cert
    """
    class Meta:
        fields = ('server', 'server_port', 'subnet', 'server_vpn_ip')
        field_classes = {'subnet': GenericIPNetworkField}

    def clean(self):
        cleaned_data = super().clean()
        subnet = cleaned_data.get('subnet')
        server_ip = cleaned_data.get('server_vpn_ip')
        if not subnet or not server_ip:
            return cleaned_data
        subnet = ipaddress.ip_network(subnet)
        server_ip = ipaddress.ip_address(server_ip)
        if server_ip not in subnet:
            raise ValidationError('Server VPN IP is not inside the specified subnet',
                                  code='server_vpn_ip_not_in_subnet')
        return cleaned_data

    def create(self):
        """
        Create the VPN, initialise key
        Initialize Certificate Authority when first VPN instance is created
        """
        return VPN.objects.create(
            server=self.cleaned_data['server'],
            server_port=self.cleaned_data['server_port'],
            subnet=self.cleaned_data['subnet'],
            server_vpn_ip=self.cleaned_data['server_vpn_ip'],
        )


class VPNUpdateForm(VPNCreationForm):
    class Meta:
        fields = ('server', 'server_port', 'subnet', 'server_vpn_ip', 'private_key', 'cert')
        field_classes = {'subnet': GenericIPNetworkField}

    def update(self):
        self.instance.update(
            server=self.cleaned_data['server'],
            server_port=self.cleaned_data['server_port'],
            subnet=self.cleaned_data['subnet'],
            server_vpn_ip=self.cleaned_data['server_vpn_ip'],
            private_key=self.cleaned_data['private_key'],
            cert=self.cleaned_data['cert'],
        )


@admin.register(VPN)
class VPNAdmin(admin.ModelAdmin):
    actions = ['update_key']
    list_display = ('__str__', 'server', 'subnet', 'server_vpn_ip', 'num_clients')
    list_display_links = ('__str__',)

    def get_form(self, request, obj=None, **kwargs):
        """
        Use different forms for VPN creation or update
        """
        if not obj:
            kwargs['form'] = VPNCreationForm
        else:
            kwargs['form'] = VPNUpdateForm
        return super().get_form(request, obj, **kwargs)

    def update_key(self, request, queryset):
        """
        Admin action: generate new keys / certificates for the selected VPN servers.
        """
        for vpn in queryset.iterator():
            vpn.update_key()

    update_key.short_description = 'Generate new keys/certificates for the selected VPN servers'

    def num_clients(self, obj):
        return obj.clients.filter(active=True).count()


@admin.register(VPNClient)
class VPNClientAdmin(admin.ModelAdmin):
    list_display = ('__str__', 'vpn', 'ip', 'common_name')
    list_display_links = ('__str__',)
    list_filter = ('vpn', 'active')

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


class LinkAdminForm(_CreateUpdateModelForm):
    class Meta:
        model = Link
        exclude = ['interfaceA', 'interfaceB']

    from_host = forms.ModelChoiceField(queryset=Host.objects.all())
    from_public_ip = forms.GenericIPAddressField(required=False)
    from_public_port = forms.IntegerField(min_value=1, max_value=MAX_PORT, required=False)
    from_bind_ip = forms.GenericIPAddressField(required=False)

    to_host = forms.ModelChoiceField(queryset=Host.objects.all())
    to_public_ip = forms.GenericIPAddressField(required=False)
    to_public_port = forms.IntegerField(min_value=1, max_value=MAX_PORT, required=False)
    to_bind_ip = forms.GenericIPAddressField(required=False)

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

    def _init_default_form_data(self, initial, prefix):
        pass

    def _get_interface_form_data(self, prefix):
        return dict(
            border_router=BorderRouter.objects.first_or_create(self.cleaned_data[prefix+'host']),
            public_ip=self.cleaned_data[prefix+'public_ip'],
            public_port=self.cleaned_data[prefix+'public_port'],
            bind_ip=self.cleaned_data[prefix+'bind_ip'],
        )

    def create(self):
        interfaceA = Interface.objects.create(**self._get_interface_form_data('from_'))
        interfaceB = Interface.objects.create(**self._get_interface_form_data('to_'))
        return Link.objects.create(
            type=self.cleaned_data['type'],
            active=self.cleaned_data['active'],
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
            mtu=self.cleaned_data['mtu'],
        )


@admin.register(Link)
class LinkAdmin(admin.ModelAdmin):
    form = LinkAdminForm

    list_display = ('__str__', 'type', 'active', 'public_ip_a', 'public_port_a', 'bind_ip_a',
                    'public_ip_b', 'public_port_b', 'bind_ip_b',)
    list_filter = ('type', 'active', 'interfaceA__AS', 'interfaceB__AS',)

    def public_ip_a(self, obj):
        return obj.interfaceA.get_public_ip()

    def public_port_a(self, obj):
        return obj.interfaceA.public_port

    def bind_ip_a(self, obj):
        return obj.interfaceA.get_bind_ip()

    def public_ip_b(self, obj):
        return obj.interfaceB.get_public_ip()

    def public_port_b(self, obj):
        return obj.interfaceB.public_port

    def bind_ip_b(self, obj):
        return obj.interfaceB.get_bind_ip()


@admin.register(Host)
class HostAdmin(HostAdminMixin, admin.ModelAdmin):
    form = HostAdminForm
    readonly_fields = ['uid', 'get_scionlab_config_cmd']
    list_display = ('__str__', 'AS',
                    'internal_ip', 'public_ip', 'bind_ip', 'ssh_host',
                    'latest_config_deployed', 'get_scionlab_config_cmd', 'get_config_link')
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
        Returns same content as api_get_config, but authentication is by user (admin), not
        host/secret.
        """
        host = get_object_or_404(Host, pk=object_id)
        return get_host_config_tar_response(host)


admin.site.register([
    AttachmentPoint,
])
