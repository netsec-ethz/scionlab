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

from django import forms
from django.conf import settings
from django.forms import BaseModelFormSet
from django.core.exceptions import ValidationError
from django.db.models import Case, Value, When, BooleanField

from crispy_forms.helper import FormHelper
from crispy_forms.layout import Layout, Row, Column, Div, HTML
from crispy_forms.bootstrap import AppendedText

from scionlab.defines import MAX_PORT, DEFAULT_PUBLIC_PORT
from scionlab.models.core import Link
from scionlab.models.user_as import AttachmentPoint, AttachmentConf, UserAS
from scionlab.util.portmap import PortMap


class AttachmentConfFormSet(BaseModelFormSet):
    """
    A FormSet companion for the UserASForm, representing its `AttachmentPoint`s
    """

    def __init__(self, *args, **kwargs):
        self.userASForm = kwargs.pop('userASForm')
        self.isd = None
        super().__init__(*args, **kwargs)

    def _check_isd(self, forms):
        """
        Check the consistency of the ISD
        """
        instance = self.userASForm.instance
        isd_set = {form.cleaned_data['attachment_point'].AS.isd for form in forms}
        if instance and instance.isd_fixed():
            # If ISD is fixed, say which ISD the AS is restricted to
            isd_set.add(instance.isd)
            if len(isd_set) > 1:
                raise ValidationError("All attachment points must belong to %s. "
                                      "See \"Fixed links\" below." % instance.isd)
        else:
            if len(isd_set) > 1:
                raise ValidationError("All attachment points must belong to the same ISD")

        if instance and instance.is_attachment_point():
            for form in forms:
                if form.cleaned_data['attachment_point'] == instance.attachment_point_info:
                    raise ValidationError("A link to your own AP is not allowed.")

        if not instance:
            if len(isd_set) == 1:
                self.isd = isd_set.pop()
            else:
                # One attachment point must be selected at creation time
                raise ValidationError("Select at least one attachment point")

    def _check_ip_ports(self, forms):
        """
        Check for clashes in (ip, port) combinations
        """
        installation_type = self.userASForm.cleaned_data.get('installation_type')
        public_addrs, public_addr_clashes = PortMap(), []
        local_addrs, local_addr_clashes = PortMap(), []
        forward_ports, forward_addr_clashes = set(), []

        for f in filter(lambda f: not f.cleaned_data['use_vpn'], forms):
            public_ip = f.cleaned_data['public_ip'],
            port = f.cleaned_data['public_port']
            bind_ip = f.cleaned_data['bind_ip']
            if public_addrs.add(public_ip, port):
                public_addr_clashes.append(f)
            if local_addrs.add(bind_ip or public_ip, port) and bind_ip:
                local_addr_clashes.append(f)
            if installation_type == UserAS.VM:
                if port in forward_ports:
                    forward_addr_clashes.append(f)
                else:
                    forward_ports.add(port)

        for form in public_addr_clashes:
            form.add_error('public_port',
                           ValidationError('This port is already in use',
                                           code='public_port_clash'))
        for form in local_addr_clashes:
            form.add_error('public_port',
                           ValidationError('This port is already in use for the specified '
                                           'bind IP address',
                                           code='local_port_clash'))
        for form in forward_addr_clashes:
            form.add_error('public_port',
                           ValidationError('This port clashes in the VM setup',
                                           code='forwarded_port_clash'))

    def clean(self):
        if any(self.errors):
            # Don't bother validating the formset unless each form is valid on its own
            return
        active_forms = []
        for form in self.forms:
            if self.can_delete and self._should_delete_form(form):
                continue
            # Skip empty forms and deactivated connections
            if not form.cleaned_data or not form.cleaned_data['active']:
                continue
            active_forms.append(form)
        self._check_isd(active_forms)
        self._check_ip_ports(active_forms)

    def save(self, user_as, commit=True):
        att_confs = super().save(commit=False)
        user_as.update_attachments(att_confs, self.deleted_objects)


class AttachmentConfFormHelper(FormHelper):
    """
    Create the crispy-forms FormHelper. The form will then be rendered
    using {% crispy form %} in the template.
    """

    conf_header = Div(
            Row(
                Column('attachment_point', css_class='col-md-5'),
                Column('use_vpn', css_class='col-md-5'),
                'id'
                ),
            css_class="card-header"
            )

    conf_body = Div(
            Row(
                Column(AppendedText('public_ip', '<span class="fa fa-external-link"/>'),
                       css_class='col-md-6 hidable'),
                Column(AppendedText('public_port', '<span class="fa fa-share-square-o"/>'),
                       css_class='col-md-6')
                ),
            Row(
                HTML("""<button type="button" class="btn btn-link bind-row-collapser collapsed"
                                aria-expanded="false" aria-controls="bind-row">
                            Show binding options for NAT
                            <i class="fa fa-plus-circle"></i>
                            <i class="fa fa-minus-circle"></i>
                        </button>""")
                ),
            Row(
                Column(AppendedText('bind_ip', '<span class="fa fa-external-link-square"/>'),
                       css_class='col-md-6 hidable'),
                css_class="bind-row"
                ),
            css_class="card-body"
            )

    conf_footer = Div(
        Row(
            Column('active', css_class='col-md-6'),
            Column('DELETE', css_class='col-md-6 text-danger')
            ),
        css_class="card-footer"
    )

    conf_collapser = HTML(
        """<button type="button" id="new-ap-collapser"
                   class="mt-3 btn btn-link collapsed"
                   aria-expanded="false"
                   aria-controls="new-ap-form">
                New provider link
                <i class="mt-3 fa fa-plus-circle"></i>
                <i class="mt-3 fa fa-minus-circle"></i>
           </button>"""
    )

    def __init__(self, instance, userAS, *args, **kwargs):
        super().__init__(*args, **kwargs)

        outter_parts = ()
        if instance:
            # existing link, existing user AS
            # - can be deleted / deactivated
            card_parts = (
                self.conf_header,
                self.conf_body,
                self.conf_footer,
            )
        elif userAS:
            # new link, existing user AS
            # - cannot be deleted (it doesnt exist) or deactivated (because it doesnt make sense to
            #   create an inactive link).
            # - initially collapsed
            outter_parts = (
                self.conf_collapser,
            )
            card_parts = (
                self.conf_header,
                self.conf_body,
            )
        else:
            # new (and only) link, user AS
            # - cannot be deleted / deactivated nor collapsed
            card_parts = (
                self.conf_header,
                self.conf_body,
            )

        self.layout = Layout(
            Div(
                *outter_parts,
                Div(
                    *card_parts,
                    css_class="card attachment-form",
                ),
                css_class='attachment'
            )
        )

        # We need `form_tag = False` to render the AttachmentConfFormSet along with the UserASForm
        self.form_tag = False
        self.disable_csrf = True


class ProviderLinkWidget(forms.Select):
    """
    Subclass of Django's select widget that will disable options which refer to inactive APs.
    """

    def create_option(self, name, value, label, selected, index, subindex=None, attrs=None):
        disabled = False
        if label.startswith('UserAP'):
            current_ap = UserAS.objects.get(as_id=label[11:]).attachment_point_info
            if label.startswith('UserAP') and not current_ap.is_active():
                disabled = False
        option_dict = super()\
            .create_option(name, value, label, selected, index, subindex=subindex, attrs=attrs)
        if disabled:
            option_dict['attrs']['disabled'] = 'disabled'
        return option_dict


class AttachmentConfForm(forms.ModelForm):
    """
    Form for creating and updating a Link involving a UserAS
    """
    public_ip = forms.GenericIPAddressField(
        help_text="Public IP address",
        required=False
    )
    public_port = forms.IntegerField(
        min_value=1024,
        max_value=MAX_PORT,
        initial=DEFAULT_PUBLIC_PORT,
        label="Public Port (UDP)",
        help_text="The attachment point will use this port "
                  "for the overlay link to your AS."
    )
    bind_ip = forms.GenericIPAddressField(
        label="Bind IP address",
        help_text="(Optional) Specify the local IP "
                  "if your border router is behind a NAT/firewall etc.",
        required=False
    )
    use_vpn = forms.BooleanField(
        required=False,
        label="Use VPN",
        help_text="Use an OpenVPN connection for the overlay link between this attachment point "
                  "and the border router of my AS."
    )
    active = forms.BooleanField(
        required=False,
        label="Active",
        help_text="Activate or deactivate this connection without deleting it"
    )
    attachment_point = forms.ModelChoiceField(
        queryset=None,
        widget=ProviderLinkWidget,
        help_text="Links to User APs can disappear when the corresponding Attachment Point is deleted."
    )

    class Meta:
        model = Link
        fields = ('id', )

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user')
        userAS = kwargs.pop('userAS')
        instance = kwargs.get('instance')
        initial = kwargs.pop('initial', {})
        initial['active'] = False
        if instance:
            use_vpn = UserAS.is_link_over_vpn(instance.interfaceB)
            initial['active'] = instance.active
            initial['attachment_point'] = AttachmentPoint.objects.get(AS=instance.interfaceA.AS)
            initial['use_vpn'] = use_vpn
            initial['public_ip'] = instance.interfaceB.public_ip
            initial['bind_ip'] = instance.interfaceB.bind_ip
            initial['public_port'] = instance.interfaceB.public_port

            # Clean IP fields when use_vpn is enabled
            if use_vpn:
                initial.pop('public_ip', None)
                initial.pop('bind_ip', None)

            # Clean bind fields when installation type VM
            if userAS.installation_type == UserAS.VM:
                initial.pop('bind_ip', None)
        elif userAS:
            # Set some convenient default values for adding new links:
            # Copy first public IP:
            iface = next((iface for iface in userAS.interfaces.all()
                          if not UserAS.is_link_over_vpn(iface)), None)
            if iface:
                initial['public_ip'] = iface.public_ip
            # Set simple increasing port number:
            index = self._get_formset_index(kwargs['prefix'])
            initial['public_port'] = DEFAULT_PUBLIC_PORT + index

        self.helper = AttachmentConfFormHelper(instance, userAS)
        super().__init__(*args, initial=initial, **kwargs)
        self.fields['attachment_point'].queryset = AttachmentPoint.objects.all().annotate(
            is_user_ap=Case(
                When(
                    AS__owner=None,
                    then=Value(False)
                ),
                default=True,
                output_field=BooleanField()
            )
        ).order_by('is_user_ap', '-AS__hosts__config_queried_at')

    @staticmethod
    def _get_formset_index(prefix):
        """
        Extract index of form in formset by parsing the _default_ formset form prefix
        "<prefix>-<index>".
        Fail hard if the prefix does not match.
        """
        _, idx = prefix.split('-')
        return int(idx)

    def clean(self):
        cleaned_data = super().clean()
        if 'attachment_point' in self.errors:
            return cleaned_data

        if cleaned_data.get('use_vpn'):
            cleaned_data.get('attachment_point').check_vpn_available()
        else:
            public_ip = cleaned_data.get('public_ip')
            if not public_ip:
                # public_ip cannot be empty when use_vpn is false
                self.add_error(
                    'public_ip',
                    ValidationError('Please provide a value for public IP, or enable "Use VPN".',
                                    code='missing_public_ip_no_vpn')
                )
            else:
                ip_addr = ipaddress.ip_address(public_ip)

                if ip_addr.version not in cleaned_data['attachment_point'].supported_ip_versions():
                    self.add_error(
                        'public_ip',
                        ValidationError('IP version {ipv} not supported by the selected '
                                        'attachment point'.format(ipv=ip_addr.version),
                                        code='unsupported_ip_version')
                    )

                if (not settings.DEBUG and (not ip_addr.is_global or ip_addr.is_loopback)) or \
                        ip_addr.is_multicast or \
                        ip_addr.is_reserved or \
                        ip_addr.is_link_local or \
                        (ip_addr.version == 6 and ip_addr.is_site_local) or \
                        ip_addr.is_unspecified:
                    self.add_error(
                        'public_ip',
                        ValidationError("Public IP address must be a publicly routable address. "
                                        "It cannot be a multicast, loopback or otherwise reserved "
                                        "address.",
                                        code='invalid_public_ip')
                    )

        # Ignore active flag while creating a new instance
        if self.instance.pk is None:
            self.cleaned_data['active'] = True

        return cleaned_data

    def save(self, commit=True, user_as=None):
        """
        :return AttachmentPointConf:
        """
        assert not commit, "Persistency in the DB shall be handled in the save(...) method of the \
                           AttachmentLinksFormSet"
        return AttachmentConf(attachment_point=self.cleaned_data['attachment_point'],
                              public_ip=self.cleaned_data['public_ip'] or None,  # needs None not ''
                              public_port=self.cleaned_data['public_port'],
                              bind_ip=self.cleaned_data['bind_ip'] or None,
                              use_vpn=self.cleaned_data['use_vpn'],
                              active=self.cleaned_data['active'],
                              link=self.instance if self.instance.pk is not None else None)
