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

import datetime
import os
import string

import pathlib
from django.conf import settings

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

CLIENT_CONFIG_TEMPLATE_PATH = os.path.join(settings.BASE_DIR, "scionlab",
                                           "hostfiles", "client.conf.tmpl")
SERVER_CONFIG_TEMPLATE_PATH = os.path.join(settings.BASE_DIR, "scionlab",
                                           "hostfiles", "server.conf.tmpl")


def write_vpn_ca_config():
    if not os.path.exists(settings.VPN_CA_KEY_PATH):
        # generate ca private key
        password = settings.VPN_CA_KEY_PASSWORD.encode('utf-8')
        key = _generate_private_key()
        pathlib.Path(settings.VPN_CA_KEY_PATH).write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(password)
            )
        )
    else:
        key = load_ca_key()

    # Generate ca certificate
    if not os.path.exists(settings.VPN_CA_CERT_PATH):
        # create self-signed certificate
        # set issuer and subject attributes
        cert = _generate_root_ca_cert(key)
        # store the ca certificate
        pathlib.Path(settings.VPN_CA_CERT_PATH).write_bytes(
            cert.public_bytes(serialization.Encoding.PEM)
        )
    return


def load_ca_key_material():
    # get ca material
    ca_cert = load_ca_cert()
    ca_key = load_ca_key()

    return ca_key, ca_cert


def load_ca_cert():
    try:
        ca_cert_data = pathlib.Path(settings.VPN_CA_CERT_PATH).read_bytes()
        ca_cert = x509.load_pem_x509_certificate(ca_cert_data, backend=default_backend())
    except FileNotFoundError as e:
        raise RuntimeError("Missing CA root configuration. "
                           "Please run the admin command `python3 ./manage.py initialize_root_ca` "
                           "or import an existing root CA configuration.", e)
    return ca_cert


def load_ca_key():
    try:
        password = settings.VPN_CA_KEY_PASSWORD.encode('utf-8')
        ca_key_data = pathlib.Path(settings.VPN_CA_KEY_PATH).read_bytes()
        ca_key = serialization.load_pem_private_key(ca_key_data,
                                                    password=password,
                                                    backend=default_backend())
        if not isinstance(ca_key, rsa.RSAPrivateKey):
            raise TypeError
    except FileNotFoundError as e:
        raise RuntimeError("Missing CA root configuration."
                           "Please run the admin command `python3 ./manage.py initialize_root_ca`"
                           "or import an existing root CA configuration.", e)
    return ca_key


def _generate_root_ca_cert(key):
    subject = issuer = _make_name(settings.VPN_KEYGEN_CONFIG.KEY_ORG + " CA")

    # create and sign the certificate
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() +
        datetime.timedelta(days=settings.VPN_KEYGEN_CONFIG.CA_EXPIRE)
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
        critical=False,
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
        critical=False,
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=0),
        critical=True,
    ).sign(key, hashes.SHA256(), default_backend())
    return cert


def generate_vpn_server_key_material(host):
    # generate server private key
    key = _generate_private_key()

    key_decoded = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    # Generate server certificate
    # get ca material
    ca_key, ca_cert = load_ca_key_material()

    # create server certificate
    # set subject attributes
    owner_email = get_owner_email(host.AS)
    subject = _make_name(host.AS.isd_as_path_str()+"__"+host.public_ip.replace(":", "_"))
    subject_alt_name = owner_email + "__" + host.AS.isd_as_path_str()

    # create and sign the certificate
    cert = _make_cert(subject, subject_alt_name, key, ca_cert.issuer, ca_key,
                      x509.ExtendedKeyUsageOID.SERVER_AUTH)

    cert_decoded = cert.public_bytes(serialization.Encoding.PEM).decode()
    return key_decoded, cert_decoded


def generate_vpn_client_key_material(as_):
    ca_key, ca_cert = load_ca_key_material()

    # generate client key
    client_key = _generate_private_key()

    # create a certificate signed by the ca
    # set subject attributes
    owner_email = get_owner_email(as_)
    subject_common_name = owner_email+"__"+as_.isd_as_path_str()
    subject = _make_name(subject_common_name)

    # create and sign the client certificate
    client_cert = _make_cert(subject, subject_common_name, client_key, ca_cert.issuer, ca_key,
                             x509.ExtendedKeyUsageOID.CLIENT_AUTH)

    client_key_decoded = client_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
    client_cert_decoded = client_cert.public_bytes(
            encoding=serialization.Encoding.PEM).decode()
    return client_key_decoded, client_cert_decoded


def get_owner_email(as_):
    if as_.is_infrastructure_AS():
        owner_email = settings.VPN_KEYGEN_CONFIG.KEY_EMAIL
    else:
        owner_email = as_.owner.email
    return owner_email


def get_cert_common_name(cert_data):
    cert = x509.load_pem_x509_certificate(cert_data, backend=default_backend())
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(cn) != 1:
        raise ValueError("Certificate Common Name field is not unequivocal.")
    common_name = cn[0].value
    return common_name


def generate_vpn_client_config(client):
    ca_cert = load_ca_cert().public_bytes(
        encoding=serialization.Encoding.PEM).decode()
    client_config_tmpl = pathlib.Path(CLIENT_CONFIG_TEMPLATE_PATH).read_text(encoding='utf-8')
    server_public_ip = client.vpn.server.public_ip
    server_vpn_port = client.vpn.server_port
    client_config = string.Template(client_config_tmpl).substitute(
        ServerIP=server_public_ip,
        ServerPort=server_vpn_port,
        CACert=ca_cert,
        ClientCert=client.cert,
        ClientKey=client.private_key,
    )
    return client_config


def ccd_config(vpn_client):
    common_name = get_cert_common_name(vpn_client.cert.encode())
    config_string = "ifconfig-push %s %s" % (vpn_client.ip, vpn_client.vpn.vpn_subnet().netmask)
    return common_name, config_string


def generate_vpn_server_config(vpn):
    ca_cert = load_ca_cert().public_bytes(
        encoding=serialization.Encoding.PEM).decode()
    server_config_tmpl = pathlib.Path(SERVER_CONFIG_TEMPLATE_PATH).read_text(encoding='utf-8')
    server_vpn_as = vpn.server.AS.as_path_str()
    server_vpn_ip = vpn.server_vpn_ip()
    server_vpn_port = vpn.server_port
    server_vpn_subnet = vpn.vpn_subnet()
    server_vpn_start_ip, server_vpn_end_ip = vpn.vpn_subnet_min_max_client_ips()

    server_config = string.Template(server_config_tmpl).substitute(
        AS=server_vpn_as,
        ServerIP=server_vpn_ip,
        ServerPort=server_vpn_port,
        Netmask=server_vpn_subnet.netmask,
        Subnet=server_vpn_subnet,
        SubnetStart=server_vpn_start_ip,
        SubnetEnd=server_vpn_end_ip,
        CACert=ca_cert,
        ServerCert=vpn.cert,
        ServerKey=vpn.private_key,
    )
    return server_config


def _make_name(common_name):
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME,
                           settings.VPN_KEYGEN_CONFIG.KEY_COUNTRY),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,
                           settings.VPN_KEYGEN_CONFIG.KEY_PROVINCE),
        x509.NameAttribute(NameOID.LOCALITY_NAME,
                           settings.VPN_KEYGEN_CONFIG.KEY_CITY),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                           settings.VPN_KEYGEN_CONFIG.KEY_ORG),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,
                           settings.VPN_KEYGEN_CONFIG.KEY_OU),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(x509.ObjectIdentifier("2.5.4.41"),  # Name
                           settings.VPN_KEYGEN_CONFIG.KEY_NAME),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS,
                           settings.VPN_KEYGEN_CONFIG.KEY_EMAIL)
    ])


def _make_cert(subject_name, subject_alt_name, subject_key, issuer_name, issuer_key,
               extended_key_usage_oid):
    return x509.CertificateBuilder().subject_name(subject_name) \
        .issuer_name(
        issuer_name
    ).public_key(
        subject_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() +
        datetime.timedelta(days=settings.VPN_KEYGEN_CONFIG.KEY_EXPIRE)
    ).add_extension(
        x509.SubjectAlternativeName(
            [x509.DNSName(subject_alt_name)]),
        critical=False,
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
        critical=False,
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()),
        critical=False,
    ).add_extension(
        # digital_signature
        x509.KeyUsage(True, False, False, False, False, False, False, False, False),
        critical=True,
    ).add_extension(
        x509.ExtendedKeyUsage([extended_key_usage_oid]),
        critical=True,
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).sign(issuer_key, hashes.SHA256(), default_backend())


def _generate_private_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=settings.VPN_KEYGEN_CONFIG.KEY_SIZE,
        backend=default_backend()
    )
