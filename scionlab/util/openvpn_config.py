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

import configparser
import datetime
import os

from django.conf import settings

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh, rsa

from scionlab.settings.common import BASE_DIR, SECRET_KEY


def write_vpn_ca_config(self):
    x509_config_file = os.path.join(BASE_DIR, 'scionlab', 'settings', 'x509_cert.default')
    x509_config = configparser.ConfigParser(converters={
        'string': lambda e: str(e).replace('"', '')}
    )
    x509_config.read(x509_config_file)

    ca_key_file = "%s_cakey.pem" % self.path_str()
    ca_key_path = os.path.join(BASE_DIR, 'run', ca_key_file)
    if not os.path.exists(ca_key_path):
        # generate ca private key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=x509_config['x509_config'].getint('KEY_SIZE'),
            backend=default_backend()
        )
        with open(ca_key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(
                    SECRET_KEY.encode('utf-8'))
            ))
    else:
        with open(ca_key_path, "rb") as f:
            key_data = f.read()
            key = serialization.load_pem_private_key(key_data,
                                                     password=SECRET_KEY.encode('utf-8'),
                                                     backend=default_backend())
            if not isinstance(key, rsa.RSAPrivateKey):
                raise TypeError

    # Generate ca certificate
    ca_cert_file = "%s_cacert.pem" % self.path_str()
    ca_cert_path = os.path.join(BASE_DIR, 'run', ca_cert_file)
    if not os.path.exists(ca_cert_path):
        # create self-signed certificate
        # set issuer and subject attributes
        cname_props = "/name=%s/emailAddress=%s" % (
            x509_config['x509_config'].getstring('KEY_NAME'),
            x509_config['x509_config'].getstring('KEY_EMAIL'))
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME,
                               x509_config['x509_config'].getstring('KEY_COUNTRY')),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,
                               x509_config['x509_config'].getstring('KEY_PROVINCE')),
            x509.NameAttribute(NameOID.LOCALITY_NAME,
                               x509_config['x509_config'].getstring('KEY_CITY')),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                               x509_config['x509_config'].getstring('KEY_ORG')),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,
                               x509_config['x509_config'].getstring('KEY_OU')),
            x509.NameAttribute(NameOID.COMMON_NAME,
                               x509_config['x509_config'].getstring('KEY_ORG') + " CA" +
                               cname_props)
        ])

        # create and sign the certificate
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() +
            datetime.timedelta(days=x509_config['x509_config'].getint('CA_EXPIRE'))
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

        # store the ca certificate
        with open(ca_cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
    return


def write_vpn_server_config(self):
    x509_config_file = os.path.join(BASE_DIR, 'scionlab', 'settings', 'x509_cert.default')
    x509_config = configparser.ConfigParser(
        converters={'string': lambda e: str(e).replace('"', '')}
    )
    x509_config.read(x509_config_file)

    key_file = "%s_key.pem" % self.path_str()
    key_path = os.path.join(BASE_DIR, 'run', key_file)
    if not os.path.exists(key_path):
        # generate server private key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=x509_config['x509_config'].getint('KEY_SIZE'),
            backend=default_backend()
        )
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(
                    SECRET_KEY.encode('utf-8'))
            ))
    else:
        with open(key_path, "rb") as f:
            key_data = f.read()
            key = serialization.load_pem_private_key(key_data,
                                                     password=SECRET_KEY.encode('utf-8'),
                                                     backend=default_backend())
            if not isinstance(key, rsa.RSAPrivateKey):
                raise TypeError

    # Generate Diffie Hellman parameters
    dh_param_file = "%s_dh4096.pem" % self.path_str()
    dh_param_path = os.path.join(BASE_DIR, 'run', dh_param_file)
    if not os.path.exists(dh_param_path):
        with open(dh_param_path, "wb") as f:
            dh_parameters = dh.generate_parameters(generator=2, key_size=4096,
                                                   backend=default_backend())
            f.write(dh_parameters.parameter_bytes(serialization.Encoding.PEM,
                                                  serialization.ParameterFormat.PKCS3))

    # Generate server certificate
    cert_file = "%s_cert.pem" % self.path_str()
    cert_path = os.path.join(BASE_DIR, 'run', cert_file)
    if not os.path.exists(cert_path):
        # get ca material
        ca_cert_file = "%s_cacert.pem" % self.path_str()
        ca_cert_path = os.path.join(BASE_DIR, 'run', ca_cert_file)
        if not os.path.exists(ca_cert_path):
            self.write_vpn_ca_config()
        with open(ca_cert_path, 'rb') as f:
            ca_cert_data = f.read()
            ca_cert = x509.load_pem_x509_certificate(ca_cert_data, backend=default_backend())

        issuer = ca_cert.issuer

        ca_key_file = "%s_cakey.pem" % self.path_str()
        ca_key_path = os.path.join(BASE_DIR, 'run', ca_key_file)
        with open(ca_key_path, "rb") as f:
            ca_key_data = f.read()
            ca_key = serialization.load_pem_private_key(ca_key_data,
                                                        password=SECRET_KEY.encode('utf-8'),
                                                        backend=default_backend())
            if not isinstance(ca_key, rsa.RSAPrivateKey):
                raise TypeError

        # create server certificate
        # set subject attributes
        cname_props = "/name=%s/emailAddress=%s" % (
            x509_config['x509_config'].getstring('KEY_NAME'),
            x509_config['x509_config'].getstring('KEY_EMAIL'))
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME,
                               x509_config['x509_config'].getstring('KEY_COUNTRY')),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,
                               x509_config['x509_config'].getstring('KEY_PROVINCE')),
            x509.NameAttribute(NameOID.LOCALITY_NAME,
                               x509_config['x509_config'].getstring('KEY_CITY')),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                               x509_config['x509_config'].getstring('KEY_ORG')),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,
                               x509_config['x509_config'].getstring('KEY_OU')),
            x509.NameAttribute(NameOID.COMMON_NAME,
                               self.AS.isd_as_path_str() + "__" + self.public_ip.replace(":", "_") +
                               cname_props)
        ])

        # create and sign the certificate
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() +
            datetime.timedelta(days=x509_config['x509_config'].getint('KEY_EXPIRE'))
        ).add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(self.AS.owner.email + "__" + self.AS.isd_as_path_str())]),
            critical=False,
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        ).add_extension(
            # digital_signature
            x509.KeyUsage(True, False, False, False, False, False, False, False, False),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=True,
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).sign(ca_key, hashes.SHA256(), default_backend())

        # store the ca certificate
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
    return


def write_vpn_client_config(self):
    x509_config_file = os.path.join(BASE_DIR, 'scionlab', 'settings', 'x509_cert.default')
    x509_config = configparser.ConfigParser(
        converters={'string': lambda e: str(e).replace('"', '')}
    )
    x509_config.read(x509_config_file)

    client_config_file = "%s_client.config" % self.path_str()
    client_config_path = os.path.join(BASE_DIR, 'run', client_config_file)
    if not os.path.exists(client_config_path):
        # get ca material
        ca_cert_file = "%s_cacert.pem" % self.path_str()
        ca_cert_path = os.path.join(BASE_DIR, 'run', ca_cert_file)
        with open(ca_cert_path, 'rb') as f:
            ca_cert_data = f.read()
            ca_cert = x509.load_pem_x509_certificate(ca_cert_data, backend=default_backend())

        issuer = ca_cert.issuer

        ca_key_file = "%s_cakey.pem" % self.path_str()
        ca_key_path = os.path.join(BASE_DIR, 'run', ca_key_file)
        with open(ca_key_path, "rb") as f:
            ca_key_data = f.read()
            ca_key = serialization.load_pem_private_key(ca_key_data,
                                                        password=SECRET_KEY.encode('utf-8'),
                                                        backend=default_backend())
            if not isinstance(ca_key, rsa.RSAPrivateKey):
                raise TypeError

        # generate client key
        client_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=x509_config['x509_config'].getint('KEY_SIZE'),
            backend=default_backend()
        )
        # create a certificate signed by the ca
        # set subject attributes
        cname_props = "/name=%s/emailAddress=%s" % (
            x509_config['x509_config'].getstring('KEY_NAME'),
            x509_config['x509_config'].getstring('KEY_EMAIL'))
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME,
                               x509_config['x509_config'].getstring('KEY_COUNTRY')),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,
                               x509_config['x509_config'].getstring('KEY_PROVINCE')),
            x509.NameAttribute(NameOID.LOCALITY_NAME,
                               x509_config['x509_config'].getstring('KEY_CITY')),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                               x509_config['x509_config'].getstring('KEY_ORG')),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,
                               x509_config['x509_config'].getstring('KEY_OU')),
            x509.NameAttribute(NameOID.COMMON_NAME,
                               self.AS.owner.email + "__" + self.AS.isd_as_path_str() + cname_props)
        ])

        # create and sign the client certificate
        client_cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer). \
            public_key(
            client_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() +
            datetime.timedelta(days=x509_config['x509_config'].getint('KEY_EXPIRE'))
        ).add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(self.AS.owner.email + "__" + self.AS.isd_as_path_str())]),
            critical=False,
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(client_key.public_key()),
            critical=False,
        ).add_extension(
            # digital_signature
            x509.KeyUsage(True, False, False, False, False, False, False, False, False),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=True,
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).sign(ca_key, hashes.SHA256(), default_backend())

        client_config_template = os.path.join(settings.BASE_DIR, "scionlab",
                                              "hostfiles", "client.conf.tmpl")
        with open(client_config_template, 'r', encoding='utf-8') as f:
            client_config = f.read()
            server_vpn_ip = self.AS.attachment_point_info.vpn.server_vpn_ip()
            client_config = client_config.replace("{{.ServerIP}}", str(server_vpn_ip))
            server_vpn_port = self.AS.attachment_point_info.vpn.server_port
            client_config = client_config.replace("{{.ServerPort}}", str(server_vpn_port))
            client_config = client_config.replace("{{.CACert}}", ca_cert.public_bytes(
                encoding=serialization.Encoding.PEM).decode())
            client_config = client_config.replace("{{.ClientCert}}", client_cert.public_bytes(
                encoding=serialization.Encoding.PEM).decode())
            client_config = client_config.replace("{{.ClientKey}}", client_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode())

        with open(client_config_path, 'w') as f:
            f.write(client_config)
    return
