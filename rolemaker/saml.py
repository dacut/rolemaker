#!/usr/bin/env python3
"""
SAML handler for Rolemaker.
"""

from datetime import datetime, timedelta
from logging import getLogger
from urllib.parse import unquote as url_unquote

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.primitives.serialization import (
    Encoding, load_pem_private_key, NoEncryption, PrivateFormat)
from cryptography.x509 import (
    CertificateBuilder, DNSName, load_pem_x509_certificate, Name,
    NameAttribute, random_serial_number, SubjectAlternativeName
)
from cryptography.x509.oid import NameOID
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config

log = getLogger("rolemaker.saml") # pylint: disable=invalid-name


class SAMLHandler(object):
    """
    Handle SAML functions for RoleMaker.
    """
    # SAML attribute keys
    saml_attribute_prefix = (
        "https://github.com/dacut/rolemaker/SAML/Attributes/")
    saml_username_key = saml_attribute_prefix + "Username"
    saml_groups_key = saml_attribute_prefix + "Groups"

    # X509 relative distinguished name (RDN) and shortcuts.
    x509_rdn = {
        "commonName": NameOID.COMMON_NAME,
        "countryName": NameOID.COUNTRY_NAME,
        "localityName": NameOID.LOCALITY_NAME,
        "stateOrProvinceName": NameOID.STATE_OR_PROVINCE_NAME,
        "streetAddress": NameOID.STREET_ADDRESS,
        "organizationName": NameOID.ORGANIZATION_NAME,
        "organizationalUnitName": NameOID.ORGANIZATIONAL_UNIT_NAME,
        "serialNumber": NameOID.SERIAL_NUMBER,
        "surname": NameOID.SURNAME,
        "givenName": NameOID.GIVEN_NAME,
        "title": NameOID.TITLE,
        "generationQualifier": NameOID.GENERATION_QUALIFIER,
        "x500UniqueIdentifier": NameOID.X500_UNIQUE_IDENTIFIER,
        "dnQualifier": NameOID.DN_QUALIFIER,
        "pseudonym": NameOID.PSEUDONYM,
        "userID": NameOID.USER_ID,
        "domainComponent": NameOID.DOMAIN_COMPONENT,
        "emailAddress": NameOID.EMAIL_ADDRESS,
        "jurisdictionCountryName": NameOID.JURISDICTION_COUNTRY_NAME,
        "jurisdictionLocalityName": NameOID.JURISDICTION_LOCALITY_NAME,
        "jurisdictionStateOrProvinceName": NameOID.JURISDICTION_STATE_OR_PROVINCE_NAME,
        "businessCategory": NameOID.BUSINESS_CATEGORY,
        "postalAddress": NameOID.POSTAL_ADDRESS,
        "postalCode": NameOID.POSTAL_CODE,

        "CN": NameOID.COMMON_NAME,
        "C": NameOID.COUNTRY_NAME,
        "L": NameOID.LOCALITY_NAME,
        "ST": NameOID.STATE_OR_PROVINCE_NAME,
        "O": NameOID.ORGANIZATION_NAME,
        "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
        "SN": NameOID.SURNAME,
        "GN": NameOID.GIVEN_NAME,
        "UID": NameOID.USER_ID,
        "DC": NameOID.DOMAIN_COMPONENT,
    }

    def __init__(self, parameters, crypto, acs_url_generator=None):
        super(SAMLHandler, self).__init__()
        self.parameters = parameters
        self.crypto = crypto
        self.acs_url_generator = acs_url_generator
        return

    def get_claims(self, data):
        """
        get_claims(data) -> dict

        Decodes the claims sent by the identity provider (IdP). The returned
        dict has two keys: username and groups.
        """
        authn_response = self.saml_client.parse_authn_request_response(
            data, BINDING_HTTP_POST)
        log.debug("get_claims: authn_respose=%s", authn_response)
        identity = authn_response.get_identity()
        log.debug("get_claims: identity=%s", identity)
        usernames = identity.get(self.saml_username_key, [])
        if len(usernames) != 1:
            raise ValueError("Invalid usernames: %r" % usernames)

        return {
            "username": usernames[0],
            "groups": identity.get(self.saml_groups_key, []),
        }

    @property
    def saml_metadata(self):
        """
        Return the XML document for the SAML metadata.
        """
        sp_certificate = self.get_sp_certificate()
        site_dns = self.parameters["SiteDNS"]["Value"]

        if not site_dns:
            raise ValueError("Site DNS name not configured")

        cert = sp_certificate[0]
        expiration = cert.not_valid_after.strftime("%Y-%m-%dT%H:%M:%SZ")
        cert_pem = str(cert.public_bytes(Encoding.PEM), "utf-8")
        cert_pem_lines = cert_pem.strip().split("\n")
        assert cert_pem_lines[0] == "-----BEGIN CERTIFICATE-----"
        assert cert_pem_lines[-1] == "-----END CERTIFICATE-----"

        cert_pem = "\n".join(cert_pem_lines[1:-1])
        substitutions = {
            "expiration": expiration,
            "site_dns": site_dns,
            "cert_pem": cert_pem,
        }

        return """\
<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://%(site_dns)s" validUntil="%(expiration)s">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" WantAssertionsSigned="true">
    <KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>%(cert_pem)s</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>
    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat>
    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>
    <AssertionConsumerService index="1" isDefault="true" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://%(site_dns)s/saml/sso"/>
    <AttributeConsumingService index="1">
      <ServiceName xml:lang="en">Rolemaker Single Sign-On</ServiceName>
      <RequestedAttribute isRequired="true" Name="https://github.com/dacut/rolemaker/SAML/Attributes/Groups" FriendlyName="Groups"/>
      <RequestedAttribute isRequired="true" Name="https://github.com/dacut/rolemaker/SAML/Attributes/Username" FriendlyName="Username"/>
      <RequestedAttribute isRequired="false" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.1" FriendlyName="eduPersonAffiliation"/>
      <RequestedAttribute isRequired="false" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.2" FriendlyName="eduPersonNickname"/>
      <RequestedAttribute isRequired="false" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.3" FriendlyName="eduPersonOrgDN"/>
      <RequestedAttribute isRequired="false" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.4" FriendlyName="eduPersonOrgUnitDN"/>
      <RequestedAttribute isRequired="false" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.5" FriendlyName="eduPersonPrimaryAffiliation"/>
      <RequestedAttribute isRequired="false" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" FriendlyName="eduPersonPrincipalName"/>
      <RequestedAttribute isRequired="false" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.7" FriendlyName="eduPersonEntitlement"/>
      <RequestedAttribute isRequired="false" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.8" FriendlyName="eduPersonPrimaryOrgUnitDN"/>
      <RequestedAttribute isRequired="false" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.9" FriendlyName="eduPersonScopedAffiliation"/>
      <RequestedAttribute isRequired="false" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.10" FriendlyName="eduPersonTargetedID"/>
      <RequestedAttribute isRequired="false" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.11" FriendlyName="eduPersonAssurance"/>
      <RequestedAttribute isRequired="false" Name="urn:oid:1.3.6.1.4.1.5923.1.2.1.2" FriendlyName="eduOrgHomePageURI"/>
      <RequestedAttribute isRequired="false" Name="urn:oid:1.3.6.1.4.1.5923.1.2.1.3" FriendlyName="eduOrgIdentityAuthNPolicyURI"/>
      <RequestedAttribute isRequired="false" Name="urn:oid:1.3.6.1.4.1.5923.1.2.1.4" FriendlyName="eduOrgLegalName"/>
      <RequestedAttribute isRequired="false" Name="urn:oid:1.3.6.1.4.1.5923.1.2.1.5" FriendlyName="eduOrgSuperiorURI"/>
      <RequestedAttribute isRequired="false" Name="urn:oid:1.3.6.1.4.1.5923.1.2.1.6" FriendlyName="eduOrgWhitePagesURI"/>
      <RequestedAttribute isRequired="false" Name="urn:oid:2.5.4.3" FriendlyName="cn"/>
    </AttributeConsumingService>
  </SPSSODescriptor>
</EntityDescriptor>
""" % substitutions

    @property
    def certificate_subject(self):
        """
        Return the X509 subject for the certficate.
        """
        subject_name = []
        subject = self.parameters["SPSubject"]

        if not subject:
            raise ValueError("SPSubject configuration is unset")

        for rdn in subject.split(","):
            key, value = rdn.split("=", 1)
            value = url_unquote(value).strip()

            name_oid = self.x509_rdn[key.strip()]
            subject_name.append(NameAttribute(name_oid, value))

        return Name(subject_name)

    @property
    def saml_client(self):
        """
        Return a PySAML2 client using the configuration stored for this system.
        """
        settings = {
            'accepted_time_diff': 60,
            'metadata': {
                'inline': [self.parameters["IdPMetadata"]["Value"]],
            },
            'service': {
                'sp': {
                    'endpoints': {
                        'assertion_consumer_service': [
                            (self.acs_url_generator(), BINDING_HTTP_REDIRECT),
                            (self.acs_url_generator(), BINDING_HTTP_POST),
                        ],
                    },
                    # Don't verify that the incoming requests originate from us via
                    # the built-in cache for authn request ids in pysaml2
                    'allow_unsolicited': True,
                    # Don't sign authn requests, since signed requests only make
                    # sense in a situation where you control both the SP and IdP
                    'authn_requests_signed': False,
                    'logout_requests_signed': True,
                    'want_assertions_signed': True,
                    'want_response_signed': False,
                },
            },
        }

        log.info("getting saml_config")
        sp_config = Saml2Config()
        sp_config.load(settings)
        sp_config.allow_unknown_attributes = True
        saml_client = Saml2Client(config=sp_config)
        return saml_client

    def get_sp_certificate(self, include_private_key=False):
        """
        get_sp_certificate(get_private_key=False) ->
            (Certificate, RSAPrivateKeyWithSerialization/None)

        Returns the SAML service provider (SP) certificate and corresponding
        private key, creating them if necessary.
        """
        while True:
            try:
                certificate, encrypted_private_key = self.load_certificate()
            except ValueError:
                certificate = encrypted_private_key = None

            if (certificate is not None and
                    certificate.not_valid_after > datetime.utcnow()):
                if include_private_key:
                    private_key = self.decrypt_private_key(
                        encrypted_private_key)
                else:
                    private_key = None

                return (certificate, private_key)

            # Not available; create it.
            try:
                certificate, private_key = self.generate_sp_certificate(
                    overwrite=True)

                if not include_private_key:
                    private_key = None

                return certificate, private_key
            except Exception as e: # pylint: disable=broad-except,invalid-name
                if self.parameters.persistence.is_retryable_exception(e):
                    # Try again -- someone else beat us here.
                    continue
                else:
                    raise

    def generate_sp_certificate(self, overwrite=False):
        """
        generate_sp_certificate() -> (Certificate, RSAPrivateKeyWithSerialization)

        Create a new SAML service provider (SP) certificate and corresponding
        private key.
        """
        private_key = generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend())
        public_key = private_key.public_key()

        today = datetime.today()
        yesterday = today - timedelta(1, 0, 0)
        if today.year % 4 == 0 and (
                today.year % 100 != 0 or today.year % 400 == 0):
            year_from_today = today + timedelta(366, 0, 0)
        else:
            year_from_today = today + timedelta(365, 0, 0)

        subject = self.certificate_subject

        builder = (CertificateBuilder()
                   .subject_name(subject)
                   .issuer_name(subject)
                   .not_valid_before(yesterday)
                   .not_valid_after(year_from_today)
                   .serial_number(random_serial_number())
                   .public_key(public_key))

        sans = []
        for san in self.pagerameters["SPSubjectAlternativeNames"]["Value"].split(","):
            san = san.strip()
            if san:
                sans.append(DNSName(san))

        if sans:
            builder = builder.add_extension(SubjectAlternativeName(sans), False)

        certificate = builder.sign(
            private_key=private_key, algorithm=hashes.SHA256(),
            backend=default_backend())

        encrypted_private_key = self.encrypt_private_key(private_key)

        self.save_certificate(certificate, encrypted_private_key, overwrite)
        return certificate, encrypted_private_key

    def encrypt_private_key(self, private_key):
        """
        encrypt_private_key(private_key) -> bytes

        Encrypt a private key.
        """
        private_key_bytes = private_key.private_bytes(
            Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())

        return self.crypto.encrypt(
            private_key_bytes, {"KeyType": "RSAPrivateKey"})

    def decrypt_private_key(self, encrypted_private_key):
        """
        decrypt_private_key(encrypted_private_key) -> RSAPrivateKey

        Decrypt a private key.
        """
        private_key_pem = self.crypto.decrypt(encrypted_private_key)
        return load_pem_private_key(
            private_key_pem, password=None, backend=default_backend())

    def save_certificate(self, certificate, encrypted_private_key,
                         overwrite=False):
        """
        save_certificate(certificate, encrypted_private_key, overwrite=False)

        Save the certificate to the parameters table.
        """
        certificate_pem = certificate.public_bytes(Encoding.PEM)

        if overwrite:
            expected = {}
        else:
            expected = {"Name": {"Exists": False}}

        self.parameters.persistence.put(
            key={"Name": "SPCertificate"},
            values={
                "Value": str(certificate_pem, "utf-8"),
                "PrivateKey": str(encrypted_private_key, "utf-8"),
            },
            expected=expected)

    def load_certificate(self):
        """
        load_certificate() -> (certificate, encrypted_private_key/None)

        Load the certificate and the encrypted private key for the
        certificate.
        """
        result = self.parameters.get("SPCertificate")

        certificate_pem = result["Value"]
        certificate_pem = certificate_pem.encode("utf-8")
        certificate = load_pem_x509_certificate(
            certificate_pem, backend=default_backend())

        encrypted_private_key = result["PrivateKey"]
        return (certificate, encrypted_private_key)

    def is_retryable_exception(self, exception):
        # pylint: disable=no-self-use,unused-argument
        """
        Indicates whether the specified exception indicates the operation
        should be retried.

        The default implemention always returns False. This can be overridden
        in persistence subclasses.
        """
        return False
