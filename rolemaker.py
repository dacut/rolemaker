#!/usr/bin/env python3
from base64 import b64decode, b64encode
import boto3
from botocore.exceptions import ClientError
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat)
from cryptography.x509 import (
    CertificateBuilder, DNSName, load_pem_x509_certificate, Name,
    NameAttribute, random_serial_number, SubjectAlternativeName
)
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
from flask import (
    flash, Flask, make_response, redirect, render_template, request, session,
    url_for as flask_url_for
)
from http.client import (
    BAD_GATEWAY, BAD_REQUEST, FORBIDDEN, INTERNAL_SERVER_ERROR, NOT_FOUND, OK,
    SERVICE_UNAVAILABLE, UNAUTHORIZED
)
from json import dumps as json_dumps
from os import environ, urandom
from logging import DEBUG, Formatter, getLogger, INFO, StreamHandler
from markupsafe import escape as escape_html
from passlib.hash import pbkdf2_sha256
import requests
from requests.exceptions import RequestException
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config
from sys import stderr
from time import gmtime, time
from urllib.parse import unquote as url_unquote
from uuid import uuid4

# Configure application logging early on.
rootLogger = getLogger()
log = getLogger("rolemaker")
rootLogger.setLevel(DEBUG)
handler = StreamHandler(stderr)
formatter = Formatter("%(asctime)s %(filename)s:%(lineno)s %(name)s %(levelname)s: %(message)s")
formatter.default_time_format = "%Y-%m-%dT%H:%M:%S"
formatter.default_msec_format = "%s.%03dZ"
formatter.converter = gmtime
handler.setFormatter(formatter)
rootLogger.addHandler(handler)
log.info("Starting initialization")

# Force URL rewrites to use https
def url_for(*args, **kw):
    return flask_url_for(*args, _scheme="https", _external="True", **kw)

# Make Boto quieter
getLogger("botocore").setLevel(INFO)
getLogger("boto3").setLevel(INFO)

# DynamoDB handles
ddb_table_prefix = environ.get("DYNAMODB_TABLE_PREFIX", "Rolemaker.")
encryption_key_id = environ.get("ENCRYPTION_KEY_ID", "")
ddb = boto3.resource("dynamodb")
ddb_parameters = ddb.Table(ddb_table_prefix + "Parameters")
ddb_accounts = ddb.Table(ddb_table_prefix + "Accounts")
ddb_groups = ddb.Table(ddb_table_prefix + "Groups")

# Key Management Service (KMS) handle
kms = boto3.client("kms")

# Our main flask application
app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 5
app.config["DEBUG"] = True

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


def get_secret_key():
    """
    get_secret_key() -> str

    Return the secret key for Flask sessions, creating it if necessary.

    If the secret key doesn't already exist in the DynamoDB Parameters table,
    it is generated automatically (in a way that protects against race
    conditions).
    """
    enc_context = {"KeyType": "FlaskSecretKey"}

    while True:
        result = ddb_parameters.get_item(
            Key={"Name": "SecretKey"}, ConsistentRead=True)
        item = result.get("Item")
        if item is not None:
            return kms.decrypt(
                CiphertextBlob=b64decode(item["Value"]),
                EncryptionContext=enc_context)["Plaintext"]

        # No secret key available -- generate one, but don't replace one if
        # we encounter a race with another thread.
        secret_key = urandom(16)
        encrypt_response = kms.encrypt(
            KeyId=encryption_key_id, Plaintext=secret_key,
            EncryptionContext=enc_context)
        ciphertext_blob = b64encode(encrypt_response["CiphertextBlob"])

        try:
            ddb_parameters.put_item(
                Item={"Name": "SecretKey", "Value": ciphertext_blob},
                Expected={"Name": {"Exists": False}})
            return secret_key
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code")
            if error_code != "ConditionalCheckFailedException":
                raise

        # Try again -- someone else beat us here.
        continue

app.secret_key = get_secret_key()


class Parameters(object):
    """
    Site-parameters, used on every page render. This is heavily cached to
    avoid overloading DynamoDB.
    """
    cache_time = 300

    def __init__(self):
        super(Parameters, self).__init__()
        self._next_refresh_time = 0
        self._items = {}
        self.refresh()
        return

    def refresh(self):
        self._items = {}
        for item in ddb_parameters.scan(ConsistentRead=True).get("Items", []):
            self._items[item["Name"]] = item["Value"]
        self._next_refresh_time = time() + self.cache_time
        return

    def refresh_if_needed(self):
        if self.refresh_needed:
            self.refresh()

    @property
    def refresh_needed(self):
        return time() > self._next_refresh_time

    def get(self, name, default=None):
        return self._items.get(name, default)

    def __getitem__(self, name):
        return self._items.get(name, "")

    def __setitem__(self, name, value):
        if not session.get("is_admin"):
            return

        if not value:
            del self[name]
        else:
            ddb_parameters.put_item(Item={"Name": name, "Value": value})
            self._items[name] = value
        return

    def __delitem__(self, name):
        ddb_parameters.delete_item(Key={"Name": name})
        try: del self._items[name]
        except KeyError: pass
        return


def get_xsrf_token():
    """
    get_xsrf_token() -> str

    Return the cross site request forgery (XSRF) token for the current
    session, generating it and setting it in the session cookie if necessary.
    """
    if "xsrf_token" not in session:
        session["xsrf_token"] = str(b64encode(urandom(18)))

    return session["xsrf_token"]


def xsrf_ok():
    """
    xsrf_ok() -> bool

    Indicates whether the cross stie request forgery (XSRF) token for the
    form matched that of the session cookie.
    """
    form_xsrf = request.form.get("xsrf")
    session_xsrf = get_xsrf_token()
    return form_xsrf == session_xsrf


parameters = Parameters()
app.jinja_env.globals["parameters"] = parameters
app.jinja_env.globals["getattr"] = getattr
app.jinja_env.globals["session"] = session
app.jinja_env.globals["get_xsrf_token"] = get_xsrf_token


@app.route("/", methods=["GET", "HEAD"])
def get_index():
    parameters.refresh_if_needed()
    return render_template("index.html", url_for=url_for)


@app.route("/admin", methods=["GET", "HEAD"])
def get_admin_index():
    parameters.refresh_if_needed()
    return render_template("admin/index.html")


@app.route("/admin", methods=["POST"])
def post_admin_index():
    action = request.form.get("action")
    if action == "initial-admin-login":
        return initial_admin_login()
    elif action == "site-config":
        return update_site_config()
    elif action == "auth-config":
        return update_auth_config()

    flash("Unknown form submitted.", category="error")
    return make_response(render_template("admin/index.html"), BAD_REQUEST)


def get_sp_certificate(get_private_key=False):
    """
    get_sp_certificate(get_private_key=False) -> (Certificate, RSAPrivateKeyWithSerialization/None)

    Returns the SAML service provider (SP) certificate and corresponding
    private key, creating them if necessary.
    """
    enc_context = {"KeyType": "RSAPrivateKey"}
    proj_expr = "#V,PrivateKey" if get_private_key else "#V"

    while True:
        result = ddb_parameters.get_item(
            Key={"Name": "SPCertificate"}, ConsistentRead=True,
            ProjectionExpression=proj_expr,
            ExpressionAttributeNames={"#V": "Value"})
        item = result.get("Item")
        if item is not None:
            certificate_pem = item["Value"]
            certificate_pem = certificate_pem.encode("utf-8")
            log.debug("Certificate:\n%s", certificate_pem)
            certificate = load_pem_x509_certificate(
                certificate_pem, backend=default_backend())

            if certificate.not_valid_after > datetime.utcnow():
                if get_private_key:
                    private_key_pem = kms.decrypt(
                        CiphertextBlob=b64decode(item["PrivateKey"]),
                        EncryptionContext=enc_context)
                    private_key = load_pem_private_key(
                        private_key_pem, password=None, backend=default_backend())
                else:
                    private_key = None

                return (certificate, private_key)
            else:
                # Certificate is no longer valid; delete it.
                try:
                    ddb_parameters.delete_item(
                        Key={"Name": "SPCertificate"},
                        Expected={
                            "#V": {"Value": item["Value"]},
                            "PrivateKey": {"Value": item["PrivateKey"]}})
                except ClientError as e:
                    # Someone recreated it while we tried to delete it?
                    error_code = e.response.get("Error", {}).get("Code")
                    if error_code != "ConditionalCheckFailedException":
                        raise

                    # Try to read it again.
                    continue

        # Not available; create it.
        try:
            certificate, private_key = generate_sp_certificate(
                expected={"Name": {"Exists": False}})

            if not get_private_key:
                private_key = None

            return certificate, private_key
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code")
            if error_code != "ConditionalCheckFailedException":
                raise

            # Try again -- someone else beat us here.
            continue


def generate_sp_certificate(expected=None):
    """
    generate_sp_certificate() -> (Certificate, RSAPrivateKeyWithSerialization)

    Create a new SAML service provider (SP) certificate and corresponding
    private key.
    """
    private_key = generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    enc_context = {"KeyType": "RSAPrivateKey"}

    subject_name = []
    subject = parameters["SPSubject"]

    if not subject:
        raise ValueError("Cannot generate SAML SP certificate: SPSubject "
                         "configuration is unset")

    for rdn in subject.split(","):
        key, value = rdn.split("=", 1)
        value = url_unquote(value).strip()

        name_oid = x509_rdn[key.strip()]
        subject_name.append(NameAttribute(name_oid, value))

    subject_name = Name(subject_name)

    today = datetime.today()
    yesterday = today - timedelta(1, 0, 0)
    if today.year % 4 == 0 and (
        today.year % 100 != 0 or today.year % 400 == 0):
        year_from_today = today + timedelta(366, 0, 0)
    else:
        year_from_today = today + timedelta(365, 0, 0)

    builder = (CertificateBuilder()
                .subject_name(subject_name)
                .issuer_name(subject_name)
                .not_valid_before(yesterday)
                .not_valid_after(year_from_today)
                .serial_number(random_serial_number())
                .public_key(public_key))

    sans = []
    for san in parameters["SPSubjectAlternativeNames"].split(","):
        san = san.strip()
        if san:
            sans.append(DNSName(san))

    if sans:
        builder = builder.add_extension(SubjectAlternativeName(sans), False)

    certificate = builder.sign(
        private_key=private_key, algorithm=hashes.SHA256(),
        backend=default_backend())

    certificate_pem = certificate.public_bytes(Encoding.PEM)

    private_key_bytes = private_key.private_bytes(
        Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())
    encrypt_response = kms.encrypt(
        KeyId=encryption_key_id, Plaintext=private_key_bytes,
        EncryptionContext=enc_context)
    ciphertext_blob = b64encode(encrypt_response["CiphertextBlob"])

    ddb_kw = {"Expected": expected} if expected is not None else {}

    ddb_parameters.put_item(
        Item={
            "Name": "SPCertificate",
            "Value": str(certificate_pem),
            "PrivateKey": str(ciphertext_blob),
        },
        **ddb_kw)

    return certificate, private_key


def initial_admin_login():
    parameters.refresh()
    password_hash = parameters["AdminPasswordHash"]
    password = request.form.get("password")

    if not xsrf_ok():
        flash("Form expired. Please try again.", category="error")
        status = BAD_REQUEST
    elif not password:
        flash("Password cannot be empty.", category="error")
        status = UNAUTHORIZED
    elif not password_hash:
        flash("This Rolemaker deployment has already been configured.",
              category="error")
        status = FORBIDDEN
    elif pbkdf2_sha256.verify(password, password_hash):
        session["is_admin"] = True
        status = OK
    else:
        flash("Incorrect password.", category="error")
        status = UNAUTHORIZED

    return make_response(render_template("admin/index.html"), status)


def update_site_config():
    """
    This is invoked when new site configuration information is POSTed.
    """
    parameters.refresh_if_needed()
    site_dns = request.form.get("site-dns", "")
    updates = {}
    errors = []

    if site_dns != parameters["SiteDNS"]:
        updates["SiteDNS"] = site_dns

    if not errors:
        for key, value in updates.items():
            parameters[key] = value
        flash("Site configuration updated", category="info")
    else:
        for error in errors:
            flash(error, category="error")

    return redirect(url_for("get_admin_index"))


def update_auth_config():
    """
    This is invoked when new site authentication configuration information is
    POSTed.
    """
    parameters.refresh_if_needed()
    idp_metadata_url = request.form.get("idp-metadata-url", "").strip()
    sp_certificate_subject = (
        request.form.get("sp-certificate-subject", "").strip())
    sp_subject_alternative_names = (
        request.form.get("sp-subject-alternative-names").strip())
    updates = {}
    errors = []

    if idp_metadata_url != parameters["IdPMetadataURL"]:
        try:
            idp_metadata = get_idp_metadata(idp_metadata_url, errors)
            updates["IdPMetadataURL"] = idp_metadata_url
            updates["IdPMetadata"] = idp_metadata
        except RequestException as e:
            errors.append(
                "Unable to read SAML metadata from %s: %s" %
                (escape_html(idp_metadata_url), escape_html(str(e))))

    if sp_certificate_subject != parameters["SPSubject"]:
        if not sp_certificate_subject:
            errors.append("SAML SP certificate subject cannot be empty")
        else:
            updates["SPSubject"] = sp_certificate_subject

    if sp_subject_alternative_names != parameters["SPSubjectAlternativeNames"]:
        updates["SPSubjectAlternativeNames"] = sp_subject_alternative_names

    if not errors:
        for key, value in updates.items():
            parameters[key] = value

        # Force a certificate renewal if we've updated the certificate subject.
        if "SPSubject" in updates or "SPSubjectAlternativeNames" in updates:
            generate_sp_certificate()

        flash("Site authentication configuration updated", category="info")
    else:
        for error in errors:
            flash(error, category="error")

    return redirect(url_for("get_admin_index"))


def get_idp_metadata(idp_metadata_url, errors):
    r = requests.get(idp_metadata_url)
    if r.status_code != OK:
        errors.append(
            "Unable to read SAML metadata from %s: HTTP error %s: %s" %
            (escape_html(idp_metadata_url),
             escape_html(str(r.status_code)),
             escape_html(str(r.reason))))

    return r.text


def get_saml_client():
    acs_url = url_for("idp_initiated", _external=True)
    https_acs_url = url_for("idp_initiated", _external=True, _scheme='https')

    return {
        'metadata': {
            'inline': parameters["IdPMetadata"],
            },
        'service': {
            'sp': {
                'endpoints': {
                    'assertion_consumer_service': [
                        (acs_url, BINDING_HTTP_REDIRECT),
                        (acs_url, BINDING_HTTP_POST),
                        (https_acs_url, BINDING_HTTP_REDIRECT),
                        (https_acs_url, BINDING_HTTP_POST)
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

    spConfig = Saml2Config()
    spConfig.load(settings)
    spConfig.allow_unknown_attributes = True
    saml_client = Saml2Client(config=spConfig)
    return saml_client


@app.route("/saml/sso", methods=["POST"])
def idp_initiated():
    return None


@app.route("/saml/metadata.xml", methods=["GET"])
def get_saml_metadata():
    sp_certificate = get_sp_certificate()

    site_dns = parameters["SiteDNS"]
    if not site_dns:
        return make_response(
            ("Site DNS name not configured", SERVICE_UNAVAILABLE,
             {"Content-Type": "text/plain; charset=utf-8"})
        )

    cert = get_sp_certificate()[0]
    expiration = cert.not_valid_after.strftime("%Y-%m-%dT%H:%M:%SZ")
    cert_pem_lines = cert.public_bytes(Encoding.PEM).strip().split("\n")
    assert cert_pem_lines[0] == "-----BEGIN CERTIFICATE-----"
    assert cert_pem_lines[-1] == "-----END CERTIFICATE-----"

    cert_pem = "\n".join(cert_pem_lines[1:-1])

    doc = """\
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
      <RequestedAttribute isRequired="true" Name="https://github.com/dacut/rolemaker/SAML/Attributes/AWSAccountEntitlement" FriendlyName="AWSAccountEntitlement"/>
      <RequestedAttribute isRequired="true" Name="https://github.com/dacut/rolemaker/SAML/Attributes/SessionName" FriendlyName="SessionName"/>
      <RequestedAttribute isRequired="false" Name="https://github.com/dacut/rolemaker/SAML/Attributes/RolemakerEntitlement" FriendlyName="RolemakerEntitlement"/>
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
""" % {
        "expiration": expiration,
        "site_dns": site_dns,
        "cert_pem": cert_pem,
    }

    return make_response((doc, OK, {"Content-Type": "text/xml; charset=utf-8"}))


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("get_index"))
