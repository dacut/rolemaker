#!/usr/bin/env python
from __future__ import absolute_import, print_function
from base64 import b64decode, b64encode
import boto3
from botocore.exceptions import ClientError
from flask import (
    flash, Flask, make_response, render_template, request, session, url_for
)
from json import dumps as json_dumps
from os import environ, urandom
from logging import DEBUG, getLogger, INFO
from passlib.hash import pbkdf2_sha256
import requests
from six.moves.http_client import (
    BAD_GATEWAY, BAD_REQUEST, FORBIDDEN, INTERNAL_SERVER_ERROR, NOT_FOUND, OK,
    UNAUTHORIZED
)
from time import time
from uuid import uuid4

# Make Boto quieter
getLogger("botocore").setLevel(INFO)
getLogger("boto3").setLevel(INFO)

ddb_table_prefix = environ.get("DYNAMODB_TABLE_PREFIX", "Rolemaker.")
encryption_key_id = environ.get("ENCRYPTION_KEY_ID", "")
ddb = boto3.resource("dynamodb")
ddb_parameters = ddb.Table(ddb_table_prefix + "Parameters")
ddb_accounts = ddb.Table(ddb_table_prefix + "Accounts")
ddb_groups = ddb.Table(ddb_table_prefix + "Groups")

kms = boto3.client("kms")

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 5

def get_secret_key():
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
        self.refresh()
        return

    def refresh(self):
        for item in ddb_parameters.scan().get("Items", []):
            setattr(self, item["Name"], item["Value"])
        self._next_refresh_time = time() + self.cache_time
        return

    def refresh_if_needed(self):
        if self.refresh_needed:
            self.refresh()

    @property
    def refresh_needed(self):
        return time() > self._next_refresh_time


def get_xsrf_token():
    if "xsrf_token" not in session:
        session["xsrf_token"] = b64encode(urandom(18))

    return session["xsrf_token"]


def xsrf_ok():
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
    parameters.refresh()
    password_hash = getattr(parameters, "AdminPasswordHash", None)
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
        session.is_admin = True
        status = OK
    else:
        flash("Incorrect password.", category="error")
        status = UNAUTHORIZED

    return make_response(render_template("admin/index.html"), status)
