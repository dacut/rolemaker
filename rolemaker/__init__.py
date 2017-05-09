#!/usr/bin/env python3
"""
Rolemaker application.
"""
from base64 import b64decode, b64encode
from functools import partial
from json import dumps as json_dumps
from os import environ, urandom
from logging import DEBUG, Formatter, getLogger, INFO, StreamHandler
from sys import stderr
from time import gmtime, time
from uuid import uuid4

import boto3
from flask import Flask, session
from .util import url_for
from .xsrf import get_xsrf_token

def configure_logging():
    """
    Configure application logging.
    """
    root_logger = getLogger()
    root_logger.setLevel(DEBUG)
    handler = StreamHandler(stderr)
    formatter = Formatter("%(asctime)s %(filename)s:%(lineno)s %(name)s %(levelname)s: %(message)s")
    formatter.default_time_format = "%Y-%m-%dT%H:%M:%S"
    formatter.default_msec_format = "%s.%03dZ"
    formatter.converter = gmtime
    handler.setFormatter(formatter)
    root_logger.addHandler(handler)

    # Make Boto and PySAML quieter
    getLogger("botocore").setLevel(INFO)
    getLogger("boto3").setLevel(INFO)
    getLogger("saml2").setLevel(INFO)

def configure_persistence(app):
    # pylint: disable=redefined-outer-name
    """
    Configure the persistence for the application.

    Currently, this always uses DynamoDB.
    """
    from .persistence import DynamoDBPersistence

    ddb = boto3.resource("dynamodb")
    ddb_table_prefix = environ.get("DYNAMODB_TABLE_PREFIX", "Rolemaker.")
    ddb_parameters_table = ddb.Table(ddb_table_prefix + "Parameters")
    ddb_accounts_table = ddb.Table(ddb_table_prefix + "Accounts")
    ddb_groups_table = ddb.Table(ddb_table_prefix + "Groups")

    app.config["ddb_table_prefix"] = ddb_table_prefix
    app.config["ddb"] = ddb
    app.config["parameters_table"] = DynamoDBPersistence(ddb_parameters_table)
    app.config["accounts_table"] = DynamoDBPersistence(ddb_accounts_table)
    app.config["groups_table"] = DynamoDBPersistence(ddb_groups_table)
    return

def configure_encryption(app):
    # pylint: disable=redefined-outer-name
    """
    Configure encryption for the application.

    Currently, this always uses KMS.
    """
    from .encryption import KMSCrypto

    kms = boto3.client("kms")
    encryption_key_id = environ.get("ENCRYPTION_KEY_ID", "")
    app.config["crypto"] = KMSCrypto(kms, encryption_key_id)
    return

def configure_parameters(app):
    # pylint: disable=redefined-outer-name
    """
    Configure site-wide parameters object.
    """
    from .parameters import Parameters
    app.config["parameters"] = Parameters(app.config["parameters_table"])
    return

def configure_saml(app):
    # pylint: disable=redefined-outer-name
    """
    Configure SAML handler for Flask.
    """
    from .saml import SAMLHandler
    app.config["saml"] = SAMLHandler(
        app.config["parameters"], app.config["crypto"])

def configure_flask(app):
    # pylint: disable=redefined-outer-name
    """
    Configure Flask-specific details for the application.
    """
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 5
    app.config["DEBUG"] = True

    crypto = app.config["crypto"]
    params = app.config["parameters"]

    # Jijna globals
    app.jinja_env.globals["parameters"] = params
    app.jinja_env.globals["getattr"] = getattr
    app.jinja_env.globals["session"] = session
    app.jinja_env.globals["get_xsrf_token"] = get_xsrf_token

    # Configure the secret key
    enc_context = {"KeyType": "FlaskSecretKey"}

    while True:
        encrypted_secret_key = params.get("SecretKey", {}).get("Value")
        if encrypted_secret_key is not None:
            app.secret_key = crypto.decrypt(encrypted_secret_key, enc_context)
            break

        # No secret key available -- generate one, but don't replace one if
        # we encounter a race with another thread.
        secret_key = urandom(16)
        ciphertext = crypto.encrypt(secret_key, enc_context)

        try:
            params.safe_set("SecretKey", ciphertext)
        except Exception as e: # pylint: disable=broad-except,invalid-name
            if params.persistence.is_condition_failed_exception(e):
                # Try again -- someone else beat us here.
                continue

        app.secret_key = secret_key
        break

    return

def configure_views(app):
    """
    Configure view handlers for Rolemaker.
    """
    # pylint: disable=redefined-outer-name
    from . import view
    from .view import admin
    from .view import saml

    app.add_url_rule("/", "get_index", view.get_index, methods=["GET", "POST"])
    app.add_url_rule("/logout", "logout", view.logout, methods=["GET", "POST"])

    app.register_blueprint(admin.blueprint, url_prefix="/admin")
    app.register_blueprint(saml.blueprint, url_prefix="/saml")


    app.config["saml"].acs_url_generator = partial(
        url_for, "saml.idp_initiated")

    return

app = Flask(__name__, static_folder="../static",
            template_folder="../templates") # pylint: disable=invalid-name
configure_logging()
configure_persistence(app)
configure_encryption(app)
configure_parameters(app)
configure_saml(app)
configure_flask(app)
configure_views(app)
log = getLogger("rolemaker") # pylint: disable=invalid-name
