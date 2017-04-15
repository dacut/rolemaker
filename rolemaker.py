#!/usr/bin/env python
from __future__ import absolute_import, print_function
import boto3
from flask import Flask, render_template, url_for
from json import dumps as json_dumps
from os import environ
from logging import DEBUG, getLogger, INFO
import requests
from six.moves.http_client import (
    BAD_GATEWAY, BAD_REQUEST, INTERNAL_SERVER_ERROR, NOT_FOUND, OK,
    responses as http_responses
)
from time import time
from uuid import uuid4

# Make Boto quieter
getLogger("botocore").setLevel(INFO)
getLogger("boto3").setLevel(INFO)

ddb_table_prefix = environ.get("DYNAMODB_TABLE_PREFIX", "Rolemaker.")
ddb = boto3.resource("dynamodb")
ddb_parameters = ddb.Table(ddb_table_prefix + "Parameters")
ddb_accounts = ddb.Table(ddb_table_prefix + "Accounts")
ddb_groups = ddb.Table(ddb_table_prefix + "Groups")

app = Flask(__name__)

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

parameters = Parameters()
app.jinja_env.globals["parameters"] = parameters
app.jinja_env.globals["getattr"] = getattr


@app.route("/", methods=["GET", "HEAD"])
@app.route("/index.html", methods=["GET", "HEAD"])
def get_index():
    parameters.refresh_if_needed()
    return render_template("index.html", url_for=url_for)

@app.route("/admin/", methods=["GET", "HEAD"])
@app.route("/admin/index.html", methods=["GET", "HEAD"])
def get_admin_index():
    parameters.refresh_if_needed()
    return render_template("admin/index.html")
