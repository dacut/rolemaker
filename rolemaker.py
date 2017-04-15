#!/usr/bin/env python
from __future__ import absolute_import, print_function
import boto3
from flask import Flask, render_template, url_for
from json import dumps as json_dumps
from os import environ
import requests
from six.moves.http_client import (
    BAD_GATEWAY, BAD_REQUEST, INTERNAL_SERVER_ERROR, NOT_FOUND, OK,
    responses as http_responses
)
from uuid import uuid4

ddb_table_prefix = environ.get("DYNAMODB_TABLE_PREFIX", "Rolemaker.")
ddb = boto3.resource("dynamodb")
ddb_parameters = ddb.Table(ddb_table_prefix + "Parameters")
ddb_accounts = ddb.Table(ddb_table_prefix + "Accounts")
ddb_groups = ddb.Table(ddb_table_prefix + "Groups")

app = Flask(__name__)

@app.route("/", methods=["GET", "HEAD"])
@app.route("/index.html", methods=["GET", "HEAD"])
def get_index():
    return render_template("index.html")

@app.route("/admin/", methods=["GET", "HEAD"])
@app.route("/admin/index.html", methods=["GET", "HEAD"])
def get_admin_index():
    return render_template("admin/index.html")
