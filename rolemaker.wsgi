#!/usr/bin/env python
from __future__ import absolute_import, division, print_function
from os import environ
from os.path import dirname, exists
import logging
from rolemaker.server import RolemakerServer
import rolemaker.server

config_filename = environ.get("ROLEMAKER_CONFIG", "/etc/rolemaker.cfg")
config = {
    "region": "us-gov-west-1",
    "webroot": dirname(rolemaker.server.__file__) + "/web",
    "storage-prefix": "s3://cuthbert-rolemaker/",
    "create-queue-name": "rolemaker_create_role",
    "log-file": "/etc/httpd/logs/rolemaker.log",
    "log-level": "debug",
    "log-format": "%(asctime)s %(filename)s:%(lineno)d [%(levelname)s]: %(message)s",
    "profile": "",
    "session-cookie-domain": "rolemaker.cuthbert-test.net",
    "session-cookie-name": "session",
    "session-cookie-httponly": "true",
    "session-cookie-secure": "true",
    "server-name": "rolemaker.cuthbert-test.net",
    "preferred-url-scheme": "https",
    "application-root": "",
    "max-content-length": "10000000", # 10 MB
    "debug": "true",
    "testing": "true",
}

if exists(config_filename):
    with open(config_filename, "r") as fd:
        for line in fd:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            key, value = line.split("=", 1)
            config[key.strip()] = value.strip()

def to_bool(x):
    return x.lower()[:1] in ("y", "t", "1")

def empty_none(x):
    return x if x else None

logging.basicConfig(
    level=getattr(logging, config["log-level"].upper(), "DEBUG"),
    filename=config['log-file'],
    format=config['log-format'])
logging.getLogger("boto").setLevel(logging.INFO)

application = RolemakerServer(
    region=config["region"],    
    webroot=config["webroot"],
    storage_prefix=config["storage-prefix"],
    profile_name=empty_none(config["profile"]),
    create_queue_name=config["create-queue-name"])

application.config.update(
    DEBUG=to_bool(config["debug"]),
    TESTING=to_bool(config["testing"]),
    SESSION_COOKIE_DOMAIN=config["session-cookie-domain"],
    SESSION_COOKIE_NAME=config["session-cookie-name"],
    SESSION_COOKIE_HTTPONLY=to_bool(config["session-cookie-httponly"]),
    SESSION_COOKIE_SECURE=to_bool(config["session-cookie-secure"]),
    SERVER_NAME=config["server-name"],
    PREFERRED_URL_SCHEME=config["preferred-url-scheme"],
    APPLICATION_ROOT=empty_none(config["application-root"]),
    MAX_CONTENT_LENGTH=int(config["max-content-length"]),
)

@application.errorhandler(404)
def notfound(*args, **kw):
    from flask import request
    return "Yikes: %s" % (request.path,)

application.policy_model.refresh_attachable_policies()

# Local variables:
# mode: Python
# tab-width: 8
# indent-tabs-mode: nil
# End:
# vi: set expandtab tabstop=8
