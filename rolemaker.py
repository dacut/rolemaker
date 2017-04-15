#!/usr/bin/env python
from __future__ import absolute_import, print_function
from functools import wraps
from json import dumps as json_dumps
from os import environ
from os.path import dirname
from logging import getLogger
from six.moves.http_client import (
    BAD_GATEWAY, BAD_REQUEST, INTERNAL_SERVER_ERROR, NOT_FOUND, OK,
    responses as http_responses
)
from threading import local

# In Lambda, we need to manually add our directory as a site directory.
try:
    from routes import Mapper
except ImportError:
    from site import addsitedir
    addsitedir(dirname(__file__))
    from routes import Mapper

ddb_table_prefix = environ.get("DYNAMODB_TABLE_PREFIX", "")
log = getLogger("rolemaker")
request = local()
mapper = Mapper()
controllers = {}

default_headers = {
    "Cache-Control": "private",
    "Content-Type": "application/json; charset=utf-8",
}


class HTTPError(RuntimeError):
    def __init__(self, status, message=None):
        super(HTTPError, self).__init__(status, message)
        return

    @property
    def status(self):
        return self.args[0]

    @property
    def message(self):
        return self.args[1]


def make_error(status, message=None):
    if message is None:
        message = http_responses.get(status)
        if message is None:
            message = "HTTP error %s" % status

    result = {
        "Error": message,
    }

    return make_response(status, result)


def make_response(status, result):
    body = json_dumps(result)
    return {
        "body": body,
        # "contentHandling": "CONVERT_TO_BINARY",
        "headers": default_headers,
        "statusCode": status,
    }


def invoke(f, *args, **kw):
    try:
        result = f(*args, **kw)
        if not isinstance(result, dict):
            log.error("Invalid response from handler %s: %s",
                      f.__name__, result)
            raise ValueError("Invalid response returned from handler")
        return make_response(OK, result)
    except HTTPError as e:
        return make_error(e.status, e.message)
    except Exception as e:
        return make_error(INTERNAL_SERVER_ERROR)


def route(path, *args, **kw):
    def wrap(f):
        mapper.connect(f.__name__, path, controller=f.__name__, *args, **kw)
        controllers[f.__name__] = f
        return f

    return wrap

def lambda_handler(event, context):
    request.event = event
    request.path = event.get("path")
    if request.path is None:
        log.error("Event missing path field: %s", event)
        return make_error(BAD_GATEWAY)

    route = mapper.match(request.path)
    if route is None:
        log.warning("No match for path: %s", request.path)
        return make_error(NOT_FOUND)

    controller_name = route.pop("controller")
    controller = controllers[controller_name]
    return invoke(controller, **route)


@route("/accounts")
def accounts():
    return {"Accounts": []}
