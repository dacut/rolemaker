#!/usr/bin/env python2.7
from __future__ import absolute_import, print_function
import boto3
from json import dumps as json_dumps
from logging import getLogger, DEBUG
import requests
from uuid import uuid4

log = getLogger()
log.setLevel(DEBUG)

def lambda_handler(event, context):
    global handlers

    log.debug("event=%s", event)

    body = {
        "Status": "FAILED",
        "Reason": "Unknown error",
        "StackId": event["StackId"],
        "RequestId": event["RequestId"],
        "LogicalResourceId": event["LogicalResourceId"],
    }

    if "PhysicalResourceId" in event:
        body["PhysicalResourceId"] = event["PhysicalResourceId"]

    handler = handlers.get(event["ResourceType"])
    if handler is None:
        body["Reason"] = "Unknown resource type %s" % event["ResourceType"]
    else:
        try:
            data = handler(event)
            if data is None:
                data = {}
            if "PhysicalResourceId" in data:
                body["PhysicalResourceId"] = data.pop("PhysicalResourceId")
            body["Status"] = "SUCCESS"
            del body["Reason"]
            body["Data"] = data
        except Exception as e:
            body["Reason"] = str(e)

    if "PhysicalResourceId" not in body:
        body["PhysicalResourceId"] = str(uuid4())

    log.debug("body=%s", body)
    body = json_dumps(body)
    headers = {
        "Content-Type": "",
        "Content-Length": str(len(body)),
    }
    r = requests.put(event["ResponseURL"], headers=headers, data=body)
    print("Result: %d %s" % (r.status_code, r.reason))
    return

def api_gateway_binary(event):
    if event["RequestType"] not in ("Create", "Update"):
        return

    apigw = boto3.client("apigateway")
    rest_api_id = event["ResourceProperties"]["RestApiId"]

    # Do we already have binary support enabled?
    rest_api_info = apigw.get_rest_api(restApiId=rest_api_id)

    if ("binaryMediaTypes" not in rest_api_info or
        "*/*" not in rest_api_info["binaryMediaTypes"]):
        apigw.update_rest_api(restApiId=rest_api_id, patchOperations=[
            {"op": "add", "path": "/binaryMediaTypes/*~1*"}
        ])

    return

handlers = {
    "Custom::ApiGatewayBinary": api_gateway_binary,
}
