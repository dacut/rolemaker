#!/usr/bin/env python3.6
"""
Simplified per-account Rolemaker installation using native AWS authentication
and authorization.
"""
# pylint: disable=C0103
from logging import Formatter, getLogger, DEBUG, INFO
from http.client import HTTPResponse
from json import dumps as json_dumps, loads as json_loads
from os import environ
from typing import Any, cast, Dict, Set
from urllib.request import Request, urlopen
from uuid import uuid4

import boto3
from botocore.exceptions import ClientError as BotoClientError

# Enable debug logging
log = getLogger()
log.setLevel(DEBUG)
log.handlers[0].setFormatter(Formatter(
    "%(asctime)s %(name)s [%(levelname)s] %(filename)s:%(lineno)d: %(message)s"
))

# Undo verbose logging on Boto
getLogger("botocore").setLevel(INFO)
getLogger("boto3").setLevel(INFO)

# Handle to the IAM service.
iam = boto3.client("iam")

# This is a policy document that does not grant any permissions.
ASSUME_ROLE_POLICY_NOOP = json_dumps({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Deny",
            "Action": "sts:AssumeRole",
            "Principal": {"Service": "ec2.amazonaws.com"},
        }
    ]
})

class RolemakerError(RuntimeError):
    """
    Exception class signifying a user error in calling Rolemaker (vs. a bug
    in Rolemaker) itself.
    """
    pass

class CustomResourceHandler(object):
    """
    Handle CloudFormation custom resource requests.
    """
    def __init__(self, event: Dict[str, Any], context: Any) -> None:
        super(CustomResourceHandler, self).__init__()
        self.event = event
        self.context = context

        # Return types
        self.data = None
        self.physical_resource_id = event.get("PhysicalResourceId")

        if not self.physical_resource_id:
            # By default, supply a UUID.
            self.physical_resource_id = str(uuid4())
        return

    @property
    def resource_type(self) -> str:
        """
        The CloudFormation custom resource type (Custom::TypeName).
        """
        return self.event["ResourceType"]

    @property
    def request_type(self) -> str:
        """
        The CloudFormation request type (Create, Delete, or Update)
        """
        return self.event["RequestType"]

    @property
    def resource_properties(self) -> Dict[str, Any]:
        """
        The CloudFormation properties specified for the resource.
        """
        rp = self.event.get("ResourceProperties")
        if rp is None:
            rp = {}
        return rp

    def __call__(self) -> None:
        """
        Execute a CloudFormation custom resource event.
        """
        result = {"Status": "FAILED"}

        try:
            handler_key = (self.request_type, self.resource_type)
            handler = self.resource_handlers.get(handler_key)
            if not handler:
                raise RolemakerError(
                    "Unable to handle %s on ResourceType %s: No handler" %
                    handler_key)

            handler(self)
            result.update({
                "Status": "SUCCESS",
                "Data": self.data,
            })
        except RolemakerError as e:
            log.warning("RolemakerError: %s(%s)", type(e).__name__, e,
                        exc_info=True)
            result.update({
                "Status": "FAILED",
                "Reason": "ClientError: %s" % e,
            })
        except Exception as e:                              # pylint: disable=W0703
            log.error("Internal error: %s(%s)", type(e).__name__, e,
                      exc_info=True)
            result.update({
                "Status": "FAILED",
                "Reason": "InternalError: %s" % e
            })

        # Propagate any immuatble CloudFormation keys to the result.
        for key in ["StackId", "RequestId", "LogicalResourceId"]:
            if key in self.event:
                result[key] = self.event[key]

        result["PhysicalResourceId"] = self.physical_resource_id

        # POST the request to the response URL.
        body = json_dumps(result).encode("utf-8")
        headers = {"Content-Type": "", "Content-Length": str(len(body))}
        response_url = self.event.get("ResponseURL")

        log.info("Response URL: %s", response_url)
        log.info("Response body: %s", body)
        log.info("Response headers: %s", headers)

        if not response_url:
            log.error("No ResponseURL in the request to respond to.")
        else:
            request = Request(response_url, data=body, headers=headers)
            response = cast(HTTPResponse, urlopen(request))
            if response.status < 200 or response.status >= 300:
                log.error("Received HTTP status code %d: %s", response.status,
                          response.reason)
            else:
                log.info("Received HTTP status code %d: %s", response.status,
                         response.reason)

        return

    def create_restricted_role(self) -> None:
        """
        Create the basic structure of a restricted role
        """
        mandatory_policy_arn = environ["MANDATORY_ROLE_POLICY_ARN"]
        role_name = self.resource_properties.get("RoleName")
        path = self.resource_properties.get("Path", "/")
        description = self.resource_properties.get("Description", "")

        if not role_name:
            raise RolemakerError("RoleName must be specified")

        # Note: We DO NOT use the user's specified assume role policy
        # document here just in case we can't attach the mandatory
        # role.
        response = iam.create_role(
            Path=path, RoleName=role_name,
            AssumeRolePolicyDocument=ASSUME_ROLE_POLICY_NOOP,
            Description=description)

        self.physical_resource_id = response["Role"]["Arn"]

        # Immediately attach the mandatory policy. If we fail to do so,
        # delete the role so it cannot be used.
        try:
            iam.attach_role_policy(
                RoleName=role_name, PolicyArn=mandatory_policy_arn)

            # Now we can apply the other role bits, fixup the assume role document,
            # etc.
            self.update_or_delete_restricted_role()
        except BotoClientError as e:
            log.error("Failed to configure role %s: %s", role_name, e,
                      exc_info=True)
            try:
                delete_role(role_name)
            except BotoClientError as e2:
                log.error("Failed to delete role %s while cleaning up: %s",
                          role_name, e2, exc_info=True)
            raise RuntimeError(
                "Unable to configure role %s: %s" % (role_name, e))

        return

    def update_or_delete_restricted_role(self) -> None:
        """
        Make a role conform to the specified pieces.
        """
        role_info = get_role_for_arn(self.physical_resource_id)
        role_name = role_info["RoleName"]

        # The physical resource id is the role ARN, which may contain a path.
        # We need to derive the name from this.
        if self.request_type == "Delete":
            delete_role(role_name)
            return

        if role_name != self.resource_properties.get("RoleName"):
            raise RolemakerError(
                "Cannot change role name %r to %r: role names are immutable" %
                (role_name, self.resource_properties.get("RoleName")))

        mandatory_policy_arn = environ["MANDATORY_ROLE_POLICY_ARN"]
        desired_attached_policies = self.resource_properties.get(
            "AttachedPolicies", [])
        desired_inline_policies = self.resource_properties.get(
            "InlinePolicies", {})
        desired_assume_role_policy = self.resource_properties.get(
            "AssumeRolePolicyDocument")
        current_assume_role_policy = role_info["AssumeRolePolicyDocument"]

        check_role_parameters(
            desired_assume_role_policy, desired_inline_policies,
            desired_attached_policies)

        desired_attached_policies = set(desired_attached_policies)
        desired_attached_policies.add(mandatory_policy_arn)

        # Update the assume role policy document if needed
        if current_assume_role_policy != desired_assume_role_policy:
            iam.update_assume_role_policy(
                RoleName=role_name,
                PolicyDocument=json_dumps(desired_assume_role_policy))

        # Get the existing policies for this role
        current_attached_policies = get_attached_policies_for_role(role_name)
        current_inline_policies = get_inline_policies_for_role(role_name)

        # Delete unnecessary policies first so we don't go over limits.
        for arn in current_attached_policies - desired_attached_policies:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=arn)

        # Then attach new policies
        for arn in desired_attached_policies - current_attached_policies:
            try:
                iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)
            except BotoClientError as e:
                raise RolemakerError(
                    "Unable to attach policy %s to role %s: %s" %
                    (arn, role_name, e))

        # Delete unnecessary inline policies first, again for limits.
        for key in current_inline_policies:
            if key not in desired_inline_policies:
                iam.delete_role_policy(RoleName=role_name, PolicyName=key)

        # Then attach new policies
        for key, policy in desired_inline_policies.items():
            current_policy = current_inline_policies.get(key)

            if policy != current_policy:
                try:
                    iam.put_role_policy(
                        RoleName=role_name, PolicyName=key,
                        PolicyDocument=json_dumps(policy))
                except BotoClientError as e:
                    raise RolemakerError(
                        "Unable to put inline policy %s to role %s: %s" %
                        (key, role_name, e))

        return

    resource_handlers = {
        ("Create", "Custom::RestrictedRole"): create_restricted_role,
        ("Delete", "Custom::RestrictedRole"): update_or_delete_restricted_role,
        ("Update", "Custom::RestrictedRole"): update_or_delete_restricted_role,
    }

def get_role_for_arn(role_arn: str) -> Dict[str, Any]:
    """
    get_role_for_arn(role_arn: str) -> Dict[str, Any]
    Returns role information given an ARN. This also validates the ARN to
    ensure it matches the ARN of the associated role name.
    """
    log.debug("role_arn=%r", role_arn)
    try:
        role_path = role_arn.rsplit(":", 1)[1]
        log.debug("role_path=%r", role_path)

        role_name = role_path.rsplit("/", 1)[1]
        log.debug("role_name=%r", role_name)
    except IndexError:
        raise RolemakerError(
            "Invalid PhysicalResourceId: not a valid role ARN: %r" %
            role_arn)

    # Make sure the role ARN matches what we expect
    try:
        response = iam.get_role(RoleName=role_name)
        role_info = response["Role"]
        if role_info["Arn"] != role_arn:
            raise RolemakerError(
                "Invalid PhysicalResourceId: role %s has ARN %s which "
                "doesn't match PhysicalResourceId %s" %
                (role_name, role_info["Arn"], role_arn))
    except BotoClientError as e:
        log.error("Failed to get role %s (arn=%r): %s", role_name,
                  role_arn, e, exc_info=True)
        raise RolemakerError(
            "Invalid PhysicalResourceId: role %s (ARN %s) does not exist" %
            (role_name, role_arn))

    return role_info

def get_attached_policies_for_role(role_name: str) -> Set[str]:
    """
    Returns all attached policy ARNs for the given role.
    """
    kw = {"RoleName": role_name}
    result = set()

    # We need to loop in case the results are paginated.
    while True:
        response = iam.list_attached_role_policies(**kw)
        attached_policies = response.get("AttachedPolicies", [])
        for policy in attached_policies:
            result.add(policy["PolicyArn"])

        if not response["IsTruncated"]:
            return result

        kw["Marker"] = response["Marker"]

def get_inline_policy_names_for_role(role_name: str) -> Set[str]:
    """
    get_inline_policies_for_role(role_name: str) -> Set[str]
    Returns the inline policies names for a given role.
    """
    kw = {"RoleName": role_name}
    policy_names = set()                                       # type: Set[str]

    # Undo the pagination.
    while True:
        response = iam.list_role_policies(**kw)
        policy_names.update(response.get("PolicyNames", []))

        if not response["IsTruncated"]:
            return policy_names

        kw["Marker"] = response["Marker"]


def get_inline_policies_for_role(role_name: str) -> Dict[str, Dict[str, Any]]:
    """
    get_inline_policies_for_role(role_name: str) -> Dict[str, Dict[str, Any]]
    Returns the inline policies for a given role.

    The resulting dict has the form:
    {
        "PolicyName": { PolicyDocument ... },
        ...
    }
    """
    result = {}
    for policy_name in get_inline_policy_names_for_role(role_name):
        response = iam.get_role_policy(
            RoleName=role_name, PolicyName=policy_name)
        result[policy_name] = json_loads(response["PolicyDocument"])

    return result

def delete_role(role_name: str) -> None:
    """
    delete_role(role_name: str) -> None
    Deletes the specified role, detaching all policies before doing so.
    """
    for arn in get_attached_policies_for_role(role_name):
        iam.detach_role_policy(RoleName=role_name, PolicyArn=arn)

    for policy_name in get_inline_policy_names_for_role(role_name):
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)

    iam.delete_role(RoleName=role_name)
    return

def check_role_parameters(assume_role_policy: Any, inline_policies: Any,
                          attached_policies: Any) -> None:
    """
    check_role_parameters(assume_role_policy: Any, inline_policies: Any,
                          attached_policies: Any) -> None
    Validate the types of each role parameter, throwing a RolemakerError if
    the type is incorrect.
    """
    if not assume_role_policy:
        raise RolemakerError("AssumeRolePolicyDocument cannot be empty")
    if not isinstance(assume_role_policy, dict):
        raise RolemakerError("AssumeRolePolicyDocument must be a map")

    if (not isinstance(inline_policies, dict) or
            not all([(isinstance(key, str) and isinstance(value, dict))
                     for key, value in inline_policies.items()])):
        raise RolemakerError(
            "InlinePolicies must be a mapping of policy names to documents")

    if (not isinstance(attached_policies, (list, tuple, set)) or
            not all([isinstance(el, str)
                     for el in attached_policies])):
        raise RolemakerError(
            "AttachedPolicies must be a list of policy ARNs")

    return

def lambda_handler(event: Dict[str, Any], context: Any) -> None:
    """
    Entrypoint for Lambda.
    """
    log.debug("Entering lambda_handler: event=%s", event)
    try:
        if "ResourceType" in event and "RequestType" in event:
            # This is a custom CloudFormation resource.
            handler = CustomResourceHandler(event, context)
            handler()
    except RolemakerError as e:
        log.warning("RolemakerError: %s(%s)", type(e).__name__, e,
                    exc_info=True)
    except Exception as e:                              # pylint: disable=W0703
        log.error("Internal error: %s(%s)", type(e).__name__, e, exc_info=True)

    return
