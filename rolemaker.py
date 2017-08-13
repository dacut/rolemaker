#!/usr/bin/env python3.6
"""
Simplified per-account Rolemaker installation using native AWS authentication
and authorization.
"""
# pylint: disable=C0103,C0302,C0326
from abc import abstractmethod
from base64 import b32encode
from functools import wraps
from http import HTTPStatus
from http.client import HTTPResponse
from json import dumps as json_dumps, loads as json_loads
from logging import Formatter, getLogger, DEBUG, INFO
from os import environ, urandom
from re import fullmatch
from typing import (                                    # pylint: disable=W0611
    Any, Callable, cast, Dict, List, NamedTuple, Optional, Set, Type, Union,
)
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

# This is a policy document that does not grant any permissions.
ASSUME_ROLE_POLICY_NOOP = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Deny",
            "Action": "sts:AssumeRole",
            "Principal": {"Service": "ec2.amazonaws.com"},
        }
    ]
}

def RolemakerError(
        error_code: str, message: str, operation_name: str,
        status_code: Union[int, HTTPStatus]=HTTPStatus.BAD_REQUEST) \
        -> BotoClientError:
    """
    Create a BotoClientError exception from the specified fields.
    """
    return BotoClientError(
        error_response={
            "Error": {
                "Code": error_code,
                "Type": "Sender",
                "Message": message,
            },
            "ResponseMetadata": {
                "HTTPStatusCode": int(status_code),
            }
        },
        operation_name=operation_name)

class APIInfo(NamedTuple):                              # pylint: disable=R0903
    """
    Parameter information about an API.
    """
    method: Callable
    parameters: Set[str]

rolemaker_apis = {}                                 # type: Dict[str, APIInfo]
def api(api_name: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Decorator for Rolemaker APIs that sets metadata.
    """
    def decorate_function(f: Callable[..., Any]) -> Callable[..., Any]:
        """
        Decorate the passed function so the current api name is set.
        """
        @wraps(f)
        def wrapper(*args, **kw):                       # pylint: disable=C0111
            try:
                return f(*args, **kw)
            except BotoClientError as e:
                # Reset the operation name. This requires reformatting the
                # error message as well since it's set in the constructor.
                e.operation_name = api_name
                msg = e.MSG_TEMPLATE.format(
                    error_code=e.response['Error'].get('Code', 'Unknown'),
                    error_message=e.response['Error'].get('Message', 'Unknown'),
                    operation_name=api_name,
                    retry_info=e._get_retry_info(e.response), # pylint: disable=W0212
                )
                e.args = (msg,) + e.args[1:]
                raise

        code = f.__code__
        first_kwarg = code.co_argcount
        last_kwarg = first_kwarg + code.co_kwonlyargcount
        params = set(code.co_varnames[first_kwarg:last_kwarg])

        rolemaker_apis[api_name] = APIInfo(method=wrapper, parameters=params)
        return wrapper
    return decorate_function

def InvalidParameterValue(
        message: str, operation_name: str="Unknown") -> BotoClientError:
    """
    Create a BotoClientError instance prepopulated with the
    "InvalidParameterValue" error code.
    """
    return RolemakerError("InvalidParameterValue", message, operation_name)

def DeleteConflict(
        message: str, operation_name: str="Unknown") -> BotoClientError:
    """
    Create a BotoClientError instance prepopulated with the
    "DeleteConflict" error code
    """
    return RolemakerError("DeleteConflict", message, operation_name)

class RolemakerAPI(object):
    """
    Bare Rolemaker APIs.
    """
    # Handle to the IAM service.
    iam = boto3.client("iam")
    @abstractmethod
    def __call__(self) -> Optional[Dict[str, Any]]:
        raise NotImplementedError()

    @api("CreateRestrictedRole")
    def create_restricted_role(
            self, *, RoleName: str="", AssumeRolePolicyDocument: str="",
            Path: str="/", Description: str="") -> Dict[str, Any]:
        """
        Create a new restricted role.
        """
        if not RoleName:
            raise InvalidParameterValue("RoleName cannot be empty")

        if not isinstance(RoleName, str):
            raise InvalidParameterValue("RoleName must be a string")

        if not AssumeRolePolicyDocument:
            raise InvalidParameterValue(
                "AssumeRolePolicyDocument cannot be empty")

        if not isinstance(AssumeRolePolicyDocument, str):
            raise InvalidParameterValue(
                "AssumeRolePolicyDocument must be a string")

        if not isinstance(Path, str):
            raise InvalidParameterValue("Path must be a string")

        if not isinstance(Description, str):
            raise InvalidParameterValue("Description must be a string")

        mandatory_policy_arn = environ.get("MANDATORY_ROLE_POLICY_ARN")
        if not mandatory_policy_arn:
            raise RuntimeError(
                "Server error: Environment variable MANDATORY_ROLE_POLICY_ARN "
                "has not been set on the Lambda function.")

        role_info = self.iam.create_role(
            RoleName=RoleName,
            AssumeRolePolicyDocument=AssumeRolePolicyDocument, Path=Path,
            Description=Description)

        try:
            log.info("Attaching mandatory policy %s to newly created role %s",
                     mandatory_policy_arn, RoleName)
            self.iam.attach_role_policy(
                RoleName=RoleName, PolicyArn=mandatory_policy_arn)
        except Exception as e:
            log.error("Failed to attach PolicyArn %s to role %s: %s",
                      mandatory_policy_arn, RoleName, e, exc_info=True)
            try:
                log.info("Deleting role %s because policy attachment failed.",
                         RoleName)
                self.iam.delete_role(RoleName=RoleName)
                log.info("Role %s deleted", RoleName)
            except Exception as e2:
                log.error("Failed to delete role %s: %s(%s)", RoleName,
                          type(e2).__name__, e2, exc_info=True)
                raise
            raise
        return role_info

    @api("DeleteRestrictedRole")
    def delete_restricted_role(self, *, RoleName: str="") -> None:
        """
        Delete an existing restricted role. This does not allow the deletion of
        unrestricted roles; the role must have no inline policies attached to
        it and only the mandatory policy attached to it.
        """
        if not RoleName:
            raise InvalidParameterValue("RoleName cannot be empty")

        attached_policies = self.get_attached_policies_for_role(RoleName)
        inline_policies = self.get_inline_policy_names_for_role(RoleName)

        mandatory_policy_arn = environ.get("MANDATORY_ROLE_POLICY_ARN")
        if not mandatory_policy_arn:
            raise RuntimeError(
                "Server error: Environment variable MANDATORY_ROLE_POLICY_ARN "
                "has not been set on the Lambda function.")

        if mandatory_policy_arn not in attached_policies:
            raise InvalidParameterValue("Role %s is not a restricted role.")

        if len(attached_policies) != 1:
            raise DeleteConflict(
                "Cannot delete entity, must detach all policies first.")

        if inline_policies:
            raise DeleteConflict(
                "Cannot delete entity, must delete policies first.")

        # Set the assume role document to an unusable value in case we are
        # unable to delete the role.
        self.iam.update_assume_role_policy(
            RoleName=RoleName,
            PolicyDocument=json_dumps(ASSUME_ROLE_POLICY_NOOP, indent=4))

        # Remove the mandatory policy.
        mandatory_policy_arn = environ.get("MANDATORY_ROLE_POLICY_ARN")
        self.iam.detach_role_policy(
            RoleName=RoleName, PolicyArn=mandatory_policy_arn)

        # Now that the role is empty we can delete it.
        return self.iam.delete_role(RoleName=RoleName)

    @api("AttachRestrictedRolePolicy")
    def attach_restricted_role_policy(
            self, *, RoleName: str="", PolicyArn: str="") -> None:
        """
        Attach a managed policy to a restricted IAM role.
        """
        if not RoleName:
            raise InvalidParameterValue("RoleName cannot be empty")

        if not PolicyArn:
            raise InvalidParameterValue("PolicyArn cannot be empty")

        self.assert_is_restricted_role(RoleName=RoleName)
        return self.iam.attach_role_policy(
            RoleName=RoleName, PolicyArn=PolicyArn)

    @api("DetachRestrictedRolePolicy")
    def detach_restricted_role_policy(
            self, *, RoleName: str="", PolicyArn: str="") -> None:
        """
        Detach a managed policy to a restricted IAM role.
        """
        if not RoleName:
            raise InvalidParameterValue("RoleName cannot be empty")

        if not PolicyArn:
            raise InvalidParameterValue("PolicyArn cannot be empty")

        mandatory_policy_arn = environ.get("MANDATORY_ROLE_POLICY_ARN")
        if not mandatory_policy_arn:
            raise RuntimeError(
                "Server error: Environment variable MANDATORY_ROLE_POLICY_ARN "
                "has not been set on the Lambda function.")

        if PolicyArn == mandatory_policy_arn:
            raise InvalidParameterValue("Cannot detach the mandatory policy.")

        self.assert_is_restricted_role(RoleName=RoleName)
        return self.iam.detach_role_policy(
            RoleName=RoleName, PolicyArn=PolicyArn)

    @api("PutRestrictedRolePolicy")
    def put_restricted_role_policy(
            self, *, RoleName: str="", PolicyName: str="",
            PolicyDocument: str="") -> None:
        """
        Adds or updates an inline policy to a restricted IAM role.
        """
        if not RoleName:
            raise InvalidParameterValue("RoleName cannot be empty")

        if not PolicyName:
            raise InvalidParameterValue("PolicyName cannot be empty")

        if not PolicyDocument:
            raise InvalidParameterValue("PolicyDocument cannot be empty")

        self.assert_is_restricted_role(RoleName=RoleName)
        return self.iam.put_role_policy(
            RoleName=RoleName, PolicyName=PolicyName,
            PolicyDocument=PolicyDocument)

    @api("DeleteRestrictedRolePolicy")
    def delete_restricted_role_policy(
            self, *, RoleName: str="", PolicyName: str="") -> None:
        """
        Deletes an inline policy from a restricted IAM role.
        """
        if not RoleName:
            raise InvalidParameterValue("RoleName cannot be empty")

        if not PolicyName:
            raise InvalidParameterValue("PolicyName cannot be empty")

        self.assert_is_restricted_role(RoleName=RoleName)
        return self.iam.delete_role_policy(
            RoleName=RoleName, PolicyName=PolicyName)

    @api("UpdateAssumeRestrictedRolePolicy")
    def update_assume_restricted_role_policy(
            self, *, RoleName: str="", PolicyDocument: str="") -> None:
        """
        Updates the policy that grants an IAM entity permission to assume
        a restricted role.
        """
        if not RoleName:
            raise InvalidParameterValue("RoleName cannot be empty")

        if not PolicyDocument:
            raise InvalidParameterValue("PolicyDocument cannot be empty")

        self.assert_is_restricted_role(RoleName=RoleName)
        return self.iam.update_assume_role_policy(
            RoleName=RoleName, PolicyDocument=PolicyDocument)

    @api("UpdateRestrictedRoleDescription")
    def update_restricted_role_description(
            self, *, RoleName: str="", Description: str="") -> None:
        """
        Modifies the description of a restricted role.
        """
        if not RoleName:
            raise InvalidParameterValue("RoleName cannot be empty")

        self.assert_is_restricted_role(RoleName=RoleName)
        return self.iam.update_role_description(
            RoleName=RoleName, Description=Description)

    def assert_is_restricted_role(self, RoleName: str) -> None:
        """
        Verifies the specified role name is a restricted role by ensuring
        the attached policies includes the mandatory policy ARN.
        """
        mandatory_policy_arn = environ.get("MANDATORY_ROLE_POLICY_ARN")

        if not mandatory_policy_arn:
            raise RuntimeError(
                "Server error: Environment variable MANDATORY_ROLE_POLICY_ARN "
                "has not been set on the Lambda function.")

        if not RoleName:
            raise InvalidParameterValue("RoleName cannot be empty.")

        kw = {"RoleName": RoleName}
        # We need to loop in case the results are paginated.
        while True:
            response = self.iam.list_attached_role_policies(**kw)
            att_policies = response.get("AttachedPolicies", [])
            log.debug("Attached policies for role %s: %s", RoleName,
                      att_policies)

            if mandatory_policy_arn in [p["PolicyArn"] for p in att_policies]:
                log.debug("Found mandatory policy %s", mandatory_policy_arn)
                return

            if not response["IsTruncated"]:
                break

            kw["Marker"] = response["Marker"]
        raise InvalidParameterValue(
            "Role %s is not a restricted role." % RoleName)

    def get_role_for_arn(self, role_arn: str) -> Dict[str, Any]:
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
            raise InvalidParameterValue(
                "Invalid PhysicalResourceId: not a valid role ARN: %r" %
                role_arn)

        # Make sure the role ARN matches what we expect
        try:
            response = self.iam.get_role(RoleName=role_name)
            role_info = response["Role"]
            if role_info["Arn"] != role_arn:
                raise InvalidParameterValue(
                    "Invalid PhysicalResourceId: role %s has ARN %s which "
                    "doesn't match PhysicalResourceId %s" %
                    (role_name, role_info["Arn"], role_arn))
        except BotoClientError as e:
            log.error("Failed to get role %s (arn=%r): %s", role_name,
                      role_arn, e, exc_info=True)
            raise InvalidParameterValue(
                "Invalid PhysicalResourceId: role %s (ARN %s) does not exist" %
                (role_name, role_arn))

        return role_info

    def get_attached_policies_for_role(self, role_name: str) -> Set[str]:
        """
        Returns all attached policy ARNs for the given role.
        """
        kw = {"RoleName": role_name}
        result = set()

        # We need to loop in case the results are paginated.
        while True:
            response = self.iam.list_attached_role_policies(**kw)
            attached_policies = response.get("AttachedPolicies", [])
            for policy in attached_policies:
                result.add(policy["PolicyArn"])

            if not response["IsTruncated"]:
                return result

            kw["Marker"] = response["Marker"]

    def get_inline_policy_names_for_role(self, role_name: str) -> Set[str]:
        """
        get_inline_policies_for_role(role_name: str) -> Set[str]
        Returns the inline policies names for a given role.
        """
        kw = {"RoleName": role_name}
        policy_names = set()                                       # type: Set[str]

        # Undo the pagination.
        while True:
            response = self.iam.list_role_policies(**kw)
            policy_names.update(response.get("PolicyNames", []))

            if not response["IsTruncated"]:
                return policy_names

            kw["Marker"] = response["Marker"]

    def get_inline_policies_for_role(
            self, role_name: str) -> Dict[str, Dict[str, Any]]:
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
        for policy_name in self.get_inline_policy_names_for_role(role_name):
            response = self.iam.get_role_policy(
                RoleName=role_name, PolicyName=policy_name)
            result[policy_name] = json_loads(response["PolicyDocument"])

        return result

RequestTypeHandler = Callable[['CustomResourceHandler'], Optional[Dict[str, Any]]]

class CustomResourceHandler(RolemakerAPI):
    """
    Lambda custom resource handler base class.
    """
    request_type_handlers = {} # type: Dict[str, RequestTypeHandler]
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
    def stack_id(self) -> str:
        """
        The CloudFormation stack id (ARN).
        """
        return self.event["StackId"]

    @property
    def stack_name(self) -> str:
        """
        The name of the stack, extracted from the stack_id.
        """
        m = fullmatch(
            r"arn:aws[^:]*:cloudformation:[^:]*:[^:]*:stack/([^/]+)/.*",
            self.stack_id)
        if not m:
            raise RuntimeError("Could not extract stack name from ARN %s" %
                               self.stack_id)

        return m.group(1)

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
    def logical_resource_id(self) -> str:
        """
        The CloudFormation logical resource id.
        """
        return self.event["LogicalResourceId"]

    @property
    def resource_properties(self) -> Dict[str, Any]:
        """
        The CloudFormation properties specified for the resource.
        """
        rp = self.event.get("ResourceProperties")
        if rp is None:
            rp = {}
        return rp

    @property
    def old_resource_properties(self) -> Dict[str, Any]:
        """
        The old CloudFormation properties specified for the resource during an
        update event.
        """
        rp = self.event.get("OldResourceProperties")
        if rp is None:
            rp = {}
        return rp

    def __call__(self) -> Optional[Dict[str, Any]]:
        """
        Execute a CloudFormation custom resource event.
        """
        result = {"Status": "FAILED"}                   # type: Dict[str, Any]

        try:
            handler = self.request_type_handlers.get(self.request_type)
            if not handler:
                raise InvalidParameterValue(
                    "Cannot handle CloudFormation event %s %s" %
                    (self.request_type, self.resource_type))

            data = handler(self)

            if "PhysicalResourceId" in data:
                self.physical_resource_id = result.pop("PhysicalResourceId")

            result.update({
                "Status": "SUCCESS",
                "Data": data,
            })
        except BotoClientError as e:
            log.warning("BotoClientError: %s", e, exc_info=True)
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

        # PUT the request to the response URL.
        log.debug("result: %s", result)
        body = json_dumps(result).encode("utf-8")
        headers = {"Content-Type": "", "Content-Length": str(len(body))}
        response_url = self.event.get("ResponseURL")

        log.info("Response URL: %s", response_url)
        log.info("Response body: %s", body)
        log.info("Response headers: %s", headers)

        if not response_url:
            log.error("No ResponseURL in the request to respond to.")
        else:
            request = Request(
                response_url, data=body, headers=headers, method="PUT")
            response = cast(HTTPResponse, urlopen(request))
            if response.status < 200 or response.status >= 300:
                log.error("Received HTTP status code %d: %s", response.status,
                          response.reason)
            else:
                log.info("Received HTTP status code %d: %s", response.status,
                         response.reason)

        return None


class CustomRestrictedRoleHandler(CustomResourceHandler):
    """
    Handle CloudFormation Custom::RestrictedRole resource requests.
    """
    create_props = {
        "RoleName", "AssumeRolePolicyDocument", "Path", "Description"
    }
    valid_props = create_props.union({"Policies", "ManagedPolicyArns"})

    @api("Create Custom::RestrictedRole")
    def handle_create_restricted_role(self) -> Dict[str, Any]:
        """
        Create the basic structure of a restricted role.
        """
        self.check_resource_properties()
        create_kw = {}

        for key in self.create_props:
            if key in self.resource_properties:
                create_kw[key] = self.resource_properties[key]

        if isinstance(create_kw.get("AssumeRolePolicyDocument"), dict):
            # Convert this to a string for the API call.
            create_kw["AssumeRolePolicyDocument"] = json_dumps(
                create_kw["AssumeRolePolicyDocument"], indent=4)

        if "RoleName" not in create_kw:
            base_name = self.stack_name + "-" + self.logical_resource_id
            suffix = "-" + b32encode(urandom(10)).decode("utf-8").rstrip("=")

            # Remove characters from base_name if the result would exceed 64,
            # the limit for the role name.
            base_name = base_name[:64 - len(suffix)]
            create_kw["RoleName"] = base_name + suffix

        # Create the base role structure first.
        response = self.create_restricted_role(**create_kw)
        role_name = response["Role"]["RoleName"]

        try:
            # Attach managed policy arns.
            for arn in self.resource_properties.get("ManagedPolicyArns", []):
                self.attach_restricted_role_policy(
                    RoleName=role_name, PolicyArn=arn)

            # Attach inline policies.
            for policy in self.resource_properties.get("Policies", []):
                policy_name = policy.pop("PolicyName", None)
                policy_doc = policy.pop("PolicyDocument", None)
                if not policy_name:
                    raise InvalidParameterValue("PolicyName cannot be empty")
                if not policy_doc:
                    raise InvalidParameterValue(
                        "PolicyDocument cannot be empty")

                # Make sure nothing else has been specified.
                if policy:
                    raise InvalidParameterValue(
                        "Invalid policy parameter(s): %s" % ",".join(policy))

                if isinstance(policy_doc, dict):
                    # Convert this to a string for the API call.
                    policy_doc = json_dumps(policy_doc, indent=4)

                self.put_restricted_role_policy(
                    RoleName=role_name, PolicyName=policy_name,
                    PolicyDocument=policy_doc)
        except:
            # Can't create it; roll back.
            self.force_delete_role(RoleName=role_name)
            raise

        self.physical_resource_id = role_name
        return {
            "Arn": response["Role"]["Arn"]
        }

    @api("Delete Custom::RestrictedRole")
    def handle_delete_restricted_role(self) -> Dict[str, Any]:
        """
        Deletes a restricted role.
        """
        role_name = self.physical_resource_id
        self.assert_is_restricted_role(role_name)
        self.force_delete_role(RoleName=role_name)
        return {}

    @api("Update Custom::RestrictedRole")
    def handle_update_restricted_role(self) -> Dict[str, Any]:
        """
        Update a role, replacing it if the role name has changed.
        """
        self.check_resource_properties()

        old_role_name = self.old_resource_properties["RoleName"]
        new_role_name = self.resource_properties.get("RoleName")
        old_path = self.old_resource_properties.get("Path", "/")
        new_path = self.resource_properties.get("Path", "/")

        if not new_role_name:
            raise InvalidParameterValue("RoleName cannot be empty")

        if old_role_name != new_role_name:
            # Replacement -- create the new one, delete the old one.
            return self.handle_replace_update()
        elif old_path != new_path:
            raise InvalidParameterValue(
                "Cannot update the path to an existing role. Rename the role "
                "and update the stack again.")
        else:
            return self.handle_inplace_update()

    def handle_replace_update(self) -> Dict[str, Any]:
        """
        Update a role by creating a new one and deleting the old one.
        """
        old_role_name = self.old_resource_properties["RoleName"]
        new_role_name = self.resource_properties["RoleName"]
        result = self.handle_create_restricted_role()
        try:
            self.iam.get_role(RoleName=old_role_name)
        except BotoClientError as e:
            if e.response["Error"].get("Code") != "NoSuchEntity":
                raise
        else:
            try:
                self.assert_is_restricted_role(RoleName=old_role_name)
                self.force_delete_role(RoleName=old_role_name)
            except:
                # Can't delete the old one, so rollback the new.
                self.force_delete_role(RoleName=new_role_name)
                raise

        self.physical_resource_id = new_role_name
        return {
            "Arn": result["Role"]["Arn"]
        }

    def handle_inplace_update(self) -> Dict[str, Any]: # pylint: disable=R0912,R0914,R0915
        """
        Update a role by replacing its properties.
        """
        role_name = self.resource_properties["RoleName"]
        self.assert_is_restricted_role(RoleName=role_name)

        old = self.old_resource_properties
        new = self.resource_properties

        role_info = self.iam.get_role(RoleName=role_name)

        # Get the previous properties. Note that we don't do a delta against
        # the existing (so we keep any out-of-band modifications) -- this is
        # in keeping with the existing behavior of AWS::IAM::Role.
        old_description = old.get("Description", "")
        old_assume_doc = old["AssumeRolePolicyDocument"]
        old_attached_policies = set(old.get("ManagedPolicyArns", []))
        old_inline_policies = old.get("Policies", [])

        new_description = new.get("Description", "")
        new_assume_doc = new["AssumeRolePolicyDocument"]
        new_attached_policies = set(new.get("ManagedPolicyArns", []))
        new_inline_policies = new.get("Policies", [])

        # Make sure both assume role policies are JSON structures for
        # comparison.
        old_assume_doc = self.policy_as_json(
            old_assume_doc, default=ASSUME_ROLE_POLICY_NOOP)
        new_assume_doc = self.policy_as_json(
            new_assume_doc, name="AssumeRolePolicyDocument")

        # Do the same for inline policies
        old_ip_dict = self.inline_policies_as_dict(
            old_inline_policies)
        new_ip_dict = self.inline_policies_as_dict(
            new_inline_policies)

        # If we need to roll back, this is a list of callables to invoke to
        # perform the roll back.
        undo = []

        try:
            # Update the description if needed.
            if old_description != new_description:
                self.update_restricted_role_description(
                    RoleName=role_name, Description=new_description)
                undo.append(
                    (self.update_restricted_role_description,
                     dict(RoleName=role_name, Description=old_description)))

            # Update the assume role policy document if needed
            if old_assume_doc != new_assume_doc:
                self.update_assume_restricted_role_policy(
                    RoleName=role_name,
                    PolicyDocument=json_dumps(new_assume_doc, indent=4))
                undo.append(
                    (self.update_assume_restricted_role_policy,
                     dict(RoleName=role_name,
                          PolicyDocument=json_dumps(old_assume_doc, indent=4))))

            arns_to_remove = old_attached_policies - new_attached_policies
            arns_to_add = new_attached_policies - old_attached_policies

            # Remove any managed policy arns no longer present. This has to
            # happen first to avoid going over the limit of 10 arns.
            for arn in arns_to_remove:
                self.detach_restricted_role_policy(
                    RoleName=role_name, PolicyArn=arn)
                undo.append(
                    (self.attach_restricted_role_policy,
                     dict(RoleName=role_name, PolicyArn=arn)))

            # Add any new managed policy arns.
            for arn in arns_to_add:
                self.attach_restricted_role_policy(
                    RoleName=role_name, PolicyArn=arn)
                undo.append(
                    (self.detach_restricted_role_policy,
                     dict(RoleName=role_name, PolicyArn=arn)))

            # Remove any inline policies no longer present. Again, limits.
            for policy_name, old_doc in old_ip_dict.items():
                if policy_name in new_ip_dict:
                    continue

                self.delete_restricted_role_policy(
                    RoleName=role_name, PolicyName=policy_name)
                undo.append(
                    (self.put_restricted_role_policy,
                     dict(RoleName=role_name, PolicyName=policy_name,
                          PolicyDocument=json_dumps(old_doc, indent=4))))

            # Add or replace any new or modified inline policies.
            for policy_name, new_doc in new_ip_dict.items():
                old_doc = old_ip_dict.get(policy_name)

                if old_doc == new_doc:
                    continue

                self.put_restricted_role_policy(
                    RoleName=role_name, PolicyName=policy_name,
                    PolicyDocument=json_dumps(new_doc, indent=4))

                if old_doc:
                    # Modify -- undo has to put the modification back
                    undo.append(
                        (self.put_restricted_role_policy,
                         dict(RoleName=role_name, PolicyName=policy_name,
                              PolicyDocument=json_dumps(old_doc, indent=4))))
                else:
                    # Add -- undo has to remove the policy
                    undo.append(
                        (self.delete_restricted_role_policy,
                         dict(RoleName=role_name, PolicyName=policy_name)))

        except:
            # Perform the undo actions.
            undo.reverse()
            for i, func_kw in enumerate(undo):
                func, kw = func_kw
                log.info("Perform rollback action %d: %s(**%s)", i, func, kw)
                try:
                    func(**kw)
                except Exception as e:                  # pylint: disable=W0703
                    log.error("Failed to perform rollback action %d: %s(%s)",
                              i, type(e).__name__, e, exc_info=True)
            raise

        self.physical_resource_id = role_name

        return dict(Arn=role_info["Role"]["Arn"])

    @staticmethod
    def inline_policies_as_dict(
            policy_list: List[Dict[str, Any]],
            default: Optional[Dict[str, Any]]=None) -> Dict[str, Dict[str, Any]]:
        """
        inline_policies_as_dict(
            policy_list: List[Dict[str, Any]]
            default: Optional[Dict[str, Any]]=None) -> Dict[str, Dict[str, Any]]
        Convert an inline policy structure in the form:
            [{"PolicyName": "name1", "PolicyDocument": doc1}, ...]
        to a dictionary of the form:
            {"name1": doc1, "name2": doc2, ...}

        If a policy document is a string, it is converted to JSON.
        """
        result = {}
        for policy in policy_list:
            name = policy.get("PolicyName")
            if not name:
                raise InvalidParameterValue("Inline policy missing PolicyName")

            doc = policy.get("PolicyDocument")
            if not doc:
                if default is not None:
                    doc = default
                else:
                    raise InvalidParameterValue(
                        "Inline policy missing PolicyDocument")

            doc = CustomRestrictedRoleHandler.policy_as_json(doc)
            result[name] = doc

        return result

    @staticmethod
    def policy_as_json(
            policy: Union[str, Dict[str, Any]],
            default: Optional[Dict[str, Any]]=None,
            name: str="PolicyDocument") -> Dict[str, Any]:
        """
        policy_as_json(
            policy: Union[str, Dict[str, Any]],
            default: Optional[Dict[str, Any]]=None,
            parameter_name: str="PolicyDocument") -> Dict[str, Any]
        Convert a string policy document to its JSON form. If the policy cannot
        be parsed and default is a dictionary, default is returned; otherwise,
        a BotoClientError exception is raised.
        """
        if isinstance(policy, dict):
            return policy
        elif isinstance(policy, str):
            try:
                return json_loads(policy)
            except ValueError:
                if default is not None:
                    return default

        raise InvalidParameterValue("%s is not valid JSON" % name)

    def check_resource_properties(self) -> None:
        """
        Check the names specified in the resource properties, throwing a
        BotoClientError exception if an invalid property name is found or
        the required properties RoleName or AssumeRolePolicyDocument are
        missing.
        """
        invalid_props = []
        for key in self.resource_properties:
            if key not in self.valid_props and key != "ServiceToken":
                invalid_props.append(key)

        if invalid_props:
            raise InvalidParameterValue(
                "Unknown properties: %s" % ",".join(invalid_props))

        missing_props = []
        for key in ("RoleName", "AssumeRolePolicyDocument"):
            if not self.resource_properties.get(key):
                missing_props.append(key)

        if missing_props:
            raise InvalidParameterValue(
                "Missing or empty properties: %s" % ",".join(missing_props))

        return

    def force_delete_role(self, RoleName: str) -> None:
        """
        Deletes the specified role, detaching all policies before doing so.
        """
        for arn in self.get_attached_policies_for_role(RoleName):
            self.iam.detach_role_policy(RoleName=RoleName, PolicyArn=arn)

        for PolicyName in self.get_inline_policy_names_for_role(RoleName):
            self.iam.delete_role_policy(RoleName=RoleName,
                                        PolicyName=PolicyName)

        self.iam.delete_role(RoleName=RoleName)
        return

    request_type_handlers = {
        "Create": handle_create_restricted_role,
        "Update": handle_update_restricted_role,
        "Delete": handle_delete_restricted_role,
    }

class DirectInvokeHandler(RolemakerAPI):
    """
    DirectInvokeHandler(event, context)
    Handle direct invocations via Lambda:Invoke.
    """
    def __init__(self, event: Dict[str, Any], context: Any) -> None:
        super(DirectInvokeHandler, self).__init__()
        self.event = event
        self.context = context
        return

    def __call__(self) -> Dict[str, Any]:
        try:
            action_name = self.event.get("Action")
            api_info = rolemaker_apis.get(action_name)
            if not api_info:
                raise RolemakerError(
                    "InvalidAction", "Unknown action %s" % action_name,
                    "Unknown")

            # Copy the parameters from the event, omitting the Action
            # parameter
            parameters = dict(self.event)
            parameters.pop("Action")

            invalid_params = []
            for key in parameters:
                if key not in api_info.parameters:
                    invalid_params.append(key)

            if invalid_params:
                raise InvalidParameterValue(
                    "Unknown parameters: %s" % ",".join(invalid_params),
                    action_name)

            return api_info.method(self, **parameters)
        except BotoClientError as e:
            log.warning("BotoClientError: %s", e)
            return e.response
        except Exception as e:                          # pylint: disable=W0703
            log.error("Unknown exception: %s(%s)", type(e).__name__, e,
                      exc_info=True)
            return {
                "Error": {
                    "Code": "InternalFailure",
                    "Type": "Receiver",
                    "Message": "Unhandled exception: %s(%s)" % (
                        type(e).__name__, e),
                },
                "ResponseMetadata": {
                    "HTTPStatusCode": int(HTTPStatus.INTERNAL_SERVER_ERROR),
                }
            }

def lambda_handler(event: Dict[str, Any],
                   context: Any) -> Optional[Dict[str, Any]]:
    """
    Entrypoint for Lambda.
    """
    log.debug("Entering lambda_handler: event=%s", event)
    try:
        if "ResourceType" in event and "RequestType" in event:
            # This is a custom CloudFormation resource.
            if event["ResourceType"] == "Custom::RestrictedRole":
                cls = CustomRestrictedRoleHandler # type: Type[CustomResourceHandler]
            else:
                cls = CustomResourceHandler

            result = cls(event, context)()
        elif "Action" in event:
            result = DirectInvokeHandler(event, context)()
        else:
            raise RuntimeError("Cannot handle unknown Lambda event")
    except Exception as e:
        log.error("Internal error: %s(%s)", type(e).__name__, e, exc_info=True)
        raise
    else:
        log.debug("lambda_handler returning %s", result)
        return result
