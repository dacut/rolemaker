#!/usr/bin/env python3
# pylint: disable=C0302
"""
Test the Lambda handler.
"""
# pylint: disable=C0103,C0111,R0904
from base64 import b32encode
from http.server import BaseHTTPRequestHandler, HTTPServer
from json import dumps as json_dumps, loads as json_loads
from logging import getLogger
from os import environ, urandom
from threading import Thread
from unittest import TestCase

from botocore.exceptions import ClientError as BotoClientError
import boto3
from moto import mock_iam
import rolemaker

# Fixes for Moto's unimplemented detach_role_policy API.
# https://github.com/spulec/moto/pull/1052
from moto.core.exceptions import RESTError  # pylint: disable=C0412
from moto.iam.exceptions import IAMNotFoundException
from moto.iam.models import IAMBackend, iam_backend, ManagedPolicy, Role
from moto.iam.responses import IamResponse
def policy_detach_from_role(self, role):
    self.attachment_count -= 1
    del role.managed_policies[self.name]
ManagedPolicy.detach_from_role = policy_detach_from_role

def role_delete_policy(self, policy_name):
    try:
        del self.policies[policy_name]
    except KeyError:
        raise IAMNotFoundException(
            "The role policy with name {0} cannot be found.".format(policy_name))
Role.delete_policy = role_delete_policy

class InvalidParameterError(RESTError):
    code = 400
    def __init__(self, message):
        super(InvalidParameterError, self).__init__(
            "InvalidParameterValue", message)

def role_put_policy(self, policy_name, policy_json):
    if "TRIGGER_INVALID_JSON" in str(policy_json):
        raise InvalidParameterError("Policy contains TRIGGER_INVALID_JSON")
    self.policies[policy_name] = policy_json
Role.put_policy = role_put_policy

def backend_detach_role_policy(self, policy_arn, role_name):
    arns = dict((p.arn, p) for p in self.managed_policies.values())
    try:
        policy = arns[policy_arn]
        policy.detach_from_role(self.get_role(role_name))
    except KeyError:
        raise IAMNotFoundException("Policy {0} was not found.".format(policy_arn))
IAMBackend.detach_role_policy = backend_detach_role_policy

def backend_delete_role_policy(self, role_name, policy_name):
    role = self.get_role(role_name)
    role.delete_policy(policy_name)
IAMBackend.delete_role_policy = backend_delete_role_policy

DETACH_ROLE_POLICY_TEMPLATE = """\
<DetachRolePolicyResponse>
  <ResponseMetadata>
    <RequestId>7a62c49f-347e-4fc4-9331-6e8eEXAMPLE</RequestId>
  </ResponseMetadata>
</DetachRolePolicyResponse>"""
def response_detach_role_policy(self):
    policy_arn = self._get_param('PolicyArn')        # pylint: disable=W0212
    role_name = self._get_param('RoleName')          # pylint: disable=W0212
    iam_backend.detach_role_policy(policy_arn, role_name)
    template = self.response_template(DETACH_ROLE_POLICY_TEMPLATE)
    return template.render()
IamResponse.detach_role_policy = response_detach_role_policy

DELETE_ROLE_POLICY_TEMPLATE = """\
<DeleteRolePolicyResponse>
  <ResponseMetadata>
    <RequestId>7a62c49f-347e-4fc4-9331-6e8eEXAMPLE</RequestId>
  </ResponseMetadata>
</DeleteRolePolicyResponse>"""
def response_delete_role_policy(self):
    policy_name = self._get_param('PolicyName')      # pylint: disable=W0212
    role_name = self._get_param('RoleName')          # pylint: disable=W0212
    iam_backend.delete_role_policy(role_name, policy_name)
    template = self.response_template(DELETE_ROLE_POLICY_TEMPLATE)
    return template.render()
IamResponse.delete_role_policy = response_delete_role_policy

### End Moto fixup
def randstr(length=10):
    """
    Return random letters/digits.
    """
    return b32encode(urandom(length)).decode("ascii").rstrip("=")

class ResponseHandler(BaseHTTPRequestHandler):
    """
    Handles S3 POSTs that the Lambda handler sends its results to.
    """
    log = getLogger("http")
    responses = []

    def do_PUT(self):
        content_length = self.headers.get("Content-Length")
        if content_length is not None:
            content_length = int(content_length)

        data = self.rfile.read(content_length)
        self.responses.append(data)

        self.send_response(200, "")
        self.send_header("Content-Length", "0")
        self.send_header("Server", "AmazonS3")
        self.end_headers()

        return

    def log_message(self, format, *args): # pylint: disable=W0622
        """
        Log messages to the regular logging facility; BaseHTTPRequestHandler
        forcibly prints them to stderr.
        """
        self.log.info(format, *args)

OPEN_MANDATORY_POLICY = {
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "*",
        "Principal": "*",
    }
}

POWER_USER_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "NotAction": "iam:*",
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": ["iam:Get*", "iam:List*"],
            "Resource": "*"
        }
    ]
}

S3_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "*"
        }
    ]
}

BASIC_ASSUME_ROLE_POLICY = {
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "sts:AssumeRole",
        "Principal": {"Service": "ec2.amazonaws.com"}
    }
}

LAMBDA_ASSUME_ROLE_POLICY = {
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "sts:AssumeRole",
        "Principal": {"Service": "lambda.amazonaws.com"}
    }
}

@mock_iam
class TestCustomResourceHandler(TestCase):
    """
    Test CloudFormation Custom::RestrictedRole resource handling.
    """
    mandatory_arn = ""
    power_arn = ""
    s3_arn = ""

    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), ResponseHandler)
        cls.thread = Thread(target=cls.server.serve_forever)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join()
        return

    def setUp(self):
        self.iam = boto3.client("iam")
        result = self.iam.create_policy(
            PolicyName="Mandatory",
            PolicyDocument=json_dumps(OPEN_MANDATORY_POLICY))
        environ["MANDATORY_ROLE_POLICY_ARN"] = self.mandatory_arn = \
            result["Policy"]["Arn"]

        result = self.iam.create_policy(
            PolicyName="Power",
            PolicyDocument=json_dumps(POWER_USER_POLICY))
        self.power_arn = result["Policy"]["Arn"]

        result = self.iam.create_policy(
            PolicyName="S3",
            PolicyDocument=json_dumps(S3_POLICY))
        self.s3_arn = result["Policy"]["Arn"]

        ResponseHandler.responses = []
        return

    def invoke(self, ResourceType, RequestType="Create",
               LogicalResourceId="LogicalResourceId", **kw):
        sockname = self.server.socket.getsockname()

        event = {
            "StackId": "arn:aws:cloudformation:us-west-2:12345678:stack/stack-1234",
            "RequestId": "req-1234",
            "LogicalResourceId": LogicalResourceId,
            "RequestType": RequestType,
            "ResourceType": ResourceType,
            "ResponseURL": "http://%s:%s/" % (sockname[0], sockname[1])
        }

        if "PhysicalResourceId" in kw:
            event["PhysicalResourceId"] = kw.pop("PhysicalResourceId")

        if "OldResourceProperties" in kw:
            event["OldResourceProperties"] = kw.pop("OldResourceProperties")

        event["ResourceProperties"] = kw

        rolemaker.lambda_handler(event, None)
        return json_loads(ResponseHandler.responses.pop())

    def test_unknown_type(self):
        result = self.invoke(ResourceType="Custom::Unknown")
        self.assertEqual(result["Status"], "FAILED")
        self.assertEqual(
            result["Reason"],
            "ClientError: An error occurred (InvalidParameterValue) when "
            "calling the Unknown operation: Cannot handle CloudFormation "
            "event Create Custom::Unknown")

    def test_basic_create_delete(self):
        role_name = "test-bc-%s" % randstr()
        self.invoke(
            ResourceType="Custom::RestrictedRole",
            RoleName=role_name,
            AssumeRolePolicyDocument=BASIC_ASSUME_ROLE_POLICY)

        print(self.iam.list_roles())
        role = self.iam.get_role(RoleName=role_name)
        self.assertEqual(role["Role"]["RoleName"], role_name)
        arp = role["Role"]["AssumeRolePolicyDocument"]
        self.assertEqual(BASIC_ASSUME_ROLE_POLICY, arp)

        self.invoke(
            ResourceType="Custom::RestrictedRole",
            RequestType="Delete",
            RoleName=role_name,
            PhysicalResourceId=role_name)
        with self.assertRaises(BotoClientError):
            self.iam.get_role(RoleName=role_name)

    def test_policy_updates(self):
        create_props = {
            "AssumeRolePolicyDocument": BASIC_ASSUME_ROLE_POLICY,
            "ManagedPolicyArns": [self.power_arn],
            "Policies": [
                {
                    "PolicyName": "strtest",
                    "PolicyDocument": json_dumps(OPEN_MANDATORY_POLICY)
                },
                {
                    "PolicyName": "jsontest",
                    "PolicyDocument": OPEN_MANDATORY_POLICY
                }
            ]
        }

        update1_props = {
            "AssumeRolePolicyDocument": LAMBDA_ASSUME_ROLE_POLICY,
            "ManagedPolicyArns": [self.s3_arn],
            "Policies": [
                {
                    "PolicyName": "strtest",
                    "PolicyDocument": json_dumps(OPEN_MANDATORY_POLICY)
                },
                {
                    "PolicyName": "jsontest2",
                    "PolicyDocument": OPEN_MANDATORY_POLICY
                }
            ]
        }

        update2_props = {
            "AssumeRolePolicyDocument": LAMBDA_ASSUME_ROLE_POLICY,
            "ManagedPolicyArns": [self.s3_arn],
            "Policies": [
                {
                    "PolicyName": "strtest",
                    "PolicyDocument": json_dumps(OPEN_MANDATORY_POLICY)
                },
                {
                    "PolicyName": "jsontest2",
                    "PolicyDocument": S3_POLICY
                }
            ]
        }

        update3_props = {
            "AssumeRolePolicyDocument": LAMBDA_ASSUME_ROLE_POLICY,
            "ManagedPolicyArns": [self.s3_arn],
            "Policies": [
                {
                    "PolicyName": "strtest",
                    "PolicyDocument": json_dumps(OPEN_MANDATORY_POLICY)
                },
                {
                    "PolicyName": "jsontest2",
                    "PolicyDocument": S3_POLICY,
                    "BadPolicy": "yes"
                }
            ]
        }

        update4_props = {
            "AssumeRolePolicyDocument": LAMBDA_ASSUME_ROLE_POLICY,
            "ManagedPolicyArns": [],
            "Policies": [
                {
                    "PolicyName": "jsontest2",
                    "PolicyDocument": {
                        "TRIGGER_INVALID_JSON": "Yes",
                    }
                }
            ]
        }

        response = self.invoke(
            ResourceType="Custom::RestrictedRole", **create_props)
        role_name = response["PhysicalResourceId"]
        self.iam.get_role(RoleName=role_name)
        attached = self.iam.list_attached_role_policies(RoleName=role_name)[
            "AttachedPolicies"]
        self.assertEqual(len(attached), 2)
        policy_arns = set([pol["PolicyArn"] for pol in attached])
        self.assertEqual(policy_arns, {self.mandatory_arn, self.power_arn})

        inline = set(
            self.iam.list_role_policies(RoleName=role_name)["PolicyNames"])
        self.assertEqual(inline, {"strtest", "jsontest"})

        response = self.invoke(
            ResourceType="Custom::RestrictedRole",
            RequestType="Update",
            PhysicalResourceId=role_name,
            OldResourceProperties=create_props,
            **update1_props)
        self.assertEqual("SUCCESS", response["Status"])
        self.iam.get_role(RoleName=role_name)
        attached = self.iam.list_attached_role_policies(RoleName=role_name)[
            "AttachedPolicies"]
        self.assertEqual(len(attached), 2)
        policy_arns = set([pol["PolicyArn"] for pol in attached])
        self.assertEqual(policy_arns, {self.mandatory_arn, self.s3_arn})

        inline = set(
            self.iam.list_role_policies(RoleName=role_name)["PolicyNames"])
        self.assertEqual(inline, {"strtest", "jsontest2"})

        response = self.invoke(
            ResourceType="Custom::RestrictedRole",
            RequestType="Update",
            PhysicalResourceId=role_name,
            OldResourceProperties=update1_props,
            **update2_props)
        self.assertEqual("SUCCESS", response["Status"])
        self.iam.get_role(RoleName=role_name)
        attached = self.iam.list_attached_role_policies(RoleName=role_name)[
            "AttachedPolicies"]
        self.assertEqual(len(attached), 2)
        policy_arns = set([pol["PolicyArn"] for pol in attached])
        self.assertEqual(policy_arns, {self.mandatory_arn, self.s3_arn})

        inline = set(
            self.iam.list_role_policies(RoleName=role_name)["PolicyNames"])
        self.assertEqual(inline, {"strtest", "jsontest2"})

        # Rollback due to invalid parameter
        response = self.invoke(
            ResourceType="Custom::RestrictedRole",
            RequestType="Update",
            PhysicalResourceId=role_name,
            OldResourceProperties=update2_props,
            **update3_props)
        self.assertEqual("FAILED", response["Status"])
        self.iam.get_role(RoleName=role_name)
        attached = self.iam.list_attached_role_policies(RoleName=role_name)[
            "AttachedPolicies"]
        self.assertEqual(len(attached), 2)
        policy_arns = set([pol["PolicyArn"] for pol in attached])
        self.assertEqual(policy_arns, {self.mandatory_arn, self.s3_arn})

        inline = set(
            self.iam.list_role_policies(RoleName=role_name)["PolicyNames"])
        self.assertEqual(inline, {"strtest", "jsontest2"})

        response = self.invoke(
            ResourceType="Custom::RestrictedRole",
            RequestType="Update",
            PhysicalResourceId=role_name,
            OldResourceProperties=update2_props,
            **update4_props)
        self.assertEqual("FAILED", response["Status"])
        self.assertIn(
            "Policy contains TRIGGER_INVALID_JSON", response["Reason"])
        self.iam.get_role(RoleName=role_name)
        attached = self.iam.list_attached_role_policies(RoleName=role_name)[
            "AttachedPolicies"]
        self.assertEqual(len(attached), 2)
        policy_arns = set([pol["PolicyArn"] for pol in attached])
        self.assertEqual(policy_arns, {self.mandatory_arn, self.s3_arn})

        inline = set(
            self.iam.list_role_policies(RoleName=role_name)["PolicyNames"])
        self.assertEqual(inline, {"strtest", "jsontest2"})

    def test_name_change_updates(self):
        create_props = {
            "RoleName": "role1",
            "AssumeRolePolicyDocument": BASIC_ASSUME_ROLE_POLICY,
            "ManagedPolicyArns": [self.power_arn],
            "Policies": [
                {
                    "PolicyName": "strtest",
                    "PolicyDocument": json_dumps(OPEN_MANDATORY_POLICY)
                },
                {
                    "PolicyName": "jsontest",
                    "PolicyDocument": OPEN_MANDATORY_POLICY
                }
            ]
        }

        good_update_props = {
            "RoleName": "role2",
            "AssumeRolePolicyDocument": BASIC_ASSUME_ROLE_POLICY,
            "ManagedPolicyArns": [self.power_arn],
            "Policies": [
                {
                    "PolicyName": "strtest",
                    "PolicyDocument": json_dumps(OPEN_MANDATORY_POLICY)
                },
                {
                    "PolicyName": "jsontest",
                    "PolicyDocument": OPEN_MANDATORY_POLICY
                }
            ]
        }

        bad_update_props = {
            "RoleName": "role3",
            "AssumeRolePolicyDocument": BASIC_ASSUME_ROLE_POLICY,
            "ManagedPolicyArns": [12345],
            "Policies": [
                {
                    "PolicyName": "strtest",
                    "PolicyDocument": json_dumps(OPEN_MANDATORY_POLICY)
                },
                {
                    "PolicyName": "jsontest",
                    "PolicyDocument": OPEN_MANDATORY_POLICY
                }
            ]
        }

        response = self.invoke(
            ResourceType="Custom::RestrictedRole", **create_props)
        role_name = response["PhysicalResourceId"]
        self.iam.get_role(RoleName=role_name)
        self.assertEqual("SUCCESS", response["Status"])

        response = self.invoke(
            ResourceType="Custom::RestrictedRole",
            RequestType="Update",
            PhysicalResourceId=role_name,
            OldResourceProperties=create_props,
            **good_update_props)
        self.assertEqual("SUCCESS", response["Status"])
        role_name = response["PhysicalResourceId"]
        self.iam.get_role(RoleName=role_name)

        response = self.invoke(
            ResourceType="Custom::RestrictedRole",
            RequestType="Update",
            PhysicalResourceId=role_name,
            OldResourceProperties=good_update_props,
            **bad_update_props)
        self.assertEqual("FAILED", response["Status"])
        self.iam.get_role(RoleName=role_name)
        with self.assertRaises(BotoClientError):
            self.iam.get_role(RoleName="role3")

    def test_no_update_path(self):
        role_name = "test-nup-%s" % randstr()
        create_props = {
            "RoleName": role_name,
            "Path": "/",
            "AssumeRolePolicyDocument": BASIC_ASSUME_ROLE_POLICY,
            "ManagedPolicyArns": [self.power_arn],
            "Policies": [
                {
                    "PolicyName": "strtest",
                    "PolicyDocument": json_dumps(OPEN_MANDATORY_POLICY)
                },
                {
                    "PolicyName": "jsontest",
                    "PolicyDocument": OPEN_MANDATORY_POLICY
                }
            ]
        }

        update_props = {
            "RoleName": role_name,
            "Path": "/foo/",
            "AssumeRolePolicyDocument": BASIC_ASSUME_ROLE_POLICY,
            "ManagedPolicyArns": [self.power_arn],
            "Policies": [
                {
                    "PolicyName": "strtest",
                    "PolicyDocument": json_dumps(OPEN_MANDATORY_POLICY)
                },
                {
                    "PolicyName": "jsontest",
                    "PolicyDocument": OPEN_MANDATORY_POLICY
                }
            ]
        }

        response = self.invoke(
            ResourceType="Custom::RestrictedRole", **create_props)
        role_name = response["PhysicalResourceId"]
        self.iam.get_role(RoleName=role_name)
        self.assertEqual("SUCCESS", response["Status"])

        response = self.invoke(
            ResourceType="Custom::RestrictedRole",
            RequestType="Update",
            PhysicalResourceId=role_name,
            OldResourceProperties=create_props,
            **update_props)
        self.assertEqual("FAILED", response["Status"])
        self.assertIn("Cannot update the path to an existing role",
                      response["Reason"])
        role_name = response["PhysicalResourceId"]
        self.iam.get_role(RoleName=role_name)

    def test_create_bad_inline_policy(self):
        response = self.invoke(
            ResourceType="Custom::RestrictedRole", RoleName="role1",
            AssumeRolePolicyDocument=BASIC_ASSUME_ROLE_POLICY,
            Policies=[{"PolicyDocument": {}}])
        self.assertEqual("FAILED", response["Status"])
        self.assertIn("Inline policy missing PolicyName", response["Reason"])

        response = self.invoke(
            ResourceType="Custom::RestrictedRole", RoleName="role1",
            AssumeRolePolicyDocument=BASIC_ASSUME_ROLE_POLICY,
            Policies=[{"PolicyName": "foo"}])
        self.assertEqual("FAILED", response["Status"])
        self.assertIn("Inline policy missing PolicyDocument",
                      response["Reason"])

        response = self.invoke(
            ResourceType="Custom::RestrictedRole", RoleName="role1",
            AssumeRolePolicyDocument=BASIC_ASSUME_ROLE_POLICY,
            Policies=[{"PolicyName": 1, "PolicyDocument": {}}])
        self.assertEqual("FAILED", response["Status"])
        self.assertIn(
            "Invalid type for parameter PolicyName, value: 1, type "
            "<class 'int'>, valid types: <class 'str'>",
            response["Reason"])

        response = self.invoke(
            ResourceType="Custom::RestrictedRole", RoleName="role1",
            AssumeRolePolicyDocument=BASIC_ASSUME_ROLE_POLICY,
            Policies=[{"PolicyName": "", "PolicyDocument": {}}])
        self.assertEqual("FAILED", response["Status"])
        self.assertIn("Invalid length for parameter PolicyName, value: 0",
                      response["Reason"])

        response = self.invoke(
            ResourceType="Custom::RestrictedRole", RoleName="role1",
            AssumeRolePolicyDocument=BASIC_ASSUME_ROLE_POLICY,
            Policies=[{"PolicyName": "foo", "PolicyDocument": {}, "bar": 0}])
        self.assertEqual("FAILED", response["Status"])
        self.assertIn("Invalid inline policy parameter(s): bar",
                      response["Reason"])

        response = self.invoke(
            ResourceType="Custom::RestrictedRole", RoleName="role1",
            AssumeRolePolicyDocument=BASIC_ASSUME_ROLE_POLICY,
            Policies=[{"PolicyName": "foo", "PolicyDocument": 1}])
        self.assertEqual("FAILED", response["Status"])
        self.assertIn(
            "Invalid type for parameter PolicyDocument, value: 1, type "
            "<class 'int'>, valid types: (<class 'str'>, <class 'dict'>)",
            response["Reason"])

    def test_create_missing_assume_role(self):
        response = self.invoke(
            ResourceType="Custom::RestrictedRole", RoleName="role1")
        self.assertEqual("FAILED", response["Status"])
        self.assertIn("AssumeRolePolicyDocument is missing", response["Reason"])

    def test_create_unknown_props(self):
        response = self.invoke(
            ResourceType="Custom::RestrictedRole", RoleName="role1",
            AssumeRolePolicyDocument=BASIC_ASSUME_ROLE_POLICY,
            Invalid=True)
        self.assertEqual("FAILED", response["Status"])
        self.assertIn("Unknown properties: Invalid", response["Reason"])

@mock_iam
class TestDirectInvoke(TestCase):
    """
    Test direct Lambda invocation handling.
    """
    mandatory_arn = ""
    power_arn = ""

    def setUp(self):
        self.iam = boto3.client("iam")
        result = self.iam.create_policy(
            PolicyName="Mandatory",
            PolicyDocument=json_dumps(OPEN_MANDATORY_POLICY))
        environ["MANDATORY_ROLE_POLICY_ARN"] = self.mandatory_arn = \
            result["Policy"]["Arn"]

        result = self.iam.create_policy(
            PolicyName="Power",
            PolicyDocument=json_dumps(POWER_USER_POLICY))
        self.power_arn = result["Policy"]["Arn"]

        ResponseHandler.responses = []

    def invoke(self, **kw): # pylint: disable=R0201
        return rolemaker.lambda_handler(kw, None)

    def test_basic_workflows(self):
        role_name = "test-bw-%s" % randstr()

        result = self.invoke(
            Action="CreateRestrictedRole", RoleName=role_name,
            AssumeRolePolicyDocument=json_dumps(BASIC_ASSUME_ROLE_POLICY))
        self.assertNotIn("Error", result)
        self.assertIn("Role", result)

        role = self.iam.get_role(RoleName=role_name)
        self.assertEqual(role["Role"]["RoleName"], role_name)
        arp = role["Role"]["AssumeRolePolicyDocument"]
        self.assertEqual(BASIC_ASSUME_ROLE_POLICY, arp)

        result = self.invoke(
            Action="AttachRestrictedRolePolicy", RoleName=role_name,
            PolicyArn=self.power_arn)
        self.assertNotIn("Error", result)

        result = self.invoke(
            Action="PutRestrictedRolePolicy", RoleName=role_name,
            PolicyName="Assume",
            PolicyDocument=json_dumps(BASIC_ASSUME_ROLE_POLICY))
        self.assertNotIn("Error", result)

        result = self.iam.list_attached_role_policies(RoleName=role_name)
        policy_arns = set([
            policy["PolicyArn"] for policy in result["AttachedPolicies"]])
        self.assertEqual(policy_arns, {self.mandatory_arn, self.power_arn})

        result = self.iam.list_role_policies(RoleName=role_name)
        self.assertEqual(result["PolicyNames"], ["Assume"])

        result = self.iam.get_role_policy(
            RoleName=role_name, PolicyName="Assume")
        self.assertEqual(result["PolicyDocument"], BASIC_ASSUME_ROLE_POLICY)

        result = self.invoke(
            Action="DetachRestrictedRolePolicy", RoleName=role_name,
            PolicyArn=self.power_arn)
        self.assertNotIn("Error", result)

        result = self.invoke(
            Action="DeleteRestrictedRolePolicy", RoleName=role_name,
            PolicyName="Assume")

        result = self.iam.list_attached_role_policies(RoleName=role_name)
        policy_arns = set([
            policy["PolicyArn"] for policy in result["AttachedPolicies"]])
        self.assertEqual(
            policy_arns, {environ["MANDATORY_ROLE_POLICY_ARN"]})

        result = self.iam.list_role_policies(RoleName=role_name)
        self.assertEqual(result["PolicyNames"], [])

        result = self.invoke(
            Action="UpdateAssumeRestrictedRolePolicy", RoleName=role_name,
            PolicyDocument=json_dumps(LAMBDA_ASSUME_ROLE_POLICY))
        self.assertNotIn("Error", result)

        # Moto doesn't implement this yet.
        if False: # pylint: disable=W0125
            result = self.invoke(
                Action="UpdateRestrictedRoleDescription", RoleName=role_name,
                Description="New Description")
            self.assertNotIn("Error", result)
            self.assertEqual(
                "New Description",
                self.iam.get_role(RoleName=role_name)["Role"]["Description"])

        result = self.invoke(
            Action="DeleteRestrictedRole", RoleName=role_name)
        self.assertNotIn("Error", result)

        with self.assertRaises(BotoClientError):
            role = self.iam.get_role(RoleName=role_name)

    def test_attempt_modify_nonrestricted(self):
        role_name = "test-amn-%s" % randstr()
        def check_result(result):
            self.assertIn("Error", result)
            self.assertEqual(result["Error"]["Code"], "InvalidParameterValue")
            self.assertIn(
                "Role %s is not a restricted role" % role_name,
                result["Error"]["Message"])

        self.iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json_dumps(BASIC_ASSUME_ROLE_POLICY))

        result = self.invoke(
            Action="AttachRestrictedRolePolicy", RoleName=role_name,
            PolicyArn=self.power_arn)
        check_result(result)

        result = self.invoke(
            Action="DetachRestrictedRolePolicy", RoleName=role_name,
            PolicyArn=self.power_arn)
        check_result(result)

        result = self.invoke(
            Action="PutRestrictedRolePolicy", RoleName=role_name,
            PolicyName="foo", PolicyDocument="{}")
        check_result(result)

        result = self.invoke(
            Action="DeleteRestrictedRolePolicy", RoleName=role_name,
            PolicyName="foo")
        check_result(result)

        result = self.invoke(
            Action="UpdateAssumeRestrictedRolePolicy", RoleName=role_name,
            PolicyDocument=json_dumps(BASIC_ASSUME_ROLE_POLICY))
        check_result(result)

        result = self.invoke(
            Action="UpdateRestrictedRoleDescription", RoleName=role_name,
            Description="Hello world")
        check_result(result)

    def test_attempt_detach_mandatory(self):
        role_name = "test-dm-%s" % randstr()
        self.invoke(
            Action="CreateRestrictedRole", RoleName=role_name,
            AssumeRolePolicyDocument=json_dumps(BASIC_ASSUME_ROLE_POLICY))

        result = self.invoke(
            Action="DetachRestrictedRolePolicy", RoleName=role_name,
            PolicyArn=environ["MANDATORY_ROLE_POLICY_ARN"])

        self.assertIn("Error", result)
        self.assertEqual(result["Error"]["Code"], "InvalidParameterValue")
        self.assertIn("Cannot detach the mandatory policy.",
                      result["Error"]["Message"])

    def test_empty_rolename(self):
        def check_result(result):
            self.assertIn("Error", result)
            self.assertEqual(result["Error"]["Code"], "InvalidParameterValue")
            self.assertIn(
                "Invalid length for parameter RoleName, value: 0",
                result["Error"]["Message"])

        result = self.invoke(
            Action="CreateRestrictedRole",
            AssumeRolePolicyDocument=json_dumps(BASIC_ASSUME_ROLE_POLICY))
        check_result(result)

        result = self.invoke(
            Action="CreateRestrictedRole",
            RoleName="",
            AssumeRolePolicyDocument=json_dumps(BASIC_ASSUME_ROLE_POLICY))
        check_result(result)

        result = self.invoke(Action="DeleteRestrictedRole")
        check_result(result)

        result = self.invoke(Action="DeleteRestrictedRole", RoleName="")
        check_result(result)

        result = self.invoke(
            Action="AttachRestrictedRolePolicy",
            PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
        check_result(result)

        result = self.invoke(
            Action="AttachRestrictedRolePolicy",
            RoleName="",
            PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
        check_result(result)

        result = self.invoke(
            Action="DetachRestrictedRolePolicy",
            PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
        check_result(result)

        result = self.invoke(
            Action="DetachRestrictedRolePolicy",
            RoleName="",
            PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
        check_result(result)

        result = self.invoke(
            Action="UpdateRestrictedRoleDescription",
            Description="This is a test description")
        check_result(result)

        result = self.invoke(
            Action="UpdateRestrictedRoleDescription",
            RoleName="",
            Description="This is a test description")
        check_result(result)

        result = self.invoke(
            Action="UpdateAssumeRestrictedRolePolicy",
            PolicyDocument="{}")
        check_result(result)

        result = self.invoke(
            Action="UpdateAssumeRestrictedRolePolicy",
            RoleName="",
            PolicyDocument="{}")
        check_result(result)

        result = self.invoke(
            Action="PutRestrictedRolePolicy",
            PolicyName="Foo",
            PolicyDocument="{}")
        check_result(result)

        result = self.invoke(
            Action="PutRestrictedRolePolicy",
            RoleName="",
            PolicyName="Foo",
            PolicyDocument="{}")
        check_result(result)

        result = self.invoke(
            Action="DeleteRestrictedRolePolicy",
            PolicyName="Foo")
        check_result(result)

        result = self.invoke(
            Action="DeleteRestrictedRolePolicy",
            RoleName="",
            PolicyName="Foo")
        check_result(result)

    def test_delete_nonexistent_role(self):
        role_name = "test-dnr-%s" % randstr()
        result = self.invoke(
            Action="DeleteRestrictedRole", RoleName=role_name)
        self.assertIn("Error", result)
        self.assertEqual(result["Error"]["Code"], "NoSuchEntity")
        self.assertIn(
            "Role %s not found" % role_name, result["Error"]["Message"])

    def test_delete_nonexistent_attached_policy(self):
        role_name = "test-dnap-%s" % randstr()
        self.invoke(
            Action="CreateRestrictedRole", RoleName=role_name,
            AssumeRolePolicyDocument=json_dumps(BASIC_ASSUME_ROLE_POLICY))

        result = self.invoke(
            Action="DetachRestrictedRolePolicy", RoleName=role_name,
            PolicyArn="arn:aws:iam:::policy/nonexistent")
        self.assertIn("Error", result)
        self.assertEqual(result["Error"]["Code"], "NoSuchEntity")
        self.assertIn(
            "Policy arn:aws:iam:::policy/nonexistent was not found",
            result["Error"]["Message"])

    def test_attempt_delete_role_with_policies(self):
        role_name = "test-drwp-%s" % randstr()
        self.invoke(
            Action="CreateRestrictedRole", RoleName=role_name,
            AssumeRolePolicyDocument=json_dumps(BASIC_ASSUME_ROLE_POLICY))

        result = self.invoke(
            Action="AttachRestrictedRolePolicy", RoleName=role_name,
            PolicyArn=self.power_arn)
        self.assertNotIn("Error", result)

        result = self.invoke(
            Action="DeleteRestrictedRole", RoleName=role_name)
        self.assertIn("Error", result)
        self.assertEqual(result["Error"]["Code"], "DeleteConflict")
        self.assertIn("Cannot delete entity, must detach all policies first.",
                      result["Error"]["Message"])

        result = self.invoke(
            Action="DetachRestrictedRolePolicy", RoleName=role_name,
            PolicyArn=self.power_arn)
        self.assertNotIn("Error", result)

        result = self.invoke(
            Action="PutRestrictedRolePolicy", RoleName=role_name,
            PolicyName="inline1",
            PolicyDocument=json_dumps(BASIC_ASSUME_ROLE_POLICY))
        self.assertNotIn("Error", result)

        result = self.invoke(
            Action="DeleteRestrictedRole", RoleName=role_name)
        self.assertIn("Error", result)
        self.assertEqual(result["Error"]["Code"], "DeleteConflict")
        self.assertIn("Cannot delete entity, must delete policies first.",
                      result["Error"]["Message"])

        result = self.invoke(
            Action="DeleteRestrictedRolePolicy", RoleName=role_name,
            PolicyName="inline1")
        self.assertNotIn("Error", result)

        result = self.invoke(
            Action="DeleteRestrictedRole", RoleName=role_name)
        self.assertNotIn("Error", result)

    def test_create_bad_parameters(self):
        role_name = "test-cbp-%s" % randstr()
        def check_result(result, message):
            self.assertIn("Error", result)
            self.assertEqual(result["Error"]["Code"], "InvalidParameterValue")
            self.assertIn(message, result["Error"]["Message"])

        check_result(
            self.invoke(
                Action="CreateRestrictedRole", RoleName=1234,
                AssumeRolePolicyDocument="{}", Path="/", Description="1"),
            "Invalid type for parameter RoleName, value: 1")

        check_result(
            self.invoke(
                Action="CreateRestrictedRole", RoleName=role_name,
                AssumeRolePolicyDocument="", Path="/", Description="1"),
            "Invalid length for parameter AssumeRolePolicyDocument, value: 0")

        check_result(
            self.invoke(
                Action="CreateRestrictedRole", RoleName=role_name,
                AssumeRolePolicyDocument=1, Path="/", Description="1"),
            "Invalid type for parameter AssumeRolePolicyDocument, value: 1")

        check_result(
            self.invoke(
                Action="CreateRestrictedRole", RoleName=role_name,
                AssumeRolePolicyDocument="{}", Path=1, Description="1"),
            "Invalid type for parameter Path, value: 1")

        check_result(
            self.invoke(
                Action="CreateRestrictedRole", RoleName=role_name,
                AssumeRolePolicyDocument="{}", Path="/", Description=1),
            "Invalid type for parameter Description, value: 1")

    def test_attach_detach_bad_parameters(self):
        role_name = "test-adbp-%s" % randstr()
        def check_result(result, message):
            self.assertIn("Error", result)
            self.assertEqual(result["Error"]["Code"], "InvalidParameterValue")
            self.assertIn(message, result["Error"]["Message"])

        self.invoke(
            Action="CreateRestrictedRole",
            RoleName=role_name,
            AssumeRolePolicyDocument=json_dumps(BASIC_ASSUME_ROLE_POLICY))

        check_result(
            self.invoke(
                Action="AttachRestrictedRolePolicy", RoleName="",
                PolicyArn=self.power_arn),
            "Invalid length for parameter RoleName, value: 0")

        check_result(
            self.invoke(
                Action="AttachRestrictedRolePolicy", RoleName=1,
                PolicyArn=self.power_arn),
            "Invalid type for parameter RoleName, value: 1")

        check_result(
            self.invoke(
                Action="AttachRestrictedRolePolicy", RoleName=role_name,
                PolicyArn=""),
            "Invalid length for parameter PolicyArn, value: 0")

        check_result(
            self.invoke(
                Action="AttachRestrictedRolePolicy", RoleName=role_name,
                PolicyArn=1),
            "Invalid type for parameter PolicyArn, value: 1")

        check_result(
            self.invoke(
                Action="DetachRestrictedRolePolicy", RoleName="",
                PolicyArn=self.power_arn),
            "Invalid length for parameter RoleName, value: 0")

        check_result(
            self.invoke(
                Action="DetachRestrictedRolePolicy", RoleName=1,
                PolicyArn=self.power_arn),
            "Invalid type for parameter RoleName, value: 1")

        check_result(
            self.invoke(
                Action="DetachRestrictedRolePolicy", RoleName=role_name,
                PolicyArn=""),
            "Invalid length for parameter PolicyArn, value: 0")

        check_result(
            self.invoke(
                Action="DetachRestrictedRolePolicy", RoleName=role_name,
                PolicyArn=1),
            "Invalid type for parameter PolicyArn, value: 1")

    def test_put_delete_bad_parameters(self):
        role_name = "test-pdbp-%s" % randstr()

        def check_result(result, message):
            self.assertIn("Error", result)
            self.assertEqual(result["Error"]["Code"], "InvalidParameterValue")
            self.assertIn(message, result["Error"]["Message"])

        self.invoke(
            Action="CreateRestrictedRole", RoleName=role_name,
            AssumeRolePolicyDocument=json_dumps(BASIC_ASSUME_ROLE_POLICY))

        check_result(
            self.invoke(
                Action="PutRestrictedRolePolicy", RoleName="",
                PolicyName="inline1",
                PolicyDocument=json_dumps(POWER_USER_POLICY)),
            "Invalid length for parameter RoleName, value: 0")

        check_result(
            self.invoke(
                Action="PutRestrictedRolePolicy", RoleName=1,
                PolicyName="inline1",
                PolicyDocument=json_dumps(POWER_USER_POLICY)),
            "Invalid type for parameter RoleName, value: 1")

        check_result(
            self.invoke(
                Action="PutRestrictedRolePolicy", RoleName=role_name,
                PolicyName="",
                PolicyDocument=json_dumps(POWER_USER_POLICY)),
            "Invalid length for parameter PolicyName, value: 0")

        check_result(
            self.invoke(
                Action="PutRestrictedRolePolicy", RoleName=role_name,
                PolicyName=1,
                PolicyDocument=json_dumps(POWER_USER_POLICY)),
            "Invalid type for parameter PolicyName, value: 1")

        check_result(
            self.invoke(
                Action="PutRestrictedRolePolicy", RoleName=role_name,
                PolicyName="inline1", PolicyDocument=""),
            "Invalid length for parameter PolicyDocument, value: 0")

        check_result(
            self.invoke(
                Action="PutRestrictedRolePolicy", RoleName=role_name,
                PolicyName="inline1", PolicyDocument=1),
            "Invalid type for parameter PolicyDocument, value: 1")

        check_result(
            self.invoke(
                Action="DeleteRestrictedRolePolicy", RoleName="",
                PolicyName="inline1"),
            "Invalid length for parameter RoleName, value: 0")

        check_result(
            self.invoke(
                Action="DeleteRestrictedRolePolicy", RoleName=1,
                PolicyName="inline1"),
            "Invalid type for parameter RoleName, value: 1")

        check_result(
            self.invoke(
                Action="DeleteRestrictedRolePolicy", RoleName=role_name,
                PolicyName=""),
            "Invalid length for parameter PolicyName, value: 0")

        check_result(
            self.invoke(
                Action="DeleteRestrictedRolePolicy", RoleName=role_name,
                PolicyName=1),
            "Invalid type for parameter PolicyName, value: 1")

    def test_missing_environ(self):
        def check_result(result):
            self.assertIn("Error", result)
            self.assertEqual(result["Error"]["Code"], "InternalFailure")
            self.assertEqual(result["Error"]["Type"], "Receiver")
            self.assertIn(
                "Environment variable MANDATORY_ROLE_POLICY_ARN has not "
                "been set on the Lambda function.",
                result["Error"]["Message"])

        result = self.invoke(
            Action="CreateRestrictedRole", RoleName="ok-role",
            AssumeRolePolicyDocument=json_dumps(OPEN_MANDATORY_POLICY))
        self.assertNotIn("Error", result)

        del environ["MANDATORY_ROLE_POLICY_ARN"]
        try:
            check_result(self.invoke(
                Action="CreateRestrictedRole", RoleName="test-role-missing-env",
                AssumeRolePolicyDocument="{}", Path="/", Description=""))

            check_result(self.invoke(
                Action="DeleteRestrictedRole", RoleName="ok-role"))

            check_result(self.invoke(
                Action="AttachRestrictedRolePolicy", RoleName="ok-role",
                PolicyArn=self.power_arn))

            check_result(self.invoke(
                Action="DetachRestrictedRolePolicy", RoleName="ok-role",
                PolicyArn=self.power_arn))

            check_result(self.invoke(
                Action="PutRestrictedRolePolicy", RoleName="ok-role",
                PolicyName="inline1",
                PolicyDocument=json_dumps(POWER_USER_POLICY)))

            check_result(self.invoke(
                Action="DeleteRestrictedRolePolicy", RoleName="ok-role",
                PolicyName="inline1"))

            check_result(self.invoke(
                Action="UpdateRestrictedRoleDescription", RoleName="ok-role",
                Description="A new description"))

            check_result(self.invoke(
                Action="UpdateAssumeRestrictedRolePolicy", RoleName="ok-role",
                PolicyDocument=json_dumps(OPEN_MANDATORY_POLICY)))
        finally:
            environ["MANDATORY_ROLE_POLICY_ARN"] = self.mandatory_arn

    def test_bad_mandatory_policy(self):
        invalid = "arn:aws:iam::aws:invalid-policy-name"
        environ["MANDATORY_ROLE_POLICY_ARN"] = invalid

        try:
            result = self.invoke(
                Action="CreateRestrictedRole", RoleName="test-role-bad-mand",
                AssumeRolePolicyDocument="{}", Path="/", Description="")
            self.assertIn("Error", result)
            self.assertEqual(result["Error"]["Code"], "InternalFailure")
            self.assertEqual(result["Error"]["Type"], "Receiver")
            self.assertIn(
                "Unable to attach MANDATORY_ROLE_POLICY_ARN %s "
                "to newly created role." % invalid, result["Error"]["Message"])

            with self.assertRaises(BotoClientError):
                self.iam.get_role(RoleName="test-role-bad-mand")

        finally:
            environ["MANDATORY_ROLE_POLICY_ARN"] = self.mandatory_arn

    def test_delete_non_restricted_role(self):
        self.iam.create_role(
            RoleName="ok-role-non-restrict",
            AssumeRolePolicyDocument=json_dumps(BASIC_ASSUME_ROLE_POLICY))

        result = self.invoke(
            Action="DeleteRestrictedRole", RoleName="ok-role-non-restrict")
        self.assertIn("Error", result)
        self.assertEqual(result["Error"]["Code"], "InvalidParameterValue")
        self.assertIn("Role ok-role-non-restrict is not a restricted "
                      "role.", result["Error"]["Message"])

    def test_unknown_action(self):
        result = self.invoke(Action="NotAnAction")
        self.assertIn("Error", result)
        self.assertEqual(result["Error"]["Code"], "InvalidAction")

    def test_unknown_parameters(self):
        result = self.invoke(Action="CreateRestrictedRole", Invalid=1)
        self.assertIn("Error", result)
        self.assertEqual(result["Error"]["Code"], "InvalidParameterValue")
        self.assertIn("Unknown parameter(s): Invalid",
                      result["Error"]["Message"])
