"""
Test the Lambda handler.
"""
# pylint: disable=C0103,C0111,R0904

from http.server import BaseHTTPRequestHandler, HTTPServer
from json import dumps as json_dumps, loads as json_loads
from os import environ
from threading import Thread
from unittest import TestCase

import boto3
from moto import mock_iam
import rolemaker

# Fixes for Moto's unimplemented detach_role_policy API.
# https://github.com/spulec/moto/pull/1052
from moto.iam.exceptions import IAMNotFoundException
from moto.iam.models import IAMBackend, iam_backend, ManagedPolicy, Role             # pylint: disable=C0412
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

class ResponseHandler(BaseHTTPRequestHandler):
    """
    Handles S3 POSTs that the Lambda handler sends its results to.
    """
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
    "Statment": [
        {
            "Effect": "Allow",
            "NotAction": "iam:*",
            "Principal": "*"
        },
        {
            "Effect": "Allow",
            "Action": ["iam:Get*", "iam:List*"],
            "Principal": "*"
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

@mock_iam
class TestCustomResourceHandler(TestCase):
    """
    Test CloudFormation Custom::RestrictedRole resource handling.
    """
    mandatory_arn = ""
    power_arn = ""

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

        ResponseHandler.responses = []
        return

    def invoke(self, ResourceType, RequestType="Create",
               LogicalResourceId="LogicalResourceId", **kw):
        sockname = self.server.socket.getsockname()

        event = {
            "StackId": "stack-1234",
            "RequestId": "req-1234",
            "LogicalResourceId": LogicalResourceId,
            "RequestType": RequestType,
            "ResourceType": ResourceType,
            "ResponseURL": "http://%s:%s/" % (sockname[0], sockname[1])
        }

        if "PhysicalResourceId" in kw:
            event["PhysicalResourceId"] = kw.pop("PhysicalResourceId")

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

    def test_basic_create(self):
        self.invoke(
            ResourceType="Custom::RestrictedRole",
            RoleName="test-role",
            AssumeRolePolicyDocument=BASIC_ASSUME_ROLE_POLICY)

        print(self.iam.list_roles())
        role = self.iam.get_role(RoleName="test-role")
        self.assertEqual(role["Role"]["RoleName"], "test-role")
        arp = role["Role"]["AssumeRolePolicyDocument"]
        self.assertEqual(BASIC_ASSUME_ROLE_POLICY, arp)

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
        result = self.invoke(
            Action="CreateRestrictedRole",
            RoleName="test-role",
            AssumeRolePolicyDocument=json_dumps(BASIC_ASSUME_ROLE_POLICY))
        self.assertNotIn("Error", result)
        self.assertIn("Role", result)

        role = self.iam.get_role(RoleName="test-role")
        self.assertEqual(role["Role"]["RoleName"], "test-role")
        arp = role["Role"]["AssumeRolePolicyDocument"]
        self.assertEqual(BASIC_ASSUME_ROLE_POLICY, arp)

        result = self.invoke(
            Action="AttachRestrictedRolePolicy",
            RoleName="test-role",
            PolicyArn=self.power_arn)
        self.assertNotIn("Error", result)

        result = self.invoke(
            Action="PutRestrictedRolePolicy",
            RoleName="test-role",
            PolicyName="Assume",
            PolicyDocument=json_dumps(BASIC_ASSUME_ROLE_POLICY))
        self.assertNotIn("Error", result)

        result = self.iam.list_attached_role_policies(RoleName="test-role")
        policy_arns = set([
            policy["PolicyArn"] for policy in result["AttachedPolicies"]])
        self.assertEqual(policy_arns, {self.mandatory_arn, self.power_arn})

        result = self.iam.list_role_policies(RoleName="test-role")
        self.assertEqual(result["PolicyNames"], ["Assume"])

        result = self.iam.get_role_policy(
            RoleName="test-role", PolicyName="Assume")
        self.assertEqual(result["PolicyDocument"], BASIC_ASSUME_ROLE_POLICY)

        result = self.invoke(
            Action="DetachRestrictedRolePolicy",
            RoleName="test-role",
            PolicyArn=self.power_arn)
        self.assertNotIn("Error", result)

        result = self.invoke(
            Action="DeleteRestrictedRolePolicy",
            RoleName="test-role",
            PolicyName="Assume")

        result = self.iam.list_attached_role_policies(RoleName="test-role")
        policy_arns = set([
            policy["PolicyArn"] for policy in result["AttachedPolicies"]])
        self.assertEqual(
            policy_arns, {environ["MANDATORY_ROLE_POLICY_ARN"]})

        result = self.iam.list_role_policies(RoleName="test-role")
        self.assertEqual(result["PolicyNames"], [])


    def test_attempt_modify_nonrestricted(self):
        def check_result(result):
            self.assertIn("Error", result)
            self.assertEqual(result["Error"]["Code"], "InvalidParameterValue")
            self.assertIn("Role non-restricted is not a restricted role",
                          result["Error"]["Message"])

        self.iam.create_role(
            RoleName="non-restricted",
            AssumeRolePolicyDocument=json_dumps(BASIC_ASSUME_ROLE_POLICY))

        result = self.invoke(
            Action="AttachRestrictedRolePolicy",
            RoleName="non-restricted",
            PolicyArn=self.power_arn)
        check_result(result)

        result = self.invoke(
            Action="DetachRestrictedRolePolicy",
            RoleName="non-restricted",
            PolicyArn=self.power_arn)
        check_result(result)

        result = self.invoke(
            Action="PutRestrictedRolePolicy",
            RoleName="non-restricted",
            PolicyName="foo",
            PolicyDocument="{}")
        check_result(result)

        result = self.invoke(
            Action="DeleteRestrictedRolePolicy",
            RoleName="non-restricted",
            PolicyName="foo")
        check_result(result)

        result = self.invoke(
            Action="UpdateAssumeRestrictedRolePolicy",
            RoleName="non-restricted",
            PolicyDocument=json_dumps(BASIC_ASSUME_ROLE_POLICY))
        check_result(result)

        result = self.invoke(
            Action="UpdateRestrictedRoleDescription",
            RoleName="non-restricted",
            Description="Hello world")
        check_result(result)

    def test_attempt_detach_mandatory(self):
        self.invoke(
            Action="CreateRestrictedRole",
            RoleName="detach-mandatory",
            AssumeRolePolicyDocument=json_dumps(BASIC_ASSUME_ROLE_POLICY))

        result = self.invoke(
            Action="DetachRestrictedRolePolicy",
            RoleName="detach-mandatory",
            PolicyArn=environ["MANDATORY_ROLE_POLICY_ARN"])

        self.assertIn("Error", result)
        self.assertEqual(result["Error"]["Code"], "InvalidParameterValue")
        self.assertIn("Cannot detach the mandatory policy.",
                      result["Error"]["Message"])

    def test_empty_rolename(self):
        def check_result(result):
            self.assertIn("Error", result)
            self.assertEqual(result["Error"]["Code"], "InvalidParameterValue")
            self.assertIn("RoleName cannot be empty", result["Error"]["Message"])

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
        result = self.invoke(
            Action="DeleteRestrictedRole",
            RoleName="nonexistent")
        self.assertIn("Error", result)
        self.assertEqual(result["Error"]["Code"], "NoSuchEntity")
        self.assertIn("Role nonexistent not found", result["Error"]["Message"])

    def test_delete_nonexistent_attached_policy(self):
        self.invoke(
            Action="CreateRestrictedRole",
            RoleName="detach-nonexistent",
            AssumeRolePolicyDocument=json_dumps(BASIC_ASSUME_ROLE_POLICY))

        result = self.invoke(
            Action="DetachRestrictedRolePolicy",
            RoleName="detach-mandatory",
            PolicyArn="arn:aws:iam:::policy/nonexistent")
        self.assertIn("Error", result)
        self.assertEqual(result["Error"]["Code"], "NoSuchEntity")
        self.assertIn(
            "Policy arn:aws:iam:::policy/nonexistent was not found",
            result["Error"]["Message"])
