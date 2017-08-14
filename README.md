# Rolemaker
Rolemaker allows unprivileged users to create restricted AWS [IAM roles](http://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html).

Rolemaker introduces the concept of restricted roles. These are IAM roles that have a mandatory IAM policy applied that typically has `Deny` rules to prohibit certain calls. This policy is attached when the role is created and cannot be detached by an unprivileged user.

By "unprivileged," we mean the user does not have permission to call the following APIs:

* [`iam:CreateRole`](http://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateRole.html) -- this would allow the user to create roles with unrestricted permissions.
* [`iam:CreateGroup`](http://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateGroup.html) -- this would allow the user to create groups with unrestricted permissions.
* [`iam:CreateUser`](http://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateUser.html) -- this would allow the user to create other users with unrestricted permissions.
* [`iam:DetachRolePolicy`](http://docs.aws.amazon.com/IAM/latest/APIReference/API_DetachRolePolicy.html) -- this would allow the user to remove the mandatory policy applied to a role.
* [`iam:DetachGroupPolicy`](http://docs.aws.amazon.com/IAM/latest/APIReference/API_DetachGroupPolicy.html) -- this would allow the user to remove the mandatory policy applied to a group.
* [`iam:DetachUserPolicy`](http://docs.aws.amazon.com/IAM/latest/APIReference/API_DetachUserPolicy.html) -- this would allow the user to remove the mandatory policy applied to a user.

Most sites that need to meet a compliance rules will impose greater restrictions than the above -- e.g. most users have no reason to be calling [`iam:CreateOpenIDConnectProvider`](http://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateOpenIDConnectProvider.html) -- but this is what's required to prevent the creation of unrestricted IAM entities.

Note that the prohibition on `iam:Detach\*Policy` means that users effectively can't call the corresponding `iam:Delete\*` APIs: roles, groups, and users must have no policies attached when they are deleted.

# API and CLI usage (for users)
Rolemaker provides alternative APIs for mutating restricted roles. The arguments and return values are the same as those for the corresponding IAM API.

* `rolemaker:CreateRestrictedRole(RoleName, AssumeRolePolicyDocument, Path="/", Description="") -> {"Role": {"Path": str, "RoleName": str, "RoleId": str, "Arn": str, "CreateDate": timestamp, "AssumeRolePolicyDocument": dict, "Description": str}}` -- Create a role with a mandatory policy attached.
* `rolemaker:DeleteRestrictedRole(RoleName) -> None` -- Detach the mandatory policy from the role, then delete it.
* `rolemaker:AttachRestrictedRolePolicy(RoleName, PolicyArn) -> None` -- Attach an IAM policy to the role.
* `rolemaker:DetachRestrictedRolePolicy(RoleName, PolicyArn) -> None` -- Detach an IAM policy from the role. The mandatory policy may not be detached.
* `rolemaker:PutRestrictedRolePolicy(RoleName, PolicyName, PolicyDocument) -> None` -- Create an inline policy on the role.
* `rolemaker:DeleteRestrictedRolePolicy(RoleName, PolicyName) -> None` -- Remove an inline policy from the role.
* `rolemaker:UpdateAssumeRestrictedRolePolicy(RoleName, PolicyDocument) -> None` -- Update the AssumeRole policy that grants other entities the permission to assume the role.
* `rolemaker:UpdateRestrictedRoleDescription(RoleName, Description) -> None` -- Changes the user-provided description for the role.

Currently, Rolemaker does not provide APIs for restricted groups or users; this will probably happen eventually. I don't have plans to support non-mutating APIs like `ListRestrictedRolePolicies` -- just call the corresponding IAM API.

To invoke a Rolemaker API programmatically, you call the Lambda function where it is installed and pass a JSON-formatted event body with `Action` set to the API name. For example, to call `CreateRestrictedRole` from Python:

```python
import boto3, json

# Note that you need to make the call in the correct region. IAM is
# global, but Lambda is not. Replace "us-west-2" with the correct
# region.
lambda_client = boto3.client("lambda", region_name="us-west-2")

create_args = {
    "Action": "CreateRestrictedRole",
    "RoleName": "TestRole",
    "AssumeRolePolicyDocument": json.dumps({
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Princpal": { "Service": "ec2.amazonaws.com" }
        }
    })
}
response = lambda_client.invoke(
    FunctionName="Rolemaker",
    Payload=json.dumps(create_args).encode("utf-8"))
result = json.loads(response["Payload"].read().decode("utf-8"))
print(result)
# Will be something like: {"Role": {"Name": "TestRole", "Path": "/" ...}}
```

A CLI wrapper is provided to make this (somewhat) easier from the [Ionosphere distribution endpoint](https://ionosphere-cfn-us-west-2.s3.amazonaws.com/rolemaker). The above call would look like:

```
% rolemaker create-restricted-role --role-name TestRole --assume-role-policy-document '\
{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "sts:AssumeRole",
        "Principal": {"Service": "ec2.amazonaws.com"}
    }
}'
```

# CloudFormation usage
Rolemaker also supports the `Custom::RestrictedRole` resource. Usage follows the [AWS::IAM::Role](http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html) resource, with the additional `ServiceToken` property for specifying the Rolemaker Lambda function ARN.

```yaml
Resources:
  MyRestrictedRole:
    Type: Custom::RestrictedRole
    Properties:
      ServiceToken: arn:aws:lambda:region:123456789012:function:Rolemaker
      RoleName: MyRestrictedRole
      AssumeRolePolicyDocument: ...
      Path: "/"
      Description: Restricted role example
      ManagedPolicyArns:
        - arn:aws:iam::aws:aws:policy/...
      Policies:
        - PolicyName: name
          PolicyDocument: ...
```

# Installation (for administrators)

## Create the mandatory policy ARN
First, create an IAM policy for your restricted roles and get its ARN. If you're unfamiliar with the provess, read *[Tutorial: Create and Attach Your First Customer Managed Policy](http://docs.aws.amazon.com/IAM/latest/UserGuide/tutorial_managed-policies.html)*.

## Deploy the Lambda function
The easiest way to deploy is via [Terraform](https://www.terraform.io/). Download the [rolemaker.tf](https://ionosphere-cfn-us-west-2/rolemaker.tf) Terraform template, run `terraform apply` on it.

A CloudFormation template is also provided at `https://ionosphere-cfn-us-west-2.s3.amazonaws.com/rolemaker-cfn.yaml`. (Note that the Lambda IAM role created by this will not have a description; as of this writing, CloudFormation does not support role descriptions.)

You can also install the Lambda function manually:
* The ZIP file is available at: https://ionosphere-cfn-us-west-2.s3.amazonaws.com/rolemaker.zip
* Specify `python3.6` as the runtime.
* Increase the timeout to 30 seconds (or more).
* Use a role that has permission to make the following IAM calls: `iam:AttachRolePolicy`, `iam:CreateRole`, `iam:DeleteRole`, `iam:DeleteRolePolicy`, `iam:GetRole`, `iam:ListAttachedRolePolicies`, `iam:ListRolePolicies`, `iam:PutRolePolicy`, `iam:UpdateAssumeRolePolicy`, `iam:UpdateRoleDescription`.
* Add the environment variable `MANDATORY_ROLE_POLICY_ARN` and specify the ARN from the previous step.

## Authorize users to call the Lambda function
This is typically done via a customer managed policy applied to a user or group. You can also do this via an inline policy for group (or even a user, but this doesn't scale well). The statement should look something like:

```json
{
    "Version": "2012-10-17",
    "Statement": {
        "Action": "lambda:Invoke",
        "Effect": "Allow",
        "Resource": "arn:aws:lambda:us-west-2:123456789012:function:Rolemaker"
    }
}
```

Replace the resource ARN with your actual Lambda function ARN.
