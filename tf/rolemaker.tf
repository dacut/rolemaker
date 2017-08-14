variable "function_name" { default = "Rolemaker" }
variable "function_role_name" { default = "Lambda-Rolemaker" }
variable "function_version" { default = "rx79ihjhERQ8WTK3WZVkcbLRLq5yUcXC" }
variable "mandatory_policy_arn" {
    # Set this to an IAM policy ARN that should be applied to each role
    # created.
}
variable "region" {}

data "aws_partition" "current" {}

provider "aws" {
    region = "${var.region}"
}

# The Rolemaker Lambda function
resource "aws_lambda_function" "rolemaker" {
    function_name = "${var.function_name}"
    s3_bucket = "ionosphere-cfn-us-west-2"
    s3_key = "rolemaker.zip"
    s3_object_version = "${var.function_version}"
    handler = "rolemaker_server.lambda_handler"
    role = "${aws_iam_role.lambda.arn}"
    runtime = "python3.6"
    timeout = "30"
    environment {
        variables = {
            MANDATORY_ROLE_POLICY_ARN = "${var.mandatory_policy_arn}"
        }
    }
}

# The IAM role for the Lambda function.
resource "aws_iam_role" "lambda" {
    name = "${var.function_role_name}"
    description = "Lambda role for executing the Rolemaker function"
    force_detach_policies = true
    assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": {
        "Action": "sts:AssumeRole",
        "Effect": "Allow",
        "Principal": { "Service": "lambda.amazonaws.com" }
    }
}
EOF
}

# Allow Lambda to write to CloudWatch logs.
resource "aws_iam_role_policy_attachment" "lambda_cw_logs" {
    role = "${aws_iam_role.lambda.name}"
    policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Function-specific rules.
resource "aws_iam_role_policy" "lambda" {
    name = "IAMAccess"
    role = "${aws_iam_role.lambda.name}"
    policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": {
        "Action": [
            "iam:AttachRolePolicy",
            "iam:CreateRole",
            "iam:DeleteRole",
            "iam:DeleteRolePolicy",
            "iam:DetachRolePolicy",
            "iam:GetRole",
            "iam:ListAttachedRolePolicies",
            "iam:ListRolePolicies",
            "iam:PutRolePolicy",
            "iam:UpdateAssumeRolePolicy",
            "iam:UpdateRoleDescription"
        ],
        "Effect": "Allow",
        "Resource": "*"
    }
}
EOF
}
