#!/usr/bin/env python
from __future__ import absolute_import, division, print_function
from multiprocessing import Pool
from types import MethodType
from urllib import unquote as url_unquote

"""
Missing methods for IAM related to managed policies.  Boto 2.38 (current as
of 2015-11-10) appears to have omitted these API by mistake.
"""
def attach_group_policy(iam, policy_arn, group_name):
    """
    Attach a managed policy (specified by ARN) to a group (specified by
    group name).
    """
    return iam.get_response(
        'AttachGroupPolicy', {"PolicyArn": policy_arn, "GroupName": group_name})

def attach_role_policy(iam, policy_arn, role_name):
    """
    Attach a managed policy (specified by ARN) to a role (specified by
    friendly name).
    """
    return iam.get_response(
        'AttachRolePolicy', {"PolicyArn": policy_arn, "RoleName": role_name})

def attach_user_policy(iam, policy_arn, user_name):
    """
    Attach a managed policy (specified by ARN) to a user (specified by
    user name).
    """
    return iam.get_response(
        'AttachUserPolicy', {"PolicyArn": policy_arn, "UserName": user_name})

def detach_role_policy(iam, policy_arn, role_name):
    """
    Detach a managed policy (specified by ARN) from a role (specified by
    friendly name).
    """
    return iam.get_response(
        'DetachRolePolicy', {"PolicyArn": policy_arn, "RoleName": role_name})

def get_policy(iam, policy_arn):
    """
    Return basic about the given policy (e.g. current version).
    """
    return iam.get_response('GetPolicy', {"PolicyArn": policy_arn})

def get_policy_version(iam, policy_arn, version_id):
    """
    Return details about the specified policy version (including the
    policy document)
    """
    return iam.get_response(
        'GetPolicyVersion', {"PolicyArn": policy_arn, "VersionId": version_id})

def list_attached_role_policies(iam, role_name):
    """
    List the policies attached to a given role.
    """
    return iam.get_response(
        'ListAttachedRolePolicies', {"RoleName": role_name},
        list_marker="AttachedPolicies")

def list_policies(iam, only_attached=False, path_prefix="/", scope="All",
                  marker=None, max_items=100):
    """
    List policies available.

    If only_attached is True, the results are limited to policies attached to
    roles.

    path_prefix can be used to filter results.  This defaults to '/', returning
    all policies.

    scope can be 'AWS' for AWS-managed policies, 'Local' for customer-managed
    policies, or 'All'.

    max_items and marker are used for pagination.  max_items defaults to 100.
    If there are additional results available, the result will have the
    is_truncated flag set and include a marker to retrieve the next page of
    results.
    """
    parameters = {"OnlyAttached": "true" if only_attached else "false",
                  "PathPrefix": path_prefix,
                  "Scope": scope,
                  "MaxItems": max_items}
    if marker is not None:
        parameters["Marker"] = marker

    return iam.get_response('ListPolicies', parameters, list_marker="Policies")

def get_json_for_policies(iam, policy_arns, parallelism=5):
    """
    Retrieve JSON objects for the specified policies.
    """
    pool = Pool(parallelism)
    futures = [(arn, pool.apply_async(get_json_for_policy, [iam, arn]))
               for arn in policy_arns]
    pool.close()
    results = dict([(arn, future.get()) for arn, future in futures])
    pool.join()
    return results

def get_json_for_policy(iam, policy_arn):
    """
    Returns a policy in JSON format.
    """
    policy = get_policy(iam, policy_arn).policy
    version = policy.get("default_version_id")

    if version:
        pv_response = get_policy_version(
            iam, policy_arn, version).policy_version
        pv = {
            version: {
                "is_default_version": pv_response.is_default_version,
                "document": url_unquote(pv_response.document),
                "create_date": pv_response.create_date,
            }
        }
    else:
        pv = {}

    return {
        "arn": policy_arn,
        "name": policy.policy_name,
        "description": policy.description,
        "create_date": policy.create_date,
        "update_date": policy.update_date,
        "policy_id": policy.policy_id,
        "path": policy.path,
        "default_version_id": version,
        "policy_versions": pv,
    }

# Local variables:
# mode: Python
# tab-width: 8
# indent-tabs-mode: nil
# End:
# vi: set expandtab tabstop=8
