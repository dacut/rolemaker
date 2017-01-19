#!/usr/bin/env python
from __future__ import absolute_import, division, print_function
from boto.exception import StorageResponseError
import boto.iam
import boto.s3
from boto.s3.connection import OrdinaryCallingFormat
import boto.sqs
from boto.sqs.message import RawMessage
from .iam import (
    get_json_for_policies, list_attached_role_policies, list_policies)
from json import dumps as json_dumps, loads as json_loads
import logging
from time import time
from uuid import uuid4

DEFAULT_REGION = "us-gov-west-1"
DEFAULT_STORAGE_PREFIX = "s3://cuthbert-rolemaker/"
DEFAULT_CREATE_QUEUE_NAME = "rolemaker_create_role"

# Strings used elsewhere
ATTACHABLE_POLICY_CACHE_JSON = "attachable-policy-cache.json"
ATTACHABLE_POLICIES = 'attachable_policies'
CACHE_TIME = "cache_time"

# All AWS-managed policies begin with this ARN prefix
AWS_POLICY_ARN_PREFIX = "arn:aws:iam::aws:policy/"

class PolicyModel(object):
    """
    Encapsulates the data and business rules around IAM policies.
    """

    # How long domain data caches are valid for, in seconds.
    domain_data_cache_timeout = 3600
    
    # How many parallel processes to spin up when retrieving policy results.
    parallelism = 10

    # How many policies can the user attach?  (Usually 1 less than the max
    # allowed by AWS; the remaining one is a mandatory policy.)
    max_attached_policies = 9
    
    # What AWS service trust relationships do we know about?
    trust_relationships = {
        "config.amazonaws.com": "AWS Config",
        "datapipeline.amazonaws.com": "Data Pipeline",
        "ec2.amazonaws.com": "EC2",
        "lambda.amazonaws.com": "Lambda",
        "spotfleet.amazonaws.com": "EC2 Spot Fleet",
        "vpc-flow-logs.amazonaws.com": "VPC Flow Logs",
        "vmie.amazonaws.com": "VM Import/Export",
    }
    
    def __init__(self, **kw):
        super(PolicyModel, self).__init__()
        self.log = logging.getLogger("rolemaker.model")
        self.region = region = kw.pop("region", DEFAULT_REGION)
        create_queue_name = kw.pop(
            "create_queue_name", DEFAULT_CREATE_QUEUE_NAME)
        self.storage_prefix = kw.pop("storage_prefix", DEFAULT_STORAGE_PREFIX)

        aws_kw = {
            "profile_name": kw.get("profile_name"),
            "aws_access_key_id": kw.get("aws_access_key_id"),
            "aws_secret_access_key": kw.get("aws_secret_access_key"),
        }
            
        # Create AWS instances for IAM and SQS.
        self.iam = boto.iam.connect_to_region(region, **aws_kw)
        self.sqs = boto.sqs.connect_to_region(region, **aws_kw)
        self.s3 = boto.s3.connect_to_region(
            region, calling_format=OrdinaryCallingFormat(), **aws_kw)

        # The SQS queue we use to track create policy executions.
        self.create_queue = self.sqs.get_queue(create_queue_name)
        if self.create_queue is None:
            raise ValueError("Unknown SQS queue %s in region %s" %
                             (create_queue_name, region))
        self.create_queue.set_message_class(RawMessage)

        return

    def get_role_policies(self, role_name):
        """
        policy_model.get_role_policies(role_name) -> dict

        Return the contents of the given role as a dictionary.
        """

        # Get all of the inline policies -- this is raw IAM/Aspen text.
        policy_names = self.iam.list_role_policies(role_name).policy_names
        inline_policies = {}
        for policy_name in policy_names:
            policy = self.iam.get_role_policy(role_name, policy_name)
            document = url_unquote(policy.policy_document)
            inline_policies[policy_name] = document

        # Get all of the attached policies.
        ap_response = (list_attached_role_policies(self.iam, role_name)
                       .attached_policies)
        attached_policies = get_json_for_policies(
            self.iam, [ap.policy_arn for ap in ap_response])

        return {
            "role_name": role_name,
            "inline_policies": inline_policies,
            "attached_policies": attached_policies,
        }

    def get_attachable_policies(self):
        """
        server.get_attachable_policies() -> JSON string

        Return a JSON-formatted response with a list of all policies.
        """
        if not hasattr(self, "attachable_policies"):
            self.refresh_attachable_policies()
            
        return self.attachable_policies

    def refresh_attachable_policies(self):
        """
        server.refresh_attachable_policies()

        Refresh the server cache of attachable policies.  This is periodically
        invoked by a helper thread.
        """
        # See if we can read this from the S3 store.
        bucket_name, prefix = self.storage_prefix[5:].split("/", 1)
        try:
            bucket = self.s3.get_bucket(bucket_name)
        except Exception as e:
            self.log.error("Unable to get bucket %r in region %r", bucket_name,
                           self.region)
            e.args = (str(e.args[0]) + " (region %r bucket %r)" %
                      (self.region, bucket_name),) + e.args[1:]
            raise RuntimeError("Could not access %r %r: %s" % (self.region, bucket_name, e))

        key_name = prefix + ATTACHABLE_POLICY_CACHE_JSON

        try:
            self.log.debug("Attempting to refresh attachable policies from "
                           "s3://%s/%s", bucket_name, key_name)
            key = bucket.get_key(key_name)
            cache = json_loads(key.get_contents_as_string())
            cache_time = cache.get(CACHE_TIME, 0)
            if cache_time > time() - self.domain_data_cache_timeout:
                self.attachable_policies = cache[ATTACHABLE_POLICIES]
                return
        except Exception as e:
            self.log.debug("Unable to refresh from S3: %s", e, exc_info=True)
            pass
        
        marker = None
        local_policies = {}
        aws_policies = {}

        policy_arns = []

        self.log.debug("Refreshing attachable policies from IAM")
        # Get a list of all attachable policy ARNs.
        while True:
            results = list_policies(self.iam, marker=marker)
            for policy in results.policies:
                # Ignore non-attachable policies
                if not policy.is_attachable: continue
                
                policy_arns.append(policy.arn)

            if results.is_truncated != 'true':
                break

            marker = results.marker

        # Get the JSON details for every policy
        policy_details = get_json_for_policies(
            self.iam, policy_arns, self.parallelism)

        for arn, details in policy_details.iteritems():
            if arn.startswith(AWS_POLICY_ARN_PREFIX):
                # AWS-managed policy
                policy_dict = aws_policies
            else:
                policy_dict = local_policies

            policy_dict[arn] = details

        self.log.debug("Retrieved %d AWS policies and %d local policies",
                       len(aws_policies), len(local_policies))

        self.attachable_policies = {
            'local': local_policies,
            'aws': aws_policies,
        }

        # Save this to the cache location
        self.log.debug("Caching policies to s3://%s/%s", bucket_name, key_name)
        key = bucket.new_key(key_name)
        key.set_contents_from_string(
            json_dumps({CACHE_TIME: time(),
                        ATTACHABLE_POLICIES: self.attachable_policies}),
            replace=True,
            reduced_redundancy=True)
        
        return


    def create_role(self, role_name, managed_policies, trust_relationships,
                    username, inline_policy_name=None, inline_policy=None,
                    create_date=None):
        """
        Asynchronously create a new role.

        Since creating the role and populating it require multiple steps,
        we don't a user breaking out of the web page to leave us with a
        half-created role that can't be fixed (easily).  Instead, we create
        a request and send it to an SQS queue to allow a backend process to
        handle this.
        """
        # Unique request id for this creation request.
        request_id = str(uuid4())

        # Dictionary (that will become a JSON object) for directing the create
        # request.
        create_parameters = {
            "request_id": request_id,
            "role_name": role_name,
            "managed_policies": managed_policies,
            "trust_relationships": trust_relationships,
            "create_date": time(),
            "username": username,
        }

        if inline_policy is not None:
            create_parameters["inline_policy_name"] = inline_policy_name
            create_parameters["inline_policy"] = inline_policy

        # Post the creation request to the worker queue.
        message = self.create_queue.new_message(json_dumps(create_parameters))
        self.create_queue.write(message)

        # Create an idle status
        self.set_create_status(
            request_id, {'status': 'Waiting for worker.',
                         'time': time(),
                         'done': "false"})

        return request_id
    
    def get_create_status(self, request_id):
        """
        Return the status of a creation request.
        """
        bucket_name, prefix = self.storage_prefix[5:].split("/", 1)
        path = prefix + "create-status/%s" % request_id
        bucket = self.s3.get_bucket(bucket_name)
        key = bucket.new_key(path)

        try:
            return json_loads(key.get_contents_as_string())
        except StorageResponseError:
            return None

    def set_create_status(self, request_id, status):
        """
        Set the status of a creation request.
        """
        bucket_name, prefix = self.storage_prefix[5:].split("/", 1)
        path = prefix + "create-status/%s" % request_id
        bucket = self.s3.get_bucket(bucket_name)
        key = bucket.new_key(path)
        key.set_contents_from_string(
            json_dumps(status), reduced_redundancy=True)
        return
    


# Local variables:
# mode: Python
# tab-width: 8
# indent-tabs-mode: nil
# End:
# vi: set expandtab tabstop=8
