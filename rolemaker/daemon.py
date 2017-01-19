#!/usr/bin/env python
from __future__ import absolute_import, division, print_function
from boto.exception import BotoServerError
import boto.iam
import boto.s3
from boto.s3.connection import OrdinaryCallingFormat
import boto.sqs
from boto.sqs.message import RawMessage
from daemonize import Daemonize
from getopt import getopt, GetoptError
from json import dumps as json_dumps, loads as json_loads
import logging
from math import exp, log
import sys
from sys import argv, stdout
from threading import Thread
from time import sleep, time
from .iam import attach_role_policy, detach_role_policy
from .utils import ExceptionData

DEFAULT_REGION = "us-gov-west-1"
DEFAULT_STORAGE_PREFIX = "s3://cuthbert-rolemaker/"
DEFAULT_CREATE_QUEUE_NAME = "rolemaker_create_role"
DEFAULT_MANDATORY_POLICY_ARN = "arn:aws:iam::187415278133:policy/DisallowIAMSuperuser"

class RoleCreationDaemon(Thread):
    def __init__(self, thread_name=None, region=DEFAULT_REGION,
                 storage_prefix=DEFAULT_STORAGE_PREFIX,
                 aws_access_key_id=None, aws_secret_access_key=None,
                 profile_name=None,
                 create_queue_name=DEFAULT_CREATE_QUEUE_NAME,
                 mandatory_policy_arn=None):
        """
        Create a new daemon that handles role creation requests.
        """
        if thread_name is None:
            thread_name = self.__class__.__name__
        super(RoleCreationDaemon, self).__init__(name=thread_name)
        self.region = region
        self.log = logging.getLogger("rolemaker.daemon")
        self.storage_prefix = storage_prefix
        self.exit_requested = False
        self.mandatory_policy_arn = mandatory_policy_arn
        self.requests_processed = 0

        self.iam = boto.iam.connect_to_region(
            region, aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            profile_name=profile_name)

        self.s3 = boto.s3.connect_to_region(
            region, aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            profile_name=profile_name, calling_format=OrdinaryCallingFormat())

        self.sqs = boto.sqs.connect_to_region(
            region, aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            profile_name=profile_name)

        self.create_queue = self.sqs.get_queue(create_queue_name)
        self.create_queue.set_message_class(RawMessage)

        return

    def run(self):
        while not self.exit_requested:
            self.log.debug("Waiting for message")
            message = self.create_queue.read(wait_time_seconds=5)
            if message:
                self.log.debug("Processing message")
                self.process_message(message)
                self.requests_processed += 1
                self.log.debug("Deleting message")
                self.create_queue.delete_message(message)
            else:
                self.log.debug("No message available")
                sleep(1)

        return

    def process_message(self, message):
        request = json_loads(message.get_body())
        request_id = request['request_id']
        role_name = request['role_name']
        managed_policies = request['managed_policies']
        trust_relationships = request['trust_relationships']
        inline_policy_name = request.get('inline_policy_name')
        inline_policy = request.get('inline_policy')
        rollback_steps = []

        self.log.info("Processing request id %s", request_id)

        assume_role_policy_document = None
        if len(trust_relationships) > 0:
            assume_role_policy_document = """\
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": [%s]
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
""" % (", ".join(['"%s"' % tr for tr in trust_relationships]))

        try:
            self.set_create_status(request_id, "Creating role object")
            role = self.iam.create_role(
                role_name,
                assume_role_policy_document=assume_role_policy_document)

            rollback_steps.append((self.iam.delete_role, (role_name,)))

            if self.mandatory_policy_arn is not None:
                self.set_create_status(
                    request_id, "Attaching mandatory managed policy")
            
                attach_role_policy(self.iam, self.mandatory_policy_arn,
                                   role_name)

                rollback_steps.append(
                    (detach_role_policy,
                     (self.iam, self.mandatory_policy_arn, role_name)))

            for i, policy_arn in enumerate(managed_policies):
                self.set_create_status(
                    request_id, "Attaching managed policy %d: %s" % (
                        i + 1, policy_arn))

                attach_role_policy(self.iam, policy_arn, role_name)
                rollback_steps.append(
                    (detach_role_policy,
                     (self.iam, policy_arn, role_name)))

            if inline_policy:
                self.set_create_status(
                    request_id, "Setting inline policy")
                self.iam.put_role_policy(role_name, inline_policy_name,
                                         inline_policy)
                rollback_steps.append(
                    (self.iam.delete_role_policy, role_name,
                     inline_policy_name))

            self.set_create_status(
                request_id, "Creating instance profile")
            self.iam.create_instance_profile(role_name)

            rollback_steps.append(
                (self.iam.delete_instance_profile, (role_name,)))

            self.set_create_status(
                request_id, "Adding role to instance profile")
            self.iam.add_role_to_instance_profile(role_name, role_name)

            rollback_steps.append(
                (self.iam.remove_role_from_instance_profile,
                 (role_name, role_name)))

            self.set_create_status(
                request_id, "Role %s created successfully" % role_name,
                done=True)
        except BotoServerError as e:
            self.log.error("Creation failure.", exc_info=True)
            
            excdata = ExceptionData.from_exception(e)
            exc_msg = "%s error: %s: %s" % (
                excdata.error_type.lower(), excdata.error_code,
                excdata.message)
            self.set_create_status(
                request_id, "Rolling back; failed due to %s" % exc_msg)

            for i, step in enumerate(reversed(rollback_steps)):
                func = step[0]
                args = step[1] if len(step) > 1 else ()
                kw = step[2] if len(step) > 2 else {}

                for attempt in xrange(10):
                    try:
                        func(*args, **kw)
                        break
                    except Exception as e:
                        self.log.error("Rollback step %d (attempt %d) failed",
                                       i + 1, attempt + 1, exc_info=True)
                        # Exponential backoff
                        sleep_time = exp(0.1 * log(30) * attempt)
                        self.log.info(
                            "Exponential backoff due to AWS API failure: "
                            "sleeping for %.2f sec",
                            sleep_time)
                        sleep(sleep_time)

            self.set_create_status(
                request_id, "Failed due to %s" % exc_msg, done=True)

        return
                
            
    def set_create_status(self, request_id, status, done=False, whence=None):
        """
        Set the status of a creation request.
        """
        if whence is None:
            whence = time()
        done = "true" if done else "false"
        
        bucket_name, prefix = self.storage_prefix[5:].split("/", 1)
        path = prefix + "create-status/%s" % request_id
        bucket = self.s3.get_bucket(bucket_name)
        key = bucket.new_key(path)
        self.log.info("Status: %r (done=%s)", status, done)
        
        key.set_contents_from_string(
            json_dumps({'status': status, 'time': whence, 'done': done}),
            reduced_redundancy=True)
        return

def run_daemon(args=None):
    foreground = False
    region = DEFAULT_REGION
    storage_prefix = DEFAULT_STORAGE_PREFIX
    profile_name = None
    create_queue_name = DEFAULT_CREATE_QUEUE_NAME
    mandatory_policy_arn = DEFAULT_MANDATORY_POLICY_ARN

    if args is None:
        args = argv[1:]

    try:
        opts, args = getopt(
            args, "fhP:m:q:r:s:",
            ["help", "profile=", "queue=", "mandatorypolicy=",
             "mandatory-policy=", "mandatory-policy-arn=", "region=",
             "storageprefix=", "storage-prefix="])
    except GetoptError as e:
        print(str(e), file=sys.stderr)
        daemon_usage()
        return 1

    for opt, value in opts:
        if opt in ("-f", "--foreground"):
            foreground = True
        elif opt in ("-h", "--help"):
            daemon_usage(stdout)
            return 0
        elif opt in ("-m", "--mandatorypolicy", "--mandatory-policy",
                     "--mandatory-policy-arn"):
            mandatory_policy_arn = value if len(value) > 0 else None
        elif opt in ("-P", "--profile"):
            profile_name = value
        elif opt in ("-q", "--queue"):
            create_queue_name = value
        elif opt in ("-r", "--region"):
            region = value
        elif opt in ("-s", "--storageprefix", "--storage-prefix"):
            storage_prefix = value

    if foreground:
        return daemon(region, storage_prefix, profile_name, create_queue_name,
                      mandatory_policy_arn)
    else:
        sys.stderr = open("/var/log/rolemaker-daemon.log", "a")
        d = Daemon(app="rolemaker-daemon", pid="/var/run/rolemaker-daemon.pid",
                   action=daemon, keep_fds=[sys.stderr.fileno()])
        d.start()
        return 0

def daemon(region, storage_prefix, profile_name, create_queue_name,
           mandatory_policy_arn):    
    logging.basicConfig(
        level=logging.DEBUG, stream=sys.stderr,
        format=("%(asctime)s %(filename)s:%(lineno)s [%(levelname)s]: "
                "%(message)s"))
    logging.getLogger("boto").setLevel(logging.WARNING)

    create = RoleCreationDaemon(region=region, storage_prefix=storage_prefix,
                                profile_name=profile_name,
                                create_queue_name=create_queue_name,
                                mandatory_policy_arn=mandatory_policy_arn)

    log = logging.getLogger("rolemaker.daemon")
    log.debug("Starting creation daemon")
    create.start()

    # Sleep until we get an exit request.
    try:
        while True:
            sleep(1)
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        log.info("Exit requested; waiting for daemon to terminate.")
        create.exit_requested = True
        create.join()

    log.info("Daemon terminated after processing %d requests." %
             create.requests_processed)
    return 0

def daemon_usage(fd=sys.stderr):
    fd.write("""\
Usage: rolemaker-daemon [options]
Run the backend daemon for creating roles.

Options:
    -f | --foreground
        Keep this process in the foreground (don't daemonize).

    -h | --help
        Shows this usage information.

    -m <policy_arn> | --mandatory-policy_arn <policy_arn>
        Apply the specified managed policy to every role creation request.

    -P <profile_name> | --profile <profile_name>
        Use AWS credentials from the given profile name.  Credentials are
        looked up in ~/.aws/credentials and ~/.boto.

    -q <queue_name> | --queue <queue_name>
        Use the specified queue for writing create requests.  Defaults to
        %(DEFAULT_CREATE_QUEUE_NAME)r.

    -r <region> | --region <region>
        Make API calls in the given region.  Defaults to %(DEFAULT_REGION)r.

    -s <url> | --storage-prefix <url>
        Use the specified S3 prefix for shared-state storage from the
        specified URL.  This should be an S3 URL in the format
        s3://<bucket>/<prefix>.  Defaults to %(DEFAULT_STORAGE_PREFIX)r.
""" % globals())
    fd.flush()
    return
    
        
# Local variables:
# mode: Python
# tab-width: 8
# indent-tabs-mode: nil
# End:
# vi: set expandtab tabstop=8
