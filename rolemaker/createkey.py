#!/usr/bin/env python
from __future__ import absolute_import, division, print_function
import boto.kms
import boto.s3
from getopt import getopt, GetoptError
from .s3 import S3ClientEncryptionHandler
from os import urandom
from sys import argv, stderr, stdout

DEFAULT_REGION = "us-west-2"
DEFAULT_STORAGE_PREFIX = "s3://cuthbert-rolemaker/"

def create_key(region, storage_prefix, kms_key_id):
    kms = boto.kms.connect_to_region(region)
    s3 = boto.s3.connect_to_region(region)
    ceh = S3ClientEncryptionHandler(kms, kms_key_id)

    bucket_name, prefix = storage_prefix[5:].split("/", 1)
    s3_object = prefix + "rolemaker.key"
    
    bucket = s3.get_bucket(bucket_name)
    key = bucket.new_key(s3_object)
    data = urandom(64)
    ceh.write(key, data)
    return 0

def run_createkey():
    kms_key_id = None
    region = DEFAULT_REGION
    storage_prefix = DEFAULT_STORAGE_PREFIX
    
    try:
        opts, args = getopt(argv[1:], "hk:P:r:s:",
                            ["help", "kms-key-id=", "profile=", "region=",
                             "storageprefix=", "storage-prefix="])
    except GetoptError as e:
        print(str(e), file=stderr)
        createkey_usage()
        return 1

    for opt, value in opts:
        if opt in ("-h", "--help"):
            createkey_usage(stdout)
            return 0
        elif opt in ("-k", "--kms-key-id"):
            kms_key_id = value
        elif opt in ("-P", "--profile"):
            profile_name = value
        elif opt in ("-r", "--region"):
            region = value
        elif opt in ("-s", "--storageprefix", "--storage-prefix"):
            storage_prefix = value

    if kms_key_id is None:
        print("--kms-key-id is required", file=stderr)
        createkey_usage()
        return 1

    create_key(region, storage_prefix, kms_key_id)
    return 0

def createkey_usage(fd=stderr):
    fd.write("""\
Usage: rolemaker-create-key [options]
Create a session key for the rolemaker web server.

Options:
    -h | -- help
        Shows this usage information.

    -k <key_id> | --kms-key-id <key_id>
        Use the specified KMS key to encrypt the data in S3.

    -P <profile_name> | --profile <profile_name>
        Use AWS credentials from the given profile name.  Credentials are
        looked up in ~/.aws/credentials and ~/.boto.

    -r <region> | --region <region>
        Make API calls in the given region.  Defaults to %(DEFAULT_REGION)r.

    -s <url> | --storage-prefix <url>
        Use the specified S3 prefix for shared-state storage from the
        specified URL.  This should be an S3 URL in the format
        s3://<bucket>/<prefix>.  The rolemaker.key object in this location
        will be encrypted with KMS.  Defaults to %(DEFAULT_STORAGE_PREFIX)r.
""" % globals())
    fd.flush()
    return
        

# Local variables:
# mode: Python
# tab-width: 8
# indent-tabs-mode: nil
# End:
# vi: set expandtab tabstop=8
