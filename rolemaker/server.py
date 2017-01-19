#!/usr/bin/env python
from __future__ import absolute_import, division, print_function
from flask import abort, Flask, make_response, redirect, request, session
import boto.kms
import boto.s3
from boto.s3.connection import OrdinaryCallingFormat
from getopt import getopt, GetoptError
from hashlib import sha256
from hmac import new as hmac
from httplib import BAD_REQUEST, NOT_FOUND, OK
from json import dumps as json_dumps, loads as json_loads
import logging
from mako.lookup import TemplateLookup
from mako.template import Template
from .mimetypes import read_mime_types
from .model import PolicyModel
from os.path import dirname, exists, isfile, isdir, splitext
from re import compile as re_compile
from rolemaker import AuthenticationRequiredError
from rolemaker.s3 import S3ClientEncryptionHandler
from sys import argv, stderr, stdout
from time import time
from urllib import unquote as url_unquote
from werkzeug.datastructures import Headers

DEFAULT_REGION = "us-gov-west-1"
DEFAULT_PORT = 8080
DEFAULT_WEBROOT = dirname(__file__) + "/web"
DEFAULT_CREATE_QUEUE_NAME = "rolemaker_create_role"
DEFAULT_STORAGE_PREFIX = "s3://cuthbert-rolemaker/"

# Regex for detecting multiple slashes in a URL.
MULTISLASH = re_compile(r"//+")

# Regex for validating IAM role and policy names
IAM_NAME_REGEX = re_compile(r"^[\w\+=,\.@-]*$")

class Redirect(Exception):
    def __init__(self, location):
        super(Redirect, self).__init__()
        self.location = location
        return

class RolemakerServer(Flask):
    """
    A Flask application for allowing users to view and create roles.
    """
    content_types = read_mime_types()

    # Require MFA token when creating roles.
    require_mfa_create = True

    # How long XSRF tokens are valid, in seconds.
    xsrf_token_window = 15 * 60

    def __init__(self, **kw):
        """
        RolemakerServer([region, webroot, aws_access_key_id,
                         aws_secret_access_key, profile_name,
                         create_queue_name])
          -> RolemakerServer

        Create a new RolemakerServer Flask application.
        """
        webroot = kw.pop("webroot", DEFAULT_WEBROOT)
        super(RolemakerServer, self).__init__(
            "rolemaker.server", static_folder=webroot, static_url_path="")
        self.log = logging.getLogger("rolemaker.server")
        self.webroot = webroot
        self.region = kw.pop("region", DEFAULT_REGION)
        self.storage_prefix = kw.pop("storage_prefix", DEFAULT_STORAGE_PREFIX)
        self.lookup = TemplateLookup(directories=[webroot])
        self.policy_model = PolicyModel(
            region=self.region, storage_prefix=self.storage_prefix, **kw)

        aws_kw = {
            "profile_name": kw.get("profile_name"),
            "aws_access_key_id": kw.get("aws_access_key_id"),
            "aws_secret_access_key": kw.get("aws_secret_access_key"),
        }

        self.kms = boto.kms.connect_to_region(self.region, **aws_kw)
        self.s3 = boto.s3.connect_to_region(
            self.region, calling_format=OrdinaryCallingFormat(), **aws_kw)

        # Flask's session utilities require the session key be named
        # secret_key.
        self.secret_key = self.read_session_key(
            self.storage_prefix + "rolemaker.key")

        # We point the root URL (/) to the about page.
        self.add_url_rule("/", endpoint="render_template",
                          view_func=self.render_template,
                          methods=["GET"],
                          defaults={"template": "/about.mako"})

        # List roles.
        self.add_url_rule("/list", endpoint="render_template",
                          view_func=self.render_template,
                          methods=["GET"],
                          defaults={"template": "/list.mako"})

        # Login -- allow GET and POST
        self.add_url_rule("/login", endpoint="render_template",
                          view_func=self.render_template,
                          methods=["GET", "POST"],
                          defaults={"template": "/login.mako"})

        # Create -- allow GET and POST
        self.add_url_rule("/create", endpoint="render_template",
                          view_func=self.render_template,
                          methods=["GET"],
                          defaults={"template": "/create.mako"})
        self.add_url_rule("/create", endpoint="create_role",
                          view_func=self.create_role,
                          methods=["POST"])


        # Create status -- include the request id.
        self.add_url_rule("/create-status/<request_id>",
                          endpoint="render_template",
                          view_func=self.render_template,
                          defaults={"template": "/create-status.mako"},
                          methods=["GET"])

        # JSON API: retrieve policies for role.
        self.add_url_rule("/json/role/<role_name>/policies",
                          endpoint="get_role_policies",
                          view_func=self.get_role_policies,
                          methods=["GET"])

        # JSON API: retrieve all attachable policies.
        self.add_url_rule("/json/attachable-policies",
                          endpoint="get_attachable_policies",
                          view_func=self.get_attachable_policies,
                          methods=["GET"])

        return

    def run(self, *args, **kw):
        """
        Run the application server.
        """
        # We start by forcing a refresh of the cached policies.
        self.refresh_attachable_policies()

        # FIXME: Add thread to refresh periodically.

        return super(RolemakerServer, self).run(*args, **kw)

    def render_template(self, template, **kw):
        """
        server.render_template(template) -> response

        Renders the Mako template at the relative path.  This is called for
        all default requests.
        """
        # Set the default content type based on the extension.  If this is
        # a Mako template, we can override the result in the template.
        response_headers = Headers(
            defaults=[("Content-Type", "text/html; charset=utf-8")])

        # We need to wrap the status in its own object since Python 2.7
        # doesn't support the nonlocal keyword.
        status = [OK]
        def set_status(s):
            status[0] = s

        # Have Mako render the template for us.  This allows you to embed
        # Python bits into the otherwise static HTML file.
        template = Template(
            filename=self.webroot + template, lookup=self.lookup,
            strict_undefined=True)
        try:
            body = template.render(
                server=self,
                response_headers=response_headers,
                set_status=set_status,
                request=request,
                session=session, **kw)
        except AuthenticationRequiredError:
            return redirect("/login?redirect=%s" % request.path)
        except Redirect as redir:
            return redirect(redir.location)

        # Change this into a Flask response.
        response = make_response((body, status[0], response_headers))
        return response

    def get_role_policies(self, role_name):
        """
        server.get_role_policies(role_name) -> JSON string
        """
        response = self.policy_model.get_role_policies(role_name)
        return make_response(
            json_dumps(response), OK,
            {"Content-Type": "application/json"})

    def get_attachable_policies(self):
        response = self.policy_model.get_attachable_policies()
        return make_response(
            json_dumps(response), OK,
            {"Content-Type": "application/json"})

    def create_role(self):
        """
        server.create_role() -> redirect or render

        Handle a POSTed role creation request.
        """
        # Make sure there's one -- and only one -- username and authentication
        # code to prevent confused deputy attacks (where an attacker somehow
        # injects the user's credentials into the attacker's request).
        usernames = request.form.getlist("username")
        authcodes = request.form.getlist("authentication-code")

        def fail(create_error="", **kw):
            return self.render_template(
                "/create.mako", create_error=create_error, **kw)

        if (len(usernames) == 0 or len(authcodes) == 0 or
            (len(usernames) == 1 and usernames[0] == "")):
            # No auth supplied; indicate this as an error.
            return fail("Please enter your username and authentication code "
                        "to create the role.")
        elif len(usernames) > 1 or len(authcodes) > 1:
            return fail("Invalid username or authentication code.")

        username = usernames[0]
        authcode = authcodes[0]

        # FIXME: Actually authenticate the user.
        if username != "poc-user" or authcode != "poc-user-password":
            return fail("Invalid username or authentication code.")

        # Keep a list of errors so we can perform as much validation as
        # possible before returning.
        errors = []

        # Parameter validation: role-name
        role_name = request.form.get("role-name", "")
        if len(role_name) == 0:
            errors.append("Role name is required.")
        elif len(role_name) > 64:
            errors.append("Role name is longer than 64 characters.")
        elif not IAM_NAME_REGEX.match(role_name):
            errors.append("Role name contains invalid characters.")

        # Parameter validation: inline-policy-name
        inline_policy_name = request.form.get("inline-policy-name", "")
        inline_policy = request.form.get("inline-policy", "")

        # Only validate if inline_policy isn't empty.
        if len(inline_policy.strip()) > 0:
            if len(inline_policy_name) == 0:
                errors.append("Inline policy name is required when using "
                              "an inline policy.")
            elif len(inline_policy_name) > 64:
                errors.append("Inline policy name is longer than 64 "
                              "characters.")
            elif not IAM_NAME_REGEX.match(inline_policy_name):
                errors.append("Inline policy name contains invalid "
                              "characters.")

        # Make sure fewer than max_attached_policies managed policies are
        # attached.
        managed_policies = request.form.getlist("managed-policies")
        if len(managed_policies) > self.policy_model.max_attached_policies:
            errors.append(
                "Cannot have more than %d managed policies attached." %
                self.policy_model.max_attached_policies)

        # Make sure that every managed policy is known.
        if not all([
                (policy in self.policy_model.attachable_policies['local'] or
                 policy in self.policy_model.attachable_policies['aws'])
                for policy in managed_policies]):
            errors.append("Invalid managed policy specified.")

        # Make sure that every trust relationship is known.
        trust_relationships = request.form.getlist("trust-relationships")
        if not all([tr in self.policy_model.trust_relationships
                    for tr in trust_relationships]):
            errors.append("Invalid trust relationship specified.")

        if errors:
            # Stop here; don't try to create the role.
            return fail("<br>".join(errors))

        if not inline_policy.strip():
            inline_policy = None
            inline_policy_name = None

        request_id = self.policy_model.create_role(
            role_name=role_name, managed_policies=managed_policies,
            trust_relationships=trust_relationships, username=username,
            inline_policy_name=inline_policy_name, inline_policy=inline_policy)

        return redirect("/create-status/%s" % request_id)

    def read_session_key(self, url):
        """
        Read a session key from S3 encrypted with KMS.
        """
        if not url.startswith("s3://"):
            raise ValueError("Session key URL must be in the form "
                             "s3://<bucket>/<object>")

        try:
            bucket_name, path = url[5:].split("/", 1)
            if not bucket_name or not path:
                raise ValueError()
        except ValueError:
            raise ValueError("Session key URL must be in the form "
                             "s3://<bucket>/<object>")

        bucket = self.s3.get_bucket(bucket_name)
        key = bucket.get_key(path)
        if key is None:
            raise ValueError("Unknown S3 object: s3://%s/%s" % (bucket, path))

        return S3ClientEncryptionHandler(self.kms).read(key)

    def get_xsrf_token(self):
        """
        Return an opaque cross-site request forgery (XSRF) token for use
        in forms.
        """
        now = str(time())
        digest = hmac(self.secret_key, now, sha256).hexdigest()
        return now + ":" + digest

    def is_valid_xsrf_token(self, token):
        """
        Determines whether the given XSRF token is valid.
        """
        if ":" not in token:
            return False

        timestamp, digest = token.split(":", 1)
        if digest != hmac(self.secret_key, timestamp, sha256).hexdigest():
            return False

        now = time()
        if now - float(timestamp) > self.xsrf_token_window:
            return False

        return True

    def authenticate_user(self, username, password):
        """
        This won't be used except as a demo; we hardcode a username and
        password here.
        """
        return username == "poc-user" and password == "poc-user-password"

def run_server(args=None):
    region = DEFAULT_REGION
    port = DEFAULT_PORT
    webroot = DEFAULT_WEBROOT
    storage_prefix = DEFAULT_STORAGE_PREFIX
    profile_name = None
    create_queue_name = DEFAULT_CREATE_QUEUE_NAME

    if args is None:
        args = argv[1:]

    try:
        opts, args = getopt(
            args, "hp:P:q:r:s:w:",
            ["help", "port=", "profile=", "queue=", "region=",
             "storageprefix=", "storage-prefix=", "webroot=", "web-root="])
    except GetoptError as e:
        print(str(e), file=stderr)
        server_usage()
        return 1

    for opt, value in opts:
        if opt in ("-h", "--help"):
            server_usage(stdout)
            return 0
        elif opt in ("-p", "--port"):
            try:
                port = int(value)
                if not (0 < port <= 65535):
                    raise ValueError()
            except ValueError:
                print("Invalid port value %r" % value, file=stderr)
                usage()
                return 1
        elif opt in ("-P", "--profile"):
            profile_name = value
        elif opt in ("-q", "--queue"):
            create_queue_name = value
        elif opt in ("-r", "--region"):
            region = value
        elif opt in ("-s", "--storageprefix", "--storage-prefix"):
            storage_prefix = value
        elif opt in ("-w", "--webroot", "--web-root"):
            webroot = value

    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger("boto").setLevel(logging.WARNING)
    app = RolemakerServer(
        profile_name=profile_name, region=region,
        storage_prefix=storage_prefix, webroot=webroot,
        create_queue_name=create_queue_name)
    app.run(port=port)
    return 0

def server_usage(fd=stderr):
    fd.write("""\
Usage: rolemaker-server [options]
Run the HTTP server for creating roles.

Options:
    -h | -- help
        Shows this usage information.

    -p <port> | --port <port>
        Listen on the given port.  Defaults to %(DEFAULT_PORT)d.

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
        s3://<bucket>/<prefix>.  The rolemaker.key object in this location
        must be encrypted with KMS.  Defaults to %(DEFAULT_STORAGE_PREFIX)r.

    -w <root> | --webroot <root> | --web-root <root>
        Look for webpage templates at the specified root.  This may be a
        directory name or an S3 URL in the format s3://<bucket>/<prefix>.
        Defaults to %(DEFAULT_WEBROOT)r.
""" % globals())
    fd.flush()
    return

# Local variables:
# mode: Python
# tab-width: 8
# indent-tabs-mode: nil
# End:
# vi: set expandtab tabstop=8
