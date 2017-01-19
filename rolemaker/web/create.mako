<%page args="server, response_headers, request, session, role_name_error='', managed_policy_error='', create_error=''" />\
<%!
from rolemaker import AuthenticationRequiredError
from math import ceil
%>\
<%
policy_model = server.policy_model

# Make sure the caller is authenticated
if not 'username' in session:
    raise AuthenticationRequiredError()

# Sort local and AWS managed policies.
local_policies = sorted(
    policy_model.attachable_policies['local'].values(),
    key=lambda policy: policy['name'])
aws_policies = sorted(
    policy_model.attachable_policies['aws'].values(),
    key=lambda policy: policy['name'])
policy_count = len(local_policies) + len(aws_policies)
policy_index = [0]
policy_break_at = int(ceil(0.5 * policy_count))
def incr_policy_index():
    policy_index[0] += 1
    return policy_index[0]

# Sort trust relationships by description
all_trust_relationships = sorted(
    policy_model.trust_relationships.iteritems(),
    key=lambda kv: kv[1])

# Get previously submitted form values (if they exist).
role_name = request.form.get('role-name', "")
managed_policies = request.form.getlist('managed-policies')
inline_policy_name = request.form.get('inline-policy-name', "InlinePolicy")
inline_policy = request.form.get('inline-policy', "")

if 'trust-relationships' in request.form:
    trust_relationships = request.form.getlist('trust-relationships')
else:
    trust_relationships = ["ec2.amazonaws.com"]

# Do not hide error parameters if we have error messages to display.
role_name_error_hidden = "hidden" if not role_name_error else ""
managed_policy_error_hidden = "hidden" if not managed_policy_error else ""
%>\
<%def name="write_managed_policy(policy, policy_type)">
<% global policy_index %>
% if policy['arn'] in managed_policies:
<% checked='checked="checked"' %>
% else:
<% checked='' %>
% endif
<input type="checkbox" class="managed-policy-checkbox"
       name="managed-policies" ${checked} value="${policy['arn']|h}">
<span class="tooltip-enabled" data-toggle="tooltip"
      data-placement="auto" data-delay='{"show": "500", "hide": "100"}'
      title="${policy['description']|h}">${policy['name']|h}</span>
(${policy_type|h})<br>
% if incr_policy_index() == policy_break_at:
</div><div class="col-sm-6">
% endif
</%def>
<!DOCTYPE html>
<html lang="en">
  <head>
    <!-- This uses the Bootstrap framework.  For information on this,
         see http://getbootstrap.com/ -->

    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <!-- The above 3 meta tags *must* come first in the head; any other head
         content must come *after* these tags -->
    <title>AWS Account Role Maker</title>

    <!-- Bootstrap -- we do not use the CDN here for security reasons (might
         get compromised). -->
    <link href="css/bootstrap.min.css" rel="stylesheet">

    <!-- Site-specific customization -->
    <link href="css/local.css" rel="stylesheet">
  </head>
  <body>
    <!-- Fixed navbar -->
    <nav class="navbar navbar-default navbar-fixed-top">
      <div class="container">
        <div class="navbar-header">
          <a class="navbar-brand" href="#">AWS Role Manager</a>
        </div>
        <div id="navbar" class="navbar-collapse collapse">
          <ul class="nav navbar-nav">
            <li><a href="/">About</a></li>
            <li><a href="/list">List</a></li>
            <li class="active"><a href="#">Create</a></li>
          </ul>
        </div><!--/.nav-collapse -->
      </div>
    </nav>
    <div class="container">
      <h1>Create New Role</h1>
      <form action="/create" method="post">
        <div class="error-callout col-sm-12 ${'hidden' if not create_error else ''}"
             id="create-error">${create_error}</div>
        <div class="control-group col-sm-12">
          <label for="name">Role name</label>
          <div class="controls">
            <input autocomplete="off" type="text" class="form-control"
                   id="role-name" name="role-name" placeholder="RoleName"
                   value="${role_name|h}" data-fieldName="Role name"
                   data-errorElement="#role-name-error">
            <div class="error-callout ${role_name_error_hidden}" id="role-name-error">${role_name_error}</div>
            <small class="help-block muted">Maximum 64 characters. Valid
              characters are alphanumeric and <tt>+ = , . @ - _</tt> .
              The role name cannot be changed later.</small>
          </div>
        </div>
        <div id="settings" class="col-sm-12">
          <ul class="nav nav-tabs" role="tablist">
            <li role="presentation" class="active"><a href="#managed-policies" aria-controls="managed-policies" role="tab" data-toggle="tab">Managed Policies</a></li>
            <li role="presentation"><a href="#inline-policy-tab" aria-controls="inline-policy-tab" role="tab" data-toggle="tab">Inline Policy</a></li>
            <li role="presentation"><a href="#trust-relationships" aria-controls="trust-relationships" role="tab" data-toggle="tab">Trust Relationships</a></li>
            <li role="presentation"><a href="#confirm" aria-controls="confirm" role="tab" data-toggle="tab">Confirmation</a></li>
          </ul>

          <div class="tab-content">
            <div role="tabpanel" class="tab-pane active"
                 id="managed-policies">
              <small class="help-block muted">You may attach up to
                ${policy_model.max_attached_policies} managed policies. Hover over a
                policy name for a description of that policy.</small>
              <div class="error-callout ${managed_policy_error_hidden}" id="managed-policy-error">${managed_policy_error}</div>
              <input type="hidden" id="max-attached-policies"
                     value="${policy_model.max_attached_policies}">
              <div class="col-sm-6">
                % for policy in local_policies:
                ${write_managed_policy(policy, "Local")}
                % endfor
                % for policy in aws_policies:
                ${write_managed_policy(policy, "AWS")}
                % endfor
              </div>
            </div>
            <div role="tabpanel" class="tab-pane" id="inline-policy-tab">
              <small class="help-block muted">You may enter a custom (inline)
                IAM policy below. This policy is applied along with managed
                policies.
                <a href="http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html">Click here</a>
                for documentation about the IAM policy language.</small>
              <label for="inline-policy-name">Inline policy name</label>
              <div class="controls">
                <input autocomplete="off" type="text" class="form-control"
                       id="inline-policy-name" name="inline-policy-name"
                       placeholder="PolicyName"
                       data-fieldName="Inline policy name"
                       data-errorElement="#inline-policy-error"
                       value="${inline_policy_name}"><br>
              </div>
              <div class="error-callout hidden" id="inline-policy-error"></div>
              <label for="inline-policy">Policy document</label>
              <div class="controls">
                <textarea class="form-control code" id="inline-policy"
                          name="inline-policy"
                          rows="20">${inline_policy|h}</textarea>
                <button type="button" class="btn btn-primary float-right"
                        id="inline-policy-validate">Validate</button>
                <div class="clear-both"></div>
              </div>
              <small class="help-block muted">Example:
                <pre>{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Allow read access to EC2 resources",
            "Effect": "Allow",
            "Action": [ "ec2:Describe*" ],
            "Resource": "*"
        },
        {
            "Sid": "Don't allow access to VPN configuration info",
            "Effect": "Deny",
            "Action": [ "ec2:DescribeVpnConnections" ],
            "Resource": "*"
        }
    ]
}</pre></small>
            </div>
            <div role="tabpanel" class="tab-pane" id="trust-relationships">
              <small class="help-block muted">Trust relationships describe
                which services are allowed to access this role.</small>
              % for service, description in all_trust_relationships:
              <% checked = 'checked="checked"' if service in trust_relationships else '' %>
              <input type="checkbox" id="trust-${service|h}"
                     name="trust-relationships" ${checked}
                     value="${service|h}"> ${description|h}<br>
              % endfor
            </div>
            <div role="tabpanel" class="tab-pane form-horizontal" id="confirm">
              <small class="help-block muted">Enter your username and
                two-factor (token) authentication code to create the role.
                </small>
              <div class="error-callout hidden" id="confirm-error"></div>
              <div class="form-group">
                <label for="username" class="col-sm-2 control-label">Username</label>
                <div class="col-sm-4">
                  <input type="text" class="form-control" id="username"
                         name="username" placeholder="username">
                </div>
              </div>
              <div class="form-group">
                <label for="authentication-code" class="col-sm-2 control-label">Authentication code</label>
                <div class="col-sm-4">
                  <input type="password" class="form-control"
                         id="authentication-code" name="authentication-code">
                </div>
              </div>

              <div class="col-sm-offset-2 col-sm-4">
                <button class="btn btn-primary" type="submit">Create role</button>
              </div>

              <!-- Prevent autocomplete from happening; trying to cache
                   MFA tokens is silly and can confuse novice users. -->
              <input type="text" style="display:none">
              <input type="password" style="display:none">
            </div>
          </div>
        </div>
      </form>
    </div>
    <!-- jQuery (necessary for Bootstrap's JavaScript plugins).
         Again, we don't use the CDN here for security purposes. -->
    <script src="js/jquery-1.11.3.min.js"></script>

    <!-- Underscore (needed for dynamic loading). -->
    <script src="js/underscore-min.js"></script>

    <!-- Include all compiled plugins (below), or include individual files
         as needed.  We don't use CDNs here for security purposes. -->
    <script src="js/bootstrap.min.js"></script>

    <!-- Enable collapsing -->
    <script src="js/collapse.js"></script>

    <!-- JSON lint, for validating inline policies -->
    <script src="js/jsonlint.js"></script>

    <!-- Page-specific functions -->
    <script src="js/create_role.js"></script>
  </body>
</html>
