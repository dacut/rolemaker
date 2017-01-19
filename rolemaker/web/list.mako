<%page args="server, response_headers" />\
<%!
from rolemaker import AuthenticationRequiredError
%>\
<%
iam = server.policy_model.iam

# Make sure the caller is authenticated
if not 'username' in session:
    raise AuthenticationRequiredError()
%>\
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
            <li class="active"><a href="#">List</a></li>
            <li><a href="create">Create</a></li>
          </ul>
        </div><!--/.nav-collapse -->
      </div>
    </nav>
    <div class="container">
      <h1>Existing Roles</h1>
      <%
      result = iam.list_roles()
      roles = result.roles
      roles.sort(key=lambda role: role.role_name.lower())
         %>
      % for role in roles:
      <% role_id = role['role_id'] %>
      <a role="button" class="collapse-control" data-toggle="collapse"
         data-target="#${role_id}" aria-expanded="false"
         aria-controls="${role_id}"><span class="glyphicon glyphicon-chevron-right" id="${role_id}-caret"></span>${role['role_name'] | h}</a>
      <div class="collapse load-role-dynamic" id="${role_id}" data-caret="#${role_id}-caret" data-rolename="${role.role_name|h}">
        <img src="/loading.gif" width=100 height=40>
      </div><br>
      % endfor
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
    <script src="js/load_role.js"></script>
  </body>
</html>
