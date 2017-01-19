<%page args="server, response_headers, session" />
<%!
from rolemaker import AuthenticationRequiredError
from rolemaker.server import Redirect
%><%
redirect_location = request.values.get("redirect", "/")

if request.method == "POST":
    username = request.form.get("username")
    password = request.form.get("password")
    xsrf_token = request.form.get("xsrf-token")

    if (server.is_valid_xsrf_token(xsrf_token) and
        server.authenticate_user(username, password)):
        session['username'] = username
        raise Redirect(redirect_location)
%>
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
            <li><a href="/create">Create</a></li>
          </ul>
        </div><!--/.nav-collapse -->
      </div>
    </nav>
    <div class="container">
      <h1>Login</h1>
      <form class="form-horizontal"
            action="/login?redirect=${redirect_location|h}" method="post">
        <div class="form-group">
          <label for="username" class="col-sm-2 control-label">Username</label>
          <div class="col-sm-4">
            <input type="text" class="form-control" id="username"
                   name="username" placeholder="username">
          </div>
        </div>
        <div class="form-group">
          <label for="password" class="col-sm-2 control-label">Password</label>
          <div class="col-sm-4">
            <input type="password" class="form-control" id="password"
                      name="password" placeholder="password">
          </div>
        </div>
        <input type="hidden" id="xsrf-token" name="xsrf-token"
               value="${server.get_xsrf_token()}">
        <div class="form-group">
          <div class="col-sm-offset-2 col-sm-4">
            <button type="submit" class="btn btn-default">Login</buton>
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

    <script src="js/create_role.js"></script>
  </body>
</html>
