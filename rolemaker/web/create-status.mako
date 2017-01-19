<%page args="server, response_headers, request, session, request_id=''" />\
<%!
from flask import abort
from httplib import NOT_FOUND
from rolemaker import AuthenticationRequiredError
from time import gmtime, strftime, time
%>\
<%
# Make sure the caller is authenticated
if not 'username' in session:
    raise AuthenticationRequiredError()

if not request_id:
    abort(NOT_FOUND)

status = server.policy_model.get_create_status(request_id)
if status is None:
    abort(NOT_FOUND)

done = True if status.get("done", "false") == "true" else False

now = time()
update_time = status.get("time")
if update_time is None:
    whence = "Unknown"
else:
    delta = now - update_time
    formatted = strftime("%Y-%m-%d %H:%M:%S UTC", gmtime(update_time))
    if delta < 1:       delta_str = "Just now"
    elif delta < 2:     delta_str = "1 second ago"
    elif delta < 60:    delta_str = "%d seconds ago" % int(delta)
    elif delta < 120:   delta_str = "1 minute ago"
    elif delta < 3600:  delta_str = "%d minutes ago" % (int(delta) // 60)
    elif delta < 7200:  delta_str = "1 hour ago"
    elif delta < 86400: delta_str = "%d hours ago" % (int(delta) // 3600)
    elif delta < 172800: delta_str = "1 day ago"
    else:               delta_str = "%d days ago" % (int(delta) // 86400)

    if done:
        whence = formatted
    else:
        whence = delta_str + " (" + formatted + ")"
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
    <link href="../css/bootstrap.min.css" rel="stylesheet">

    <!-- Site-specific customization -->
    <link href="../css/local.css" rel="stylesheet">

    <!-- Refresh every 5 seconds if we're not done. -->
    % if not done:
    <meta http-equiv="refresh" content="5">
    % endif
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
      <h1>Creation Request ${request_id|h}</h1>
      <div class="row">
        <div class="col-md-2">Status:</div>
        <div class="col-md-10">${status['status']|h}</div>
      </div>
      <div class="row">
        <div class="col-md-2">Last update:</div>
        <div class="col-md-10">${whence|h}</div>
      </div>

      %if done:
      <div class="row">
        <div class="col-md-12"><b>Creation request finished processing.</b></div>
      </div>
      %endif
    </div>
    <!-- jQuery (necessary for Bootstrap's JavaScript plugins).
         Again, we don't use the CDN here for security purposes. -->
    <script src="../js/jquery-1.11.3.min.js"></script>

    <!-- Underscore (needed for dynamic loading). -->
    <script src="../js/underscore-min.js"></script>

    <!-- Include all compiled plugins (below), or include individual files
         as needed.  We don't use CDNs here for security purposes. -->
    <script src="../js/bootstrap.min.js"></script>
  </body>
</html>
