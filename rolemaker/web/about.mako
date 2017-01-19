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
            <li class="active"><a href="#">About</a></li>
            <li><a href="list">List</a></li>
            <li><a href="create">Create</a></li>
          </ul>
        </div><!--/.nav-collapse -->
      </div>
    </nav>

    <div class="container">
      <!-- Main component for a primary marketing message or call to action -->
      <h1>AWS Role Manager</h1>
      <p>This web application allows you to manage AWS Identity and Acccess
        Management (IAM) roles.</p>
      <p>IAM roles allow systems and applications (such as EC2) to interact
        with AWS.  <b>Never use personal or hardcoded credentials
          (username/password or access key/secret key) for applications.</b>
        Create an IAM role through this tool instead.</p>
      <h3><a href="#" role="button" class="collapse-control"
             data-toggle="collapse" data-target="#whatswrong"
             aria-expanded="false" aria-controls="whatswrong"><span class="glyphicon glyphicon-chevron-right" id="whatswrong-caret"></span>What's
          wrong with using my credentials?</a></h3>
      <div class="collapse" id="whatswrong" data-caret="#whatswrong-caret">
        <p>By using your personal credentials, applications have the ability
          to access your personal resources and vice-versa.  It becomes
          impossible to separate your personal data from the applications'
          data.  Permissions become overly permissive and securing the
          resulting complexity becomes impossible without a significant
          rewrite of the application.</p>
      </div>
      <h3><a href="#" role="button" class="collapse-control"
             data-toggle="collapse" data-target="#hardcoded"
             aria-expanded="false" aria-controls="hardcoded"><span class="glyphicon glyphicon-chevron-right" id="hardcoded-caret"></span>What's
            wrong with using hard-coded credentials?</a></h3>
      <div class="collapse" id="hardcoded" data-caret="#hardcoded-caret">
        <p>
          Credential management is a difficult problem.  Typically,
          developers tend to hard-code the credentials in configuration or
          source code.  This presents two major problems:
          <ul>
            <li>Credentials become easy to copy and steal.</li>
            <li>Rotating credentials becomes hard.</li>
          </ul>
          Malicious attackers constantly crawl the Internet for AWS
          credentials,
          <a href="http://wptavern.com/ryan-hellyers-aws-nightmare-leaked-access-keys-result-in-a-6000-bill-overnight">leading
            to bad surprises for unwary developers</a>.  Even if you check
          your configuration file into an internally-controlled source code repository
          and are careful about not distributing this file, another developer
          may reuse your configuration (seeing that it works) and not
          realize the sensitivity of this file.
        </p>
        <p>
          A best security practice is to periodically rotate credentials so
          that any accidentally leaked credentials are likely stale by the
          time it is in the hands of an attacker.  Applications must be able
          to handle credential rotation -- whether scheduled or ad-hoc -- in
          a graceful manner.  This becomes difficult when credentials are
          bundled with the application (often requiring a formal change
          management activity).
        </p>
      </div>
      <h3><a href="#" role="button" class="collapse-control"
             data-toggle="collapse" data-target="#rolesolve"
             aria-expanded="false" aria-controls="rolesolve"><span class="glyphicon glyphicon-chevron-right" id="rolesolve-caret"></span>How
            do roles solve these problems?</a></h3>
      <div class="collapse" id="rolesolve" data-caret="#rolesolve-caret">
        <p>
          Roles provide credentials to your application as needed.  On an
          EC2 instance, your application makes a request to the hypervisor
          and retrieves a set of temporary credentials (valid for one
          hour).
        </p>
        <p>
          If you are using the AWS software development kits (SDKs) or
          the command line tool, this happens automatically -- you do not
          need to do anything special.
        </p>
      </div>
      <h3><a href="#" role="button" class="collapse-control"
             data-toggle="collapse" data-target="#applyec2"
             aria-expanded="false" aria-controls="applyec2"><span class="glyphicon glyphicon-chevron-right" id="applyec2-caret"></span>How
            do I apply a role to my EC2 instance?</a></h3>
      <div class="collapse" id="applyec2" data-caret="#applyec2-caret">
        <p>
          When launching the instance, in Step 3, "Configure Instance
          Details," select an IAM role.
          <a href="#" data-toggle="modal" data-target="#ec2role">Click here
            to see an example.</a>
        </p>
        <p>
          You (or the application launching the EC2 instance) must have
          permissions to call <code>iam:PassRole</code> for this to work.
        </p>
      </div>
      <h3><a href="#" role="button" class="collapse-control"
             data-toggle="collapse" data-target="#readmore"
             aria-expanded="false" aria-controls="readmore"><span class="glyphicon glyphicon-chevron-right" id="readmore-caret"></span>Where
            can I read more about this?</a></h3>
      <div class="collapse" id="readmore" data-caret="#readmore-caret">
        <p>
          AWS has detailed documentation on using IAM roles:
          <ul>
            <li>
              <a href="http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html">IAM Roles for EC2</a>
              <ul>
                <li>Note that, at this site, you cannot use the IAM console for
                  creating roles due to site-specific compliance requirements;
                  use this tool instead.</li>
              </ul>
            </li>
            <li>
              <a href="http://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-ec2.html#role-usecase-ec2app-permissions">Using
              an IAM Role to Grant Permissions to Applications Running on Amazon EC2 Instances</a></li>
            <li>
              <a href="http://www.youtube.com/watch?v=C4AyfV3Z3xs">Getting Started with IAM Roles for EC2 Instances</a> [video].
            </li>
            <li>
              <a href="http://docs.aws.amazon.com/AWSSdkDocsJava/latest/DeveloperGuide/java-dg-roles.html">Using
                IAM Roles for EC2 Instances with the SDK for Java</a>
            </li>
            <li>
              <a href="http://docs.aws.amazon.com/AWSSdkDocsNET/latest/V3/DeveloperGuide/net-dg-roles.html">Using
                IAM Roles for EC2 Instances with the SDK for .NET</a>
            </li>
            <li>
              <a href="http://docs.aws.amazon.com/AWSSdkDocsRuby/latest/DeveloperGuide/ruby-dg-roles.html">Using
                IAM Roles for EC2 Instances with the SDK for Ruby</a>
            </li>
            <li>
              The Python SDK does not require any special handling.
              If credentials are not configured, it will use EC2 IAM roles.
            </li>
          </ul>
        </p>
      </div>
    </div> <!-- /container -->

    <div class="modal fade" id="ec2role" tabindex="-1" role="dialog"
         aria-labelledby="ec2role-label">
      <div class="modal-dialog" role="document">
        <div class="modal-content" style="display: inline-block;">
          <div class="modal-header">
            <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
            <h4 class="modal-title" id="myModalLabel">Assigning an EC2 role
              to an instance</h4>
          </div>
          <div class="modal-body">
            <img src="iam-ec2-role-demo.png" width="800" height="529"
                 style="display: inline-block;">
          </div>
        </div>
      </div>
    </div> <!-- /ec2role modal -->

    <!-- jQuery (necessary for Bootstrap's JavaScript plugins).
         Again, we don't use the CDN here for security purposes. -->
    <script src="js/jquery-1.11.3.min.js"></script>

    <!-- Enable collapsing -->
    <script src="js/collapse.js"></script>
    <!-- Include all compiled plugins (below), or include individual files
         as needed.  We don't use CDNs here for security purposes. -->
    <script src="js/bootstrap.min.js"></script>
  </body>
</html>
