"use strict";

var _alertIcon = ("<span class='glyphicon glyphicon-alert error-icon'>" +
                  "</span>&nbsp;&nbsp; ");

function validateIAMPolicy(doc) {
    var keys = _.keys(doc);
    var i, j, key, value;
    
    for (i in keys) {
        key = keys[i];
        value = doc[key];
        
        if (key === "Version") {
            if (value !== "2008-10-17" && value !== "2012-10-17") {
                throw ('Invalid policy version "' + value + '"; must be ' +
                       '"2008-10-17" or "2012-10-17".');
            }
        } else if (key === "Id") {
            if (! _.isString(value)) {
                throw "Policy Id must be a string.";
            }
        } else if (key === "Statement") {
            if (!_.isObject(value)) {
                throw "Statement must be an object or array.";
            }

            if (_.isArray(value)) {
                for (j in value) {
                    validateIAMStatement(value[j], j);
                }
            } else {
                validateIAMStatement(value, 0);
            }
        } else {
            throw 'Invalid policy element "' + key + '".';
        }
    }
}

function validateIAMStatement(doc, index) {
    var keys = _.keys(doc);
    var stmt = "Statement " + (index + 1).toString();
    var effectSeen = false, action = null, resource = null;
    var i, j, key, value;

    for (i in keys) {
        key = keys[i];
        value = doc[key];

        if (key === "Sid") {
            if (! _.isString(value)) {
                throw stmt + " Sid must be a string.";
            }
        } else if (key === "Effect") {
            if (value !== "Allow" && value !== "Deny") {
                throw stmt + ' Effect must be "Allow" or "Deny".';
            }
            effectSeen = true;
        } else if (key === "Action" || key === "NotAction") {
            if (action !== null) {
                throw (stmt + ' cannot have both ' + key + ' and ' + action +
                       ' blocks.');
            }

            if (_.isString(value)) {
                validateIAMAction(value, 0);
            } else if (_.isArray(value)) {
                for (j in value) {
                    validateIAMAction(value[j], j);
                }
            } else {
                throw (stmt + ' has an invalid ' + key + ' block; expected ' +
                       'string or object.');
            }
            action = key;
        } else if (key === "Resource" || key === "NotResource") {
            if (resource !== null) {
                throw (stmt + ' cannot have both ' + key + ' and ' + resource +
                       ' blocks.');
            }

            if (_.isString(value)) {
                validateIAMResource(value, 0);
            } else if (_.isArray(value)) {
                for (j in value) {
                    validateIAMResource(value[j], j);
                }
            } else {
                throw (stmt + ' has an invalid ' + key + ' block; expected ' +
                       'string or object.');
            }
            resource = key;
        } else if (key === "Condition") {
            if (! _.isObject(value) || _.isArray(value)) {
                throw (stmt + ' has an invalid Condition block; expected ' +
                       'object.');
            }
            validateIAMCondition(value);
        } else {
            throw (stmt + ' has an unknown key "' + key + '".');
        }
    }
    return;
}

function validateIAMAction() {
}

function validateIAMResource() {
}

function validateIAMCondition() {
}

var _validNameRegex = /^[\w\+=,\.@-]*$/;
function isValidIAMName(name) {
    return _validNameRegex.test(name);
}

function validateIAMNameField() {
    var name = $(this).val();
    var fieldName = $(this).attr("data-fieldName");
    var errorElement = $($(this).attr("data-errorElement"));
    if (name.length == 0) {
        errorElement.removeClass("hidden").html(
            _alertIcon + fieldName + " is required.");
    } else if (name.length > 64) {
        errorElement.removeClass("hidden").html(
            _alertIcon + fieldName + " is longer than 64 characters.");
    } else if (! isValidIAMName(name)) {
        errorElement.removeClass("hidden").html(
            _alertIcon + fieldName + " contains invalid characters.");
    } else {
        errorElement.addClass("hidden");
    }
}


jQuery(function ($) {
    // How many managed policies can we attach?  (This varies across
    // deployments).
    var maxAttachedPolicies = parseInt($("#max-attached-policies").val());
    console.log("maxAttachedPolicies: " + maxAttachedPolicies);
    
    // Enable tooltips
    $('[data-toggle="tooltip"]').tooltip();

    // Validate the role and inline policy names.
    $("#role-name").on("keyup", validateIAMNameField);
    $("#inline-policy-name").on("keyup", validateIAMNameField);

    // Validate managed policy count
    $(".managed-policy-checkbox").on("change", function (ev) {
        var num_checked = 0;

        $(".managed-policy-checkbox").each(function () {
            if ($(this).prop("checked")) {
                ++num_checked;
            }
        });

        console.log("Managed policies to attach: " + num_checked);        

        if (num_checked > maxAttachedPolicies) {
            $("#managed-policy-error").removeClass("hidden").html(
                _alertIcon + "More than " + maxAttachedPolicies +
                    " managed policies selected.");
        } else {
            $("#managed-policy-error").addClass("hidden");
        }
    });

    // Validate inline policy syntax.
    $("#inline-policy-validate").on("click", function () {
        var doctext = $("#inline-policy").val();
        var doc, message, parseErrorMatch;
        
        try {
            console.log("parsing: " + doctext);
            doc = jsonlint.parse(doctext);
            console.log(doc);

            if (! _.isObject(doc) || _.isArray(doc)) {
                throw "Policy document must be a JSON object (key-value map)";
            }

            validateIAMPolicy(doc);

            $("#inline-policy-error").addClass("hidden");
            $("#inline-policy-ok").removeClass("hidden").html(
                "Policy parsed successfully.");
        }
        catch (e) {
            message = _.escape(e.toString());

            // If jsonlint is showing where the error is, use fixed-width
            // to display it.
            parseErrorMatch = /^(.*Parse error on line [0-9]+:)\n(.*)\n(-*\^)\n((.|\n)*)$/.exec(message);
            if (parseErrorMatch) {
                console.log("Match: " + parseErrorMatch);
                message = (parseErrorMatch[1] + "<pre>" + parseErrorMatch[2] +
                           "\n" + parseErrorMatch[3] + "</pre>" +
                           parseErrorMatch[4]);
            }
            
            $("#inline-policy-error").removeClass("hidden").html(
                _alertIcon + message);
        }
    });
});
