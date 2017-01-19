"use strict";

jQuery(function ($) {
    var on_load_done = function (data) {
        var html = "";
        var policy;
        var policy_document;
        var policy_names;
        var policy_name;
        var i;
        var toLower = function (name) { name.toLowerCase() };

        // Show the attached policies, sorted by name.
        policy_names = _.keys(data.attached_policies);
        policy_names = _.sortBy(policy_names, toLower);

        for (i in policy_names) {
            policy_name = policy_names[i];
            policy = data.attached_policies[policy_name];
            policy_document = (
                policy.policy_versions[policy.default_version_id].document);

            html += ("<div><b>" + _.escape(policy_name) +
                     "</b> (managed policy)<br>" +
                     "<i>" + _.escape(policy.description) + "</i><br>" +
                     "<pre class='policy-document'>" +
                     _.escape(policy_document) + "</pre>" +
                     "</div>");
        }

        // And the inline policies, again sorted by name.
        policy_names = _.keys(data.inline_policies);
        policy_names = _.sortBy(policy_names, toLower);

        for (i in policy_names) {
            policy_name = policy_names[i];
            policy_document = data.inline_policies[policy_name];
            html += ("<div><b>" + _.escape(policy_name) +
                     "</b> (inline policy)<br><pre class='policy-document'>" +
                     _.escape(policy_document) + "</pre></div>");
        }

        if (html == "") {
            html = "<i>No attached or inline policies</i>";
        }

        this.find("img").replaceWith(html);
    };
    
    var on_show = function (ev) {
        var div = $(ev.currentTarget);
        var role_name = div.attr("data-rolename");

        if (! div.hasClass("loaded") && role_name) {
            div.addClass("loaded");
            $.getJSON("/json/role/" + role_name + "/policies",
                      _.bind(on_load_done, div));
        }
    };

    $(".load-role-dynamic").each(function () {
        $(this).on("show.bs.collapse", on_show);
    });
});
