#!/usr/bin/env python3
"""
View functions under the /admin tree
"""
from http import HTTPStatus
from flask import (
    Blueprint, current_app, flash, make_response, redirect, render_template,
    request, session
)
from markupsafe import escape as escape_html
from passlib.hash import pbkdf2_sha256
import requests
from requests.exceptions import RequestException
from ..util import url_for
from ..xsrf import xsrf_ok

# pylint: disable=invalid-name
blueprint = Blueprint("admin", __name__, template_folder="templates")

@blueprint.route("/", methods=["GET", "HEAD"])
def get_admin_index():
    """
    Render GET on the /admin page
    """
    current_app.config["parameters"].refresh_if_needed()
    return render_template("admin/index.html")


@blueprint.route("/", methods=["POST"])
def post_admin_index():
    """
    Handle POST to the /admin page
    """
    action = request.form.get("action")
    if action == "initial-admin-login":
        return initial_admin_login()
    elif action == "site-config":
        return update_site_config()
    elif action == "auth-config":
        return update_auth_config()

    flash("Unknown form submitted.", category="error")
    return make_response(render_template("admin/index.html"),
                         HTTPStatus.BAD_REQUEST)

def initial_admin_login():
    """
    Handle first-time admin login using a passphrase
    """
    parameters = current_app["parameters"]
    parameters.refresh()
    password_hash = parameters["AdminPasswordHash"]
    password = request.form.get("password")

    if not xsrf_ok():
        flash("Form expired. Please try again.", category="error")
        status = HTTPStatus.BAD_REQUEST
    elif not password:
        flash("Password cannot be empty.", category="error")
        status = HTTPStatus.UNAUTHORIZED
    elif not password_hash:
        flash("This Rolemaker deployment has already been configured.",
              category="error")
        status = HTTPStatus.FORBIDDEN
    elif pbkdf2_sha256.verify(password, password_hash):
        session["is_admin"] = True
        status = HTTPStatus.OK
    else:
        flash("Incorrect password.", category="error")
        status = HTTPStatus.UNAUTHORIZED

    return make_response(render_template("admin/index.html"), status)


def update_site_config():
    """
    This is invoked when new site configuration information is POSTed.
    """
    parameters = current_app["parameters"]
    parameters.refresh_if_needed()
    site_dns = request.form.get("site-dns", "")
    updates = {}
    errors = []

    if site_dns != parameters["SiteDNS"]:
        updates["SiteDNS"] = site_dns

    if not errors:
        for key, value in updates.items():
            parameters[key] = value
        flash("Site configuration updated", category="info")
    else:
        for error in errors:
            flash(error, category="error")

    return redirect(url_for("get_admin_index"))


def update_auth_config():
    """
    This is invoked when new site authentication configuration information is
    POSTed.
    """
    parameters = current_app["parameters"]
    parameters.refresh_if_needed()
    idp_metadata_url = request.form.get("idp-metadata-url", "").strip()
    sp_certificate_subject = (
        request.form.get("sp-certificate-subject", "").strip())
    sp_subject_alternative_names = (
        request.form.get("sp-subject-alternative-names").strip())
    updates = {}
    errors = []

    if idp_metadata_url != parameters["IdPMetadataURL"]:
        try:
            idp_metadata = get_idp_metadata(idp_metadata_url, errors)
            updates["IdPMetadataURL"] = idp_metadata_url
            updates["IdPMetadata"] = idp_metadata
        except RequestException as e:
            errors.append(
                "Unable to read SAML metadata from %s: %s" %
                (escape_html(idp_metadata_url), escape_html(str(e))))

    if sp_certificate_subject != parameters["SPSubject"]:
        if not sp_certificate_subject:
            errors.append("SAML SP certificate subject cannot be empty")
        else:
            updates["SPSubject"] = sp_certificate_subject

    if sp_subject_alternative_names != parameters["SPSubjectAlternativeNames"]:
        updates["SPSubjectAlternativeNames"] = sp_subject_alternative_names

    if not errors:
        for key, value in updates.items():
            parameters[key] = value

        # Force a certificate renewal if we've updated the certificate subject.
        if "SPSubject" in updates or "SPSubjectAlternativeNames" in updates:
            current_app.config["saml"].generate_sp_certificate(overwrite=True)

        flash("Site authentication configuration updated", category="info")
    else:
        for error in errors:
            flash(error, category="error")

    return redirect(url_for("get_admin_index"))

def get_idp_metadata(idp_metadata_url, errors):
    """
    Retrieve the SAML identity provider (IdP) metadata.
    """

    r = requests.get(idp_metadata_url)
    if r.status_code != HTTPStatus.OK:
        errors.append(
            "Unable to read SAML metadata from %s: HTTP error %s: %s" %
            (escape_html(idp_metadata_url),
             escape_html(str(r.status_code)),
             escape_html(str(r.reason))))

    return r.text
