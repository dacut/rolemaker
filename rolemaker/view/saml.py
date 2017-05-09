#/usr/bin/env python3
"""
Handle SAML views for the application.
"""
from http import HTTPStatus
from flask import (
    Blueprint, current_app, make_response, redirect, request, session,
)
from rolemaker.util import url_for

 # pylint: disable=invalid-name
blueprint = Blueprint("saml", __name__, template_folder="templates")

@blueprint.route("/sso", methods=["POST"])
def idp_initiated(target=None):
    """
    Handle an IDP post to our single-signon endpoint.
    """
    saml_response = request.form.get("SAMLResponse")
    if saml_response is None:
        # FIXME: Make better error page.
        return make_response((
            "", HTTPStatus.BAD_REQUEST, {"Content-Type": "text/plain"}
        ))

    saml = current_app.config["saml"]
    parameters = current_app.config["parameters"]

    claims = saml.get_claims(saml_response)
    session.clear()
    session["username"] = claims["username"]
    session["groups"] = claims["groups"]
    admin_groups = parameters.get("AdminGroups", [])

    for group in claims["groups"]:
        if group in admin_groups:
            session["is_admin"] = True
            break
    else:
        session["is_admin"] = False

    if target is None:
        target = url_for("get_index")

    return redirect(target)


@blueprint.route("/metadata.xml", methods=["GET"])
def get_saml_metadata():
    """
    Return the SAML metadata for this system.
    """
    saml = current_app.config["saml"]
    try:
        metadata = saml.saml_metadata
    except ValueError as e: # pylint: disable=invalid-name
        return make_response(
            (str(e), HTTPStatus.SERVICE_UNAVAILABLE,
             {"Content-Type": "text/plain; charset=utf-8"})
        )

    return make_response((
        metadata, HTTPStatus.OK, {"Content-Type": "text/xml; charset=utf-8"}))
