#!/usr/bin/env python3
"""
Handle cross-site request forgery (XSRF) for Rolemaker.
"""
from base64 import b64encode
from os import urandom
from flask import request, session

def get_xsrf_token():
    """
    get_xsrf_token() -> str

    Return the cross site request forgery (XSRF) token for the current
    session, generating it and setting it in the session cookie if necessary.
    """
    if "xsrf_token" not in session:
        session["xsrf_token"] = str(b64encode(urandom(18)))

    return session["xsrf_token"]


def xsrf_ok():
    """
    xsrf_ok() -> bool

    Indicates whether the cross site request forgery (XSRF) token for the
    form matched that of the session cookie.
    """
    form_xsrf = request.form.get("xsrf")
    session_xsrf = get_xsrf_token()
    return form_xsrf == session_xsrf
