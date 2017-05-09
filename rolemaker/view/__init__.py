#!/usr/bin/env python3
"""
Main views renderer for Rolemaker.
"""
from logging import getLogger
from flask import current_app, redirect, render_template, session
from ..util import url_for

log = getLogger("rolemaker.view")

def get_index():
    """
    Render the gateway page.
    """
    log.debug("getting parameters")
    try:
        params = current_app.config["parameters"]
        params.refresh_if_needed()
        return render_template("index.html", url_for=url_for)
    except:
        log.error("Failed to render index", exc_info=True)
        raise

def logout():
    """
    Log the user out by clearing their session.
    """
    session.clear()
    return redirect(url_for("get_index"))
