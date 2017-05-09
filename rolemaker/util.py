#!/usr/bin/env python3
"""
Rolemaker utilities that don't fit anywhere else.
"""

from flask import url_for as flask_url_for

def url_for(*args, **kw):
    """
    url_for(*args, **kw)

    This is the same as Flask's url_for except _scheme defaults to 'https' and
    _external defaults to True.
    """
    kw.setdefault("_scheme", "https")
    kw.setdefault("_external", True)
    return flask_url_for(*args, **kw)
