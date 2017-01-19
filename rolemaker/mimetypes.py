#!/usr/bin/env python
from __future__ import absolute_import, division, print_function
from os.path import dirname

def read_mime_types():
    """
    Read the Apache mime.types file so we can autoguess the MIME type
    based on the file extension.
    """
    mime_types = {}
    
    with open(dirname(__file__) + "/mime.types", "r") as fd:
        for line in fd:
            line = line.strip()
            # Ignore empty lines and comments (lines starting with #)
            if line.startswith("#") or line == "":
                continue

            # Format of each entry is:
            # mimetype ext1 [ext2...]
            # There may be multiple whitespace characters between each field,
            # so we can't use split(" ", 1) here.
            parts = line.split()
            mime_type = parts[0]
            extensions = parts[1:]

            for ext in extensions:
                mime_types[ext] = mime_type

    return mime_types

# Local variables:
# mode: Python
# tab-width: 8
# indent-tabs-mode: nil
# End:
# vi: set expandtab tabstop=8
