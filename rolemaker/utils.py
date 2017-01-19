#!/usr/bin/env python
from __future__ import absolute_import, division, print_function
from six.moves import cStringIO as StringIO
import xml.parsers.expat as expat

class ExceptionData(object):
    """
    Capture data from an XML-formatted exception from AWS.
    """
    _type_path = ("ErrorResponse", "Error", "Type")
    _code_path = ("ErrorResponse", "Error", "Code")
    _message_path = ("ErrorResponse", "Error", "Message")
    _detail_path = ("ErrorResponse", "Error", "Detail")
    _requestid_path = ("ErrorResponse", "RequestId")
    
    _cdata_paths = {
        _type_path: "error_type",
        _code_path: "error_code",
        _message_path: "message",
        _detail_path: "detail",
        _requestid_path: "request_id",
    }

    def __init__(self):
        self.error_type = None
        self.error_code = None
        self.message = None
        self.detail = None
        self.request_id = None
        self.pending_cdata = None
        self._path = []
        return

    def parse_exception(self, exc):
        parser = expat.ParserCreate()
        parser.CharacterDataHandler = self.handle_cdata
        parser.StartElementHandler = self.handle_start_element
        parser.EndElementHandler = self.handle_end_element
        parser.Parse(exc.args[2], 1)
        return

    @classmethod
    def from_exception(cls, exc):
        result = cls()
        result.parse_exception(exc)
        return result

    def handle_cdata(self, data):
        if self.pending_cdata is not None:
            self.pending_cdata.write(data)
        return

    def handle_start_element(self, name, attrs):
        self._path.append(name)
        if tuple(self._path) in self._cdata_paths:
            self.pending_cdata = StringIO()
        return

    def handle_end_element(self, name):
        if self.pending_cdata is not None:
            cdata = self.pending_cdata.getvalue()
            attr = self._cdata_paths[tuple(self._path)]

            setattr(self, attr, cdata)
            self.pending_cdata = None
            
        if self._path[-1] == name:
            del self._path[-1]

        return

# Local variables:
# mode: Python
# tab-width: 8
# indent-tabs-mode: nil
# End:
# vi: set expandtab tabstop=8
