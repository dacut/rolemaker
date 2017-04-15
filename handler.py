#!/usr/bin/env python
from __future__ import absolute_import, print_function
def lambda_handler(event, context):
    if "StackId" in event:
        import cfnutil
        return cfnutil.lambda_handler(event, context)
    else:
        import zappa.handler
        return zappa.handler.lambda_handler(event, context)
