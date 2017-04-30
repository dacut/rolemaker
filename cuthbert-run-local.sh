#!/bin/sh
FLASK_APP=rolemaker.py DYNAMODB_TABLE_PREFIX=Rolemaker. \
ENCRYPTION_KEY_ID=fee3e434-e8ef-4d01-83aa-10187cfeb09a \
flask run
