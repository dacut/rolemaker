#!/bin/bash -ex
zipbase=rolemaker-$$.zip
zipfile=/tmp/$zipbase
(
  cd venv/lib/python2.7/site-packages;
  zip --quiet --recurse-paths $zipfile . --exclude \
    boto3\* botocore\* pip\* setuptools\* wheel\*
  cd ..
  zip --quiet $zipfile site.py site.pyc orig-prefix.txt
)
python -m py_compile rolemaker.py sitecustomize.py
zip --quiet $zipfile rolemaker.py rolemaker.pyc sitecustomize.py sitecustomize.pyc
aws s3 cp $zipfile s3://cuthbert-usw2/$zipbase
sed -e "s/S3Key: rolemaker-dev-.*/S3Key: $zipbase/" cloudformation.yml > /tmp/cloudformation-$$.yml
aws cloudformation update-stack --stack-name Rolemaker \
  --template-body "$(cat /tmp/cloudformation-$$.yml)" \
  --parameters '[{"ParameterKey": "DynamoDBTablePrefix", "UsePreviousValue": true}]' \
  --capabilities CAPABILITY_IAM
