#!/bin/bash -ex
zipbase=rolemaker-$$.zip
zipfile=/tmp/$zipbase
(
  cd venv/lib/python2.7/site-packages;
  zip --quiet --recurse-paths $zipfile . --exclude \
    boto3\* botocore\* lambda_packages\* pip\* wheel\*
  cd ..
  zip --quiet $zipfile site.py site.pyc orig-prefix.txt
)
(
  cd fake_lambda_packages
  python -m py_compile lambda_packages/__init__.py
  zip --quiet --recurse-paths $zipfile lambda_packages
)
python -m py_compile cfnutil.py handler.py rolemaker.py zappa_settings.py
zip --quiet $zipfile cfnutil.py* handler.py* rolemaker.py* zappa_settings.py*
zip --quiet --recurse-paths $zipfile static templates
aws s3 cp $zipfile s3://cuthbert-usw2/$zipbase
sed -e "s/S3Key: rolemaker-dev-.*/S3Key: $zipbase/" cloudformation.yml > /tmp/cloudformation-$$.yml
aws cloudformation update-stack --stack-name RoleMaker \
  --template-body "$(cat /tmp/cloudformation-$$.yml)" \
  --parameters '[{"ParameterKey": "DynamoDBTablePrefix", "UsePreviousValue": true}]' \
  --capabilities CAPABILITY_IAM
