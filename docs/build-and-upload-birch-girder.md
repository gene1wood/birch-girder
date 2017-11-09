How to build and upload birch-girder to AWS
===========================================

Build and package virtualenv
----------------------------

To build the zip file containing the virtualenv, spin up an Amazon Linux
EC2 instance (as this is the environment that AWS Lambda functions run
in). Create the zip file as follows

    sudo yum -y groupinstall 'Development Tools'
    sudo yum -y install libyaml-devel
    virtualenv build-birch-girder-environment
    git clone https://github.com/gene1wood/birch-girder
    mkdir birch-girder-project
    pip install -r birch-girder/requirements.txt -t birch-girder-project
    cd birch-girder-project
    zip -r ../birch-girder.zip *

Then fetch the resulting zip from the ec2 instance with scp

Add the Birch Girder lambda code to the zipped virtualenv
------------------------------------------

    zip --junk-paths artifacts/birch-girder.zip birch_girder/__init__.py

Add your config to the zipped virtualenv
----------------------------------------

    zip --junk-paths artifacts/birch-girder.zip birch_girder/config.yaml

Add any plugins
----------------------------------------

    zip artifacts/birch-girder.zip plugins/example1.py
    zip artifacts/birch-girder.zip plugins/example2.py

Publish package to AWS Lambda
-----------------------------

    export AWS_DEFAULT_PROFILE="myprofilename"
    export AWS_DEFAULT_REGION="us-west-2"
    export AWS_ACCOUNT_ID="0123456789012"
    aws lambda create-function --function-name birch-girder --runtime python2.7 --timeout 30 --role arn:aws:iam::$AWS_ACCOUNT_ID:role/birch-girder --handler __init__.lambda_handler --zip-file fileb://artifacts/birch-girder.zip

There are lambda add-permissions steps needed here which are done by
manage.py to grant SES rights to invoke this function.

Iterate on code by updating and uploading
-----------------------------------------

If you want to extend or modify the monitor you can update the running
code like this

    # Update the file in the zip archive 
    zip --junk-paths artifacts/birch-girder.zip birch_girder/__init__.py

    # Upload the new zip file
    aws lambda update-function-code --function-name birch-girder --zip-file fileb://artifacts/birch-girder.zip

If you want to change your configuration

    # Update the file in the zip archive 
    zip --junk-paths artifacts/birch-girder.zip birch_girder/config.yaml

    # Upload the new zip file
    aws lambda update-function-code --function-name birch-girder --zip-file fileb://artifacts/birch-girder.zip
