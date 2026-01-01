# How to build and upload birch-girder to AWS

## Create the Lambda Layer

### Method 1 : Use pip and manylinux2014_x86_64

1. Run this command to fetch wheels of the dependencies using the 
   [`manylinux` project](https://github.com/pypa/manylinux)
   ```
   mkdir -p package/python
   pip install \
     --platform manylinux2014_x86_64 \
     --target=package/python \
     --implementation cp \
     --python-version 3.14 \
     --only-binary=:all: --upgrade \
     botocore boto3 agithub PyYAML python-dateutil email_reply_parser beautifulsoup4
   ```
2. Zip up the results
   ```
   cd package
   zip -r ../artifacts/birch-girder.zip .
   ```

This process is outlined in [this AWS documentation page](https://aws.amazon.com/premiumsupport/knowledge-center/lambda-layer-simulated-docker/).

### Method 2 : Use Amazon Linux EC2 Instance

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

## Use `deploy-birch-girder`

Use the built in tool `deploy-birch-girder` to deploy Birch Girder

```
usage: deploy-birch-girder [-h] [--config CONFIG] [--lambda-function-name LAMBDA_FUNCTION_NAME] [--lambda-iam-role-name LAMBDA_IAM_ROLE_NAME]
                           [--ses-rule-set-name SES_RULE_SET_NAME] [--ses-rule-name SES_RULE_NAME] [--github-iam-username GITHUB_IAM_USERNAME]
                           [--lambda-archive-filename FILENAME.ZIP] [--github-action-filename FILENAME.yml] [--plugins-path PLUGINS_PATH]

Deploy Birch Girder. This tool will build a config.yaml file, configure GitHub and AWS and deploy Birch Girder into your AWS account.

optional arguments:
  -h, --help            show this help message and exit
  --config CONFIG       Location of config.yaml (default : birch_girder/config.yaml)
  --lambda-function-name LAMBDA_FUNCTION_NAME
                        Name of the AWS Lambda function (default: birch-girder)
  --lambda-iam-role-name LAMBDA_IAM_ROLE_NAME
                        Name of the IAM role to be used by Lambda (default: birch-girder)
  --ses-rule-set-name SES_RULE_SET_NAME
                        Name of the SES ruleset (default: default-rule-set)
  --ses-rule-name SES_RULE_NAME
                        Name of the SES rule to create (default: birch-girder-rule)
  --github-iam-username GITHUB_IAM_USERNAME
                        Name of the IAM user to be used by GitHub (default: github-sns-publisher)
  --lambda-archive-filename FILENAME.ZIP
                        Path to the newly generated lambda zip file (default: temporary file)
  --github-action-filename FILENAME.yml
                        Filename to use for the GitHub Actions workflow (default: emit-comment-to-sns-github-action.yml)
  --plugins-path PLUGINS_PATH
                        Path to the plugins directory (default: plugins)

```