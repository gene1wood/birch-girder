#!/usr/bin/python
# -*- coding: utf-8 -*-

import os.path
import time
import json
import collections
from getpass import getpass
import argparse
import tempfile
import zipfile

import yaml
import boto3
import botocore.exceptions
import github3  # https://github3py.readthedocs.io/en/master/

try:
    prompt = raw_input  # Python 2
except NameError:
    prompt = input  # Python 3


class Config(collections.MutableMapping):
    def __init__(self, filename, *args, **kwargs):
        self.filename = filename
        self.store = dict()
        self.load()
        self.update(dict(*args, **kwargs))

    def __setitem__(self, key, value):
        self.store[key] = value
        self.save()

    def __delitem__(self, key):
        del self.store[key]
        self.save()

    def __getitem__(self, key):
        return self.store[key]

    def __iter__(self):
        return iter(self.store)

    def __len__(self):
        return len(self.store)

    def save(self):
        with open(self.filename, 'w') as f:
            f.write(yaml.dump(dict(self), default_flow_style=False))

    def load(self):
        try:
            with open(self.filename) as f:
                self.update(**yaml.load(f.read()))
        except:
            pass


def plugin_path_type(path):
    if not os.path.isdir(path):
        raise argparse.ArgumentTypeError("%s isn't a directory" % path)
    return path


def get_two_factor_code():
    code = ''
    while not code:
        code = prompt('Enter 2FA code: ')
    return code


def main():
    parser = argparse.ArgumentParser(
        description='''Deploy Birch Girder. This tool will build a config.yaml
        file, configure GitHub and AWS and deploy Birch Girder into your AWS
        account.''')
    parser.add_argument(
        '--config', default='birch_girder/config.yaml',
        help='Location of config.yaml (defualt : birch_girder/config.yaml)')
    parser.add_argument(
        '--lambda-function-name', default='birch-girder',
        help='Name of the AWS Lambda function (default: birch-girder)')
    parser.add_argument(
        '--lambda-iam-role-name', default='birch-girder',
        help='Name of the IAM role to be used by Lambda '
             '(default: birch-girder)')
    parser.add_argument(
        '--ses-rule-set-name', default='birch-girder-ruleset',
        help='Name of the SES ruleset (default: birch-girder-ruleset)')
    parser.add_argument(
        '--ses-rule-name', default='birch-girder-rule',
        help='Name of the SES rule to create (default: birch-girder-rule)')
    parser.add_argument(
        '--github-iam-username', default='github-sns-publisher',
        help='Name of the IAM user to be used by GitHub '
             '(default: github-sns-publisher)')
    parser.add_argument(
        '--lambda-archive-filename', metavar='FILENAME.ZIP',
        help='Path to the newly generated lambda zip file (default: temporary '
             'file)')
    parser.add_argument(
        '--plugins-path', default='plugins', type=plugin_path_type,
        help='Path to the plugins directory (default: plugins/)')
    parser.add_argument(
        '--clean', action='store_true',
        help='Clean up all created Birch Girder resources by deleting and '
             'removing them. This feature is not yet implemented')

    args = parser.parse_args()
    config = Config(args.config)

    # Validate AWS access
    try:
        client = boto3.client('lambda')
        client.list_functions()
    except Exception as e:
        print('''
    Ensure that you have access to an AWS account and permission
    to setup AWS SES, Lambda, SNS, S3 and IAM.
    Error "%s"''' % repr(e))
        exit(1)
    valid_regions = ['us-east-1', 'us-west-2', 'eu-west-1']
    region = client.meta.region_name
    if region not in valid_regions:
        # http://docs.aws.amazon.com/ses/latest/DeveloperGuide/regions.html#region-endpoints
        print('Please set your AWS region to one of %s' % valid_regions)
        exit(1)

    if args.clean:
        pass

        # Not yet implemented

        # SNS Alert Topic

        # SES Rule

        # SES Ruleset if empty

        # S3 bucket : leave it

        # S3 bucket policy statement GiveSESPermissionToWriteEmail

        # S3 bucket lifecycle id DeleteSESEmailPayloadsAfter7Days

        # S3 contents ses-payloads/

        # For recipients
            # SES Verified domain
            # Verification DNS record
            # SPF record
            # DKIM record
            # GitHub repo : leave it
            # GitHub webhook

        # Revoke GitHub token

        # IAM GitHub user with inline policies and associated access keys

        # SNS subscription of topic to lambda function

        # Lambda function with policy

        # IAM Lambda role with inline policies

        # SNS Topic


    # Check for first/early run
    client = boto3.client('lambda')
    response = client.list_functions()
    early_run = False
    if args.lambda_function_name not in [x['FunctionName'] for x
                                         in response['Functions']]:
        # Since the Lambda function doesn't exist yet, we'll treat this like
        # a first run or early run experience
        early_run = True
    if 'recipient_list' not in config:
        config['recipient_list'] = {}

    if len(config['recipient_list']) == 0 and early_run:
        print('''
No recipient_list in config. Continuing with setup but not
setting up any recipients. Later, configure recipients in the config and run
deploy again.''')

    if 'provider_name' not in config:
        print('''
Provider Name
Your provider name is the name of your organization to be displayed in the
suffix of emails sent.
Example : Example Corporation''')
        provider_name = prompt('Enter the provider name : ')
        if not provider_name:
            return
        config['provider_name'] = provider_name

    if 'ses_payload_s3_bucket_name' not in config:
        print('''
AWS S3 Bucket Name
This will be the name of the AWS S3 bucket that stores, temporarily, the
inbound email body. AWS S3 bucket names must be unique across all AWS accounts
in the world, so you'll have to pick a bucket name.
Example : birch-girder-example-corporation''')
        bucket_name = prompt('Enter the AWS S3 bucket name: ')
        if not bucket_name:
            return
        config['ses_payload_s3_bucket_name'] = bucket_name

    if 'github_username' not in config:
        print('''
GitHub Username
What GitHub user would you like Birch Girder to act as. This user needs access
to all repos which you'd like Birch Girder to manage.''')
        github_username = prompt('Enter the GitHub username : ')
        if not github_username:
            return
        config['github_username'] = github_username

    defaults = {
        'ses_payload_s3_prefix': 'ses-payloads/',
        'sns_topic': 'GithubWebhookTopic',
        'sns_region': region
    }
    for default in defaults:
        if default not in config:
            print('Setting %s to default of %s' % (default, defaults[default]))
            config[default] = defaults[default]

    # SES validation checks
    client = boto3.client('ses')
    # http://docs.aws.amazon.com/ses/latest/DeveloperGuide/request-production-access.html
    response = client.get_send_quota()
    if response['Max24HourSend'] <= 200:
        print('''
Your AWS SES account is in sandbox mode (as indicated by the 
fact that the accounts maximum allowed sent email in 24 hours 
is %s). As a result Birch Girder can't send email. Please open
an SES Sending Limits Increase case in Support Center and once
completed, run this again.
http://docs.aws.amazon.com/ses/latest/DeveloperGuide/request-production-access.html

If you'd like to continue setting up Birch Girder because you're
waiting on AWS support getting your account out of SES sandbox,
type continue below, otherwise hit enter'''
              % response['Max24HourSend'])
        ses_bypass = prompt('Continue? [continue]: ')
        if ses_bypass.lower() not in ['continue', 'y', 'yes', 'c']:
            return

    try:
        response = client.describe_active_receipt_rule_set()
        if response['Metadata']['Name'] != args.ses_rule_set_name:
            print('''
The SES Rule Set Name is set to {new}. Currently a different SES Rule Set is
active called {existing}. By continuing, whatever rules are defined in
{existing} will stop affecting inbound email and only the new Birch Girder
rules will affect inbound email. Would you like to continue and make this
change or stop and change the Rule Set Name that Birch Girder will use from
{new} to {existing} so that both the existing rules and the new
Birch Girder rules will affect inbound email?'''.format(
                new=args.ses_rule_set_name,
                existing=response['Metadata']['Name']))
            response = prompt('[continue/stop]: ')
            if response.lower() not in ['continue', 'c']:
                return
    except:
        pass

    # GitHub Token
    if 'github_token' not in config:
        print('''
GitHub user password\nWe'll use this password to generate a GitHub
authorization token that Birch Girder will use to interact with GitHub''')
        password = getpass('Enter the GitHub password for %s: '
                           % config['github_username'])
        if not password:
            return

        note = 'birch-girder'
        note_url = 'http://github.com/gene1wood/birch-girder'
        scopes = ['repo']

        auth = github3.authorize(
            config['github_username'], password, scopes, note, note_url,
            two_factor_callback=get_two_factor_code)
        config['github_token'] = auth.token
        print("GitHub OAuth Token (github_token) created : %s" % auth.token)

    gh = github3.login(token=config['github_token'])
    user = gh.user()

    # SNS Topic
    client = boto3.client('sns')
    response = client.create_topic(  # This action is idempotent
        Name=config['sns_topic']
    )
    config['sns_topic_arn'] = response['TopicArn']

    # Alert SNS Topic
    if 'alert_sns_topic' in config:
        response = client.create_topic(  # This action is idempotent
            Name=config['alert_sns_topic']
        )
        config['alert_sns_topic_arn'] = response['TopicArn']
    elif early_run:
        print('''No alert_sns_topic in config so no alert topic will be setup.
You can add an alert topic to config later and re-run deploy if you would like
an SNS topic created that internal Birch Girder errors will be sent to.''')

    # S3 Bucket
    client = boto3.client('s3')
    try:
        client.head_bucket(Bucket=config['ses_payload_s3_bucket_name'])
    except botocore.exceptions.ClientError:
        response = client.create_bucket(
            Bucket=config['ses_payload_s3_bucket_name'],
            CreateBucketConfiguration={
                'LocationConstraint': config['sns_region']
            }
        )
        print('Bucket %s created' % response['Location'])

    statement_id = 'GiveSESPermissionToWriteEmail'
    try:
        response = client.get_bucket_policy(
            Bucket=config['ses_payload_s3_bucket_name']
        )
        policy = json.loads(response['Policy'])
    except:
        policy = None
    if (policy is None
            or statement_id not in [x['Sid'] for x in policy['Statement']]):
        client.put_bucket_policy(
            Bucket=config['ses_payload_s3_bucket_name'],
            Policy='''{
        "Version": "2008-10-17",
        "Statement": [
            {
                "Sid": "%s",
                "Effect": "Allow",
                "Principal": {
                    "Service": "ses.amazonaws.com"
                },
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::%s/*",
                "Condition": {
                    "StringEquals": {
                        "aws:Referer": "%s"
                    }
                }
            }
        ]
    }''' % (statement_id, config['ses_payload_s3_bucket_name'],
                config['sns_topic_arn'].split(':')[4])
        )
        print('Bucket policy for %s created'
              % config['ses_payload_s3_bucket_name'])

    lifecycle_id = 'DeleteSESEmailPayloadsAfter7Days'
    try:
        response = client.get_bucket_lifecycle_configuration(
            Bucket=config['ses_payload_s3_bucket_name'],
        )
        rules = response['Rules']
    except:
        rules = None
    if rules is None or lifecycle_id not in [x['ID'] for x in rules]:
        client.put_bucket_lifecycle_configuration(
            Bucket=config['ses_payload_s3_bucket_name'],
            LifecycleConfiguration={
                'Rules': [
                    {
                        'Expiration': {
                            'Days': 7,
                        },
                        'ID': lifecycle_id,
                        'Filter': {
                            'Prefix': config['ses_payload_s3_prefix']
                        },
                        'Status': 'Enabled',
                        'NoncurrentVersionExpiration': {
                            'NoncurrentDays': 7
                        },
                        'AbortIncompleteMultipartUpload': {
                            'DaysAfterInitiation': 7
                        }
                    }
                ]
            }
        )
        print('Bucket lifecycle configuration for %s applied to bucket'
              % config['ses_payload_s3_bucket_name'])

    # SES
    client = boto3.client('ses')
    response = client.get_account_sending_enabled()
    if not response['Enabled']:
        print('Email sending is disabled.')
        client.update_account_sending_enabled(
            Enabled=True
        )
        print('Email sending has been enabled.')

    response_iterator = client.get_paginator('list_identities').paginate()
    identities = [item for sublist in
                  [x['Identities'] for x in response_iterator]
                  for item in sublist]
    verifications_initiated = False
    identities_that_matter = []
    for recipient in [x.lower() for x in config['recipient_list'].keys()]:
        domain = recipient.split('@')[1]
        if recipient not in identities and domain not in identities:
            print(
                "Recipient %s verification hasn't been initiated in AWS SES"
                % recipient)
            response = prompt(
                'Would you like to verify the email address %s or the '
                'domain %s [email/domain]: '
                % (recipient, recipient.split('@')[1]))
            if response.lower() in ['email', recipient]:
                client.verify_email_identity(
                    EmailAddress=recipient
                )
                print('Initiating verification of %s' % recipient)
                verifications_initiated = True
                break
            elif response.lower() in ['domain', domain]:
                response = prompt(
                    'Would you like to host the zone %s in route53 (for '
                    '$0.50/month) or on your own [route53/myself]: ' % domain)
                if response.lower() in ['route53', 'r']:
                    print('Route53 support in Birch Girder is not yet '
                          'available.')
                elif response.lower() in ['myself', 'm']:
                    zone = '.'.join(domain.split('.')[-2:])
                    record = ('.'.join(domain.split('.')[:-2])
                              if zone != domain else '@')
                    suffix = ('.' + record) if zone != domain else ''
                    token_txt_record = '_amazonses' + suffix
                    # http://docs.aws.amazon.com/ses/latest/DeveloperGuide/regions.html#region-endpoints
                    response = client.verify_domain_identity(Domain=domain)
                    token = response['VerificationToken']
                    response = client.verify_domain_dkim(Domain=domain)
                    dkim_cname_records = '\n'.join([
                        '{key}._domainkey{suffix}    IN    CNAME    {key}.dkim.amazonses.com.'.format(
                            key=x, suffix=suffix)
                        for x in response['DkimTokens']])
                    print('Verification of %s initiated' % domain)
                    # TODO : Add DMARC?
                    # http://docs.aws.amazon.com/ses/latest/DeveloperGuide/dmarc.html
                    print('''
To verify this domain create a DNS record in the {domain} domain with the 
name "_amazonses.{domain}" and the value "{token}"

The record in the {zone} zone would look like this:

{token_txt_record}    IN    TXT    "{token}"

Create an DNS SPF record so email that Amazon sends from the email address
{recipient} is considered to not be spam.
The record in the {zone} zone would look like this:

{record}    IN    TXT    "v=spf1 include:amazonses.com -all"

Create DNS DKIM CNAME records so that Amazon can sign email sent from
{recipient} to further ensure it isn't considered spam.
The records in the {zone} zone would look like this:

{dkim_cname_records}

Create a DNS MX record so inbound email destined for {domain} is
delivered to AWS SES. The MX record in the {zone} zone would look like this:

{record}    IN    MX    10    inbound-smtp.{region}.amazonaws.com.

'''.format(
                        domain=domain,
                        token=token,
                        zone=zone,
                        token_txt_record=token_txt_record,
                        record=record,
                        dkim_cname_records=dkim_cname_records,
                        recipient=recipient,
                        region=region))
                    verifications_initiated = True
                else:
                    return

            else:
                return
        else:
            identities_that_matter.append(
                domain if domain in identities else recipient)
    if verifications_initiated:
        print("Aborting while you complete email/domain verifications. Run "
              "this again when they're complete")
        return
    response = client.get_identity_verification_attributes(
        Identities=identities_that_matter
    )

    all_verifications_completed = True
    for identity in response['VerificationAttributes']:
        status = response['VerificationAttributes'][identity][
            'VerificationStatus']
        if status == 'Pending':
            print("Verification for %s is still pending. Run this again when "
                  "it's complete" % identity)
            all_verifications_completed = False
        elif status == 'Failed':
            print("Verification for %s failed." % identity)
            client.delete_identity(
                Identity=identity
            )
            print("Verification %s has been deleted. "
                  "Run this again to initiate a new verification." % identity)
            all_verifications_completed = False
        elif status == 'TemporaryFailure':
            print("Verification for %s has temporarily failed. Wait and run"
                  "this again." % identity)
            all_verifications_completed = False
    if not all_verifications_completed:
        return

    # Lambda IAM Role
    policies = {
        'LambdaBasicExecution': '''{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:*"
    }
  ]
}''',
        'S3Reader': '''{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:Get*",
        "s3:List*"
      ],
      "Resource": "arn:aws:s3:::%(bucket_name)s/%(prefix)s*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket"
      ],
      "Resource": "arn:aws:s3:::%(bucket_name)s"
    }
  ]
}''' % {'bucket_name': config['ses_payload_s3_bucket_name'],
            'prefix': config['ses_payload_s3_prefix']},
        'S3Writer': '''{
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Action": [
            "s3:PutObject*"
          ],
          "Resource": "arn:aws:s3:::%(bucket_name)s/%(prefix)semail-events/*"
        }
      ]
    }''' % {'bucket_name': config['ses_payload_s3_bucket_name'],
            'prefix': config['ses_payload_s3_prefix']},
        'SESSender': '''{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ses:Send*"
      ],
      "Resource": "*"
    }
  ]
}'''}

    if 'alert_sns_topic_arn' in config:
        policies['SNSPublisher'] = '''{
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Action": [
            "sns:Publish"
          ],
          "Resource": "%s"
        }
      ]
    }''' % config['alert_sns_topic_arn']

    assume_role_policy_document = '''{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}'''
    client = boto3.client('iam')
    response_iterator = client.get_paginator('list_roles').paginate()
    iam_roles = [item for sublist in
                 [x['Roles'] for x in response_iterator]
                 for item in sublist]
    if args.lambda_iam_role_name in [x['RoleName'] for x in iam_roles]:
        lambda_iam_role_arn = next(
            x['Arn'] for x in iam_roles
            if x['RoleName'] == args.lambda_iam_role_name)
    else:
        print("Creating role %s" % args.lambda_iam_role_name)
        response = client.create_role(
            RoleName=args.lambda_iam_role_name,
            AssumeRolePolicyDocument=assume_role_policy_document
        )
        # TODO : Wait for Role to exist https://github.com/boto/boto3/issues/1381
        lambda_iam_role_arn = response['Role']['Arn']

    response_iterator = client.get_paginator('list_role_policies').paginate(
        RoleName=args.lambda_iam_role_name
    )
    role_policies = [item for sublist in
                     [x['PolicyNames'] for x in response_iterator]
                     for item in sublist]
    for policy_name in policies:
        if policy_name not in role_policies:
            print("Attaching policy %s" % policy_name)
            client.put_role_policy(
                RoleName=args.lambda_iam_role_name,
                PolicyName=policy_name,
                PolicyDocument=policies[policy_name]
            )

    # Lambda function
    zip_file_name = 'artifacts/birch-girder.zip'
    if args.lambda_archive_filename is not None:
        if (os.path.exists(args.lambda_archive_filename)
                and args.lambda_archive_filename.endswith('.zip')):
            print("Deleting existing archive %s"
                  % args.lambda_archive_filename)
            os.remove(args.lambda_archive_filename)
        with open(args.lambda_archive_filename, 'w') as f:
            pass
        os.chmod(args.lambda_archive_filename, 0600)

    with (open(args.lambda_archive_filename, 'r+')
          if args.lambda_archive_filename is not None
          else tempfile.TemporaryFile(suffix='.zip')) as origin_file:
        with open(zip_file_name) as f:
            origin_file.write(f.read())

        zip_file = zipfile.ZipFile(origin_file, 'a')

        config_file = zipfile.ZipInfo('config.yaml', time.localtime()[:6])
        config_file.compress_type = zipfile.ZIP_DEFLATED
        config_file.external_attr = 0644 << 16L
        zip_file.writestr(config_file, open(args.config).read())

        init_filename = 'birch_girder/__init__.py'
        zip_file.write(
            init_filename,
            '__init__.py',
            zipfile.ZIP_DEFLATED)

        for filename in os.listdir(args.plugins_path):
            if filename == '__init__.py':
                continue
            arcname = os.path.join('plugins', filename)
            full_path = os.path.join(args.plugins_path, filename)
            zip_file.write(
                full_path,
                arcname,
                zipfile.ZIP_DEFLATED)

        zip_file.close()
        origin_file.seek(0)
        client = boto3.client('lambda')
        # TODO : Support pagination https://github.com/boto/boto3/issues/1357
        response = client.list_functions()
        if args.lambda_function_name in [x['FunctionName'] for x
                                         in response['Functions']]:
            response = client.update_function_code(
                FunctionName=args.lambda_function_name,
                ZipFile=origin_file.read()
            )
            lambda_function_arn = response['FunctionArn']
            print('Lambda function updated : %s'
                  % lambda_function_arn)
        else:
            response = client.create_function(
                FunctionName=args.lambda_function_name,
                Runtime='python2.7',
                Role=lambda_iam_role_arn,
                Handler='__init__.lambda_handler',
                Code={'ZipFile': origin_file.read()},
                Description='Birch Girder',
                Timeout=30
            )
            # TODO : Wait for function to exist https://github.com/boto/boto3/issues/1382
            lambda_function_arn = response['FunctionArn']
            print('Lambda function created : %s'
                  % lambda_function_arn)

    # SES permission to invoke Lambda function
    statement_id = 'GiveSESPermissionToInvokeFunction'
    try:
        response = client.get_policy(FunctionName=args.lambda_function_name)
        policy = response['Policy']
    except:
        policy = None
    if (policy is None
            or statement_id not in [x['Sid'] for x
                                    in json.loads(policy)['Statement']]):
        response = client.add_permission(
            FunctionName=args.lambda_function_name,
            StatementId=statement_id,
            Action='lambda:InvokeFunction',
            Principal='ses.amazonaws.com',
            SourceAccount=lambda_function_arn.split(':')[4]
        )
        print('Permission %s added' % statement_id)

    # SNS permission to invoke Lambda function
    statement_id = 'GiveGithubWebhookSNSTopicPermissionToInvokeFunction'
    if (policy is None
            or statement_id not in [x['Sid'] for x
                                    in json.loads(policy)['Statement']]):
        response = client.add_permission(
            FunctionName=args.lambda_function_name,
            StatementId=statement_id,
            Action='lambda:InvokeFunction',
            Principal='sns.amazonaws.com',
            SourceArn=config['sns_topic_arn']
        )
        print('Permission %s added' % statement_id)

    # SES receipt rule
    client = boto3.client('ses')
    rule_set_created = False
    while True:
        try:
            response = client.describe_receipt_rule_set(
                RuleSetName=args.ses_rule_set_name)
            break
        except:
            if not rule_set_created:
                client.create_receipt_rule_set(
                    RuleSetName=args.ses_rule_set_name
                )
                print('SES Rule Set %s created' % args.ses_rule_set_name)
                rule_set_created = True
            else:
                time.sleep(2)

    if args.ses_rule_name not in [x['Name'] for x in response['Rules']]:
        client.create_receipt_rule(
            RuleSetName=args.ses_rule_set_name,
            Rule={
                'Name': args.ses_rule_name,
                'Enabled': True,
                'Recipients': config['recipient_list'].keys(),
                'Actions': [
                    {
                        'S3Action': {
                            'BucketName': config['ses_payload_s3_bucket_name'],
                            'ObjectKeyPrefix': config['ses_payload_s3_prefix']
                        }
                    },
                    {
                        'LambdaAction': {
                            'FunctionArn': lambda_function_arn,
                            'InvocationType': 'Event'
                        }
                    }
                ],
                'ScanEnabled': True
            }
        )
        print('SES Rule %s created in Rule Set' % args.ses_rule_name)
    response = client.describe_active_receipt_rule_set()
    if response['Metadata']['Name'] != args.ses_rule_set_name:
        client.set_active_receipt_rule_set(
            RuleSetName=args.ses_rule_set_name
        )
        print('SES Rule Set %s set as active' % args.ses_rule_set_name)

    # GitHub IAM user
    policy_document = '''{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "sns:Publish"
            ],
            "Sid": "PublishToGitHubWebhookTopic",
            "Resource": [
                "%s"
            ],
            "Effect": "Allow"
        }
    ]
}''' % config['sns_topic_arn']
    client = boto3.client('iam')
    response_iterator = client.get_paginator('list_users').paginate()
    iam_users = [item for sublist in [x['Users'] for x in response_iterator]
                 for item in sublist]
    if args.github_iam_username not in [x['UserName'] for x in iam_users]:
        response = client.create_user(
            UserName=args.github_iam_username
        )
        print('IAM user %s created' % response['User']['UserName'])

    policy_name = 'PublishToGithubWebhookSNSTopic'
    response_iterator = client.get_paginator('list_user_policies').paginate(
        UserName=args.github_iam_username
    )
    user_policies = [item for sublist in
                     [x['PolicyNames'] for x in response_iterator]
                     for item in sublist]
    if policy_name not in user_policies:
        client.put_user_policy(
            UserName=args.github_iam_username,
            PolicyName=policy_name,
            PolicyDocument=policy_document
        )
        print('IAM policy %s applied to user %s'
              % (policy_name, args.github_iam_username))

    # GitHub webhooks
    new_event = u'issue_comment'
    for recipient in config['recipient_list']:
        if ('owner' not in config['recipient_list'][recipient]
                or 'repo' not in config['recipient_list'][recipient]):
            print('Recipient %s missing owner or repo. Skipping' % recipient)
            continue
        repo = gh.repository(config['recipient_list'][recipient]['owner'],
                             config['recipient_list'][recipient]['repo'])
        if repo is None:
            if config['recipient_list'][recipient]['owner'] != user.login:
                org = gh.organization(
                    config['recipient_list'][recipient]['owner'])
                if org is None:
                    print('''
Recipient {recipient} has repo owner of {owner} but the github_token user we're
using is {login} and the repo doesn't yet exist. {owner} is not a GitHub
organization so we can't create the repo. Skipping'''.format(
                        recipient=recipient,
                        owner=config['recipient_list'][recipient]['owner'],
                        login=user.login))
                    continue
                else:
                    repo = org.create_repo(
                        name=config['recipient_list'][recipient]['repo'],
                        private=True,
                        auto_init=True
                    )
            else:
                repo = gh.create_repo(
                    name=config['recipient_list'][recipient]['repo'],
                    private=True,
                    auto_init=True
                )
            print("Created GitHub repo %s" % repo.html_url)

        # IAM user access key
        hooks = [x for x in repo.iter_hooks()]
        if 'amazonsns' not in [x.name for x in hooks]:
            response = client.create_access_key(
                UserName=args.github_iam_username
            )
            print('Created new Access Key for IAM user %s : %s'
                  % (args.github_iam_username,
                     response['AccessKey']['AccessKeyId']))
            hook = repo.create_hook(
                'amazonsns',
                {'aws_key': response['AccessKey']['AccessKeyId'],
                 'aws_secret': response['AccessKey']['SecretAccessKey'],
                 'sns_region': config['sns_topic_arn'].split(':')[3],
                 'sns_topic': config['sns_topic_arn']})
            print('New %s webhook installed in %s with user access key %s'
                  % (hook.name, repo.html_url,
                     response['AccessKey']['AccessKeyId']))

        for hook in repo.iter_hooks():
            if hook.name == u'amazonsns':
                if new_event not in hook.events:
                    events = hook.events
                    events.append(new_event)
                    hook.edit(events=events)
                    print('GitHub webook "amazonsns" on repo %s configured to '
                          'trigger on %s' % (repo.html_url, events))

    # Subscribe Lambda function to SNS
    client = boto3.client('sns')
    response_iterator = client.get_paginator('list_subscriptions').paginate()
    subscriptions = [item for sublist in
                     [x['Subscriptions'] for x in response_iterator]
                     for item in sublist]
    if lambda_function_arn not in [x['Endpoint'] for x in subscriptions
                                   if x['TopicArn'] == config['sns_topic_arn']
                                   and x['Protocol'] == 'lambda']:
        response = client.subscribe(
            TopicArn=config['sns_topic_arn'],
            Protocol='lambda',
            Endpoint=lambda_function_arn
        )
        print('Birch Girder subscribed to GitHub Webhook SNS Topic  : %s'
              % response['SubscriptionArn'])


if __name__ == '__main__':
    main()