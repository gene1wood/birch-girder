#!/usr/bin/python
# -*- coding: utf-8 -*-

import argparse
import base64
import collections.abc
import hashlib
import io
import json
import os.path
import time
import zipfile
from base64 import b64encode
from getpass import getpass

import boto3
import yaml  # pip install PyYAML
from agithub.GitHub import GitHub  # pip install agithub
from nacl import encoding, public

END_COLOR = '\033[0m'
GREEN_COLOR = '\033[92m'
BLUE_COLOR = '\033[94m'
AWS_LAMBDA_PERSISTENCE_LAYER_ARN = 'arn:aws:lambda:us-west-2:220481034027:layer:aws-lambda-persistence:2'


class Config(collections.abc.MutableMapping):
    def __init__(self, filename, *args, **kwargs):
        self.filename = filename
        self.save_on_set = False
        self.store = dict()
        self.load()
        self.update(dict(*args, **kwargs))
        self.save_on_set = True

    def __setitem__(self, key, value):
        if (key not in self.store) or (yaml.dump(value) != yaml.dump(self.store[key])):
            self.store[key] = value
            if self.save_on_set:
                self.save()

    def __delitem__(self, key):
        if key in self.store:
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
                self.update(**yaml.load(f.read(), Loader=yaml.SafeLoader))
        except:
            pass


def prompt(message):
    return input(f'{BLUE_COLOR}{message}{END_COLOR} : ')


def plugin_path_type(path):
    if not os.path.isdir(path):
        raise argparse.ArgumentTypeError(f"{path} isn't a directory")
    return path


def get_two_factor_code():
    code = ''
    while not code:
        code = prompt('Enter 2FA code')
    return code


def green_print(data):
    print(f'{GREEN_COLOR}{data}{END_COLOR}')


def color_getpass(prompt):
    return getpass(f'{BLUE_COLOR}{prompt}{END_COLOR} : ')


def get_paginated_results(product, action, key, credentials=None, args=None):
    args = {} if args is None else args
    credentials = {} if credentials is None else credentials
    return [y for sublist in [x[key] for x in boto3.client(product, **credentials).get_paginator(action).paginate(**args)] for y in sublist]


def encrypt_github_actions_secret(public_key, secret_value):
    """Encrypt a Unicode string using the public key."""
    public_key = public.PublicKey(public_key.encode("utf-8"), encoding.Base64Encoder())
    sealed_box = public.SealedBox(public_key)
    encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
    encoded = b64encode(encrypted).decode("utf-8")
    return encoded


def main():
    parser = argparse.ArgumentParser(
        description='''Deploy Birch Girder. This tool will build a config.yaml
        file, configure GitHub and AWS and deploy Birch Girder into your AWS
        account.''')
    parser.add_argument(
        '--config', default='birch_girder/config.yaml',
        help='Location of config.yaml (default : %(default)s)')
    parser.add_argument(
        '--lambda-function-name', default='birch-girder',
        help='Name of the AWS Lambda function (default: %(default)s)')
    parser.add_argument(
        '--lambda-iam-role-name', default='birch-girder',
        help='Name of the IAM role to be used by Lambda '
             '(default: %(default)s)')
    parser.add_argument(
        '--ses-rule-set-name', default='default-rule-set',
        help='Name of the SES ruleset (default: %(default)s)')
    parser.add_argument(
        '--ses-rule-name', default='birch-girder-rule',
        help='Name of the SES rule to create (default: %(default)s)')
    parser.add_argument(
        '--github-iam-username', default='github-sns-publisher',
        help='Name of the IAM user to be used by GitHub '
             '(default: %(default)s)')
    parser.add_argument(
        '--lambda-archive-filename', metavar='FILENAME.ZIP',
        help='Path to the newly generated lambda zip file (default: temporary '
             'file)')
    parser.add_argument(
        '--github-action-filename',
        default='emit-comment-to-sns-github-action.yml', metavar='FILENAME.yml',
        help='Filename to use for the GitHub Actions workflow (default: '
             '%(default)s)')
    parser.add_argument(
        '--plugins-path', default='plugins', type=plugin_path_type,
        help='Path to the plugins directory (default: %(default)s)')

    args = parser.parse_args()
    config = Config(args.config)

    # Validate AWS access
    try:
        client = boto3.client('lambda')
        client.list_functions()
    except Exception as e:
        raise Exception(f'''
Ensure that you have access to an AWS account and permission
to setup AWS SES, Lambda, SNS, S3 and IAM.
Error "{repr(e)}"''')
    valid_regions = ['us-east-1', 'us-west-2', 'eu-west-1']
    region = client.meta.region_name
    if region not in valid_regions:
        # http://docs.aws.amazon.com/ses/latest/DeveloperGuide/regions.html#region-endpoints
        print(f'Please set your AWS region to one of {valid_regions}')
        exit(1)
    account_id = boto3.client('sts').get_caller_identity()['Account']

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
        provider_name = prompt('Enter the provider name')
        if not provider_name:
            return
        config['provider_name'] = provider_name

    if 'ses_payload_s3_bucket_name' not in config:
        config['ses_payload_s3_bucket_name'] = f'birch-girder-{account_id}'
        print(f'''
AWS S3 Bucket Name
Setting the bucket name to {config['ses_payload_s3_bucket_name']}''')

    if 'github_username' not in config:
        print('''
GitHub Username
What GitHub user would you like Birch Girder to act as. This user needs access
to all repos which you'd like Birch Girder to manage.''')
        github_username = prompt('Enter the GitHub username')
        if not github_username:
            return
        config['github_username'] = github_username

    defaults = {
        'ses_payload_s3_prefix': 'ses-payloads/',
        'sns_topic': 'GithubWebhookTopic',
        'ses_notification_sns_topic': 'BirchGirderSESNotificationTopic',
        'sns_region': region
    }
    for default in defaults:
        if default not in config:
            print(f'Setting {default} to default of {defaults[default]}')
            config[default] = defaults[default]

    # SES validation checks
    client = boto3.client('ses')
    # http://docs.aws.amazon.com/ses/latest/DeveloperGuide/request-production-access.html
    response = client.get_send_quota()
    if response['Max24HourSend'] <= 200:
        print(f'''
Your AWS SES account is in sandbox mode (as indicated by the 
fact that the accounts maximum allowed sent email in 24 hours 
is {response['Max24HourSend']}). As a result Birch Girder can't send email. Please open
an SES Sending Limits Increase case in Support Center and once
completed, run this again.
http://docs.aws.amazon.com/ses/latest/DeveloperGuide/request-production-access.html

If you'd like to continue setting up Birch Girder because you're
waiting on AWS support getting your account out of SES sandbox,
type continue below, otherwise hit enter''')
        ses_bypass = prompt('Continue? [continue]')
        if ses_bypass.lower() not in ['continue', 'y', 'yes', 'c']:
            return

    try:
        response = client.describe_active_receipt_rule_set()
        if response['Metadata']['Name'] != args.ses_rule_set_name:
            print(f'''
The SES Rule Set Name is set to {args.ses_rule_set_name}.
Currently a different SES Rule Set is active called {response['Metadata']['Name']}.
By continuing, whatever rules are defined in {response['Metadata']['Name']}
will stop affecting inbound email and only the new Birch Girder rules will
affect inbound email. Would you like to continue and make this change or stop
and change the Rule Set Name that Birch Girder will use from
{args.ses_rule_set_name} to {response['Metadata']['Name']}
so that both the existing rules and the new Birch Girder rules will affect
inbound email?''')
            response = prompt('[continue/stop]')
            if response.lower() not in ['continue', 'c']:
                return
    except:
        pass

    # GitHub Token
    if 'github_token' not in config:
        print('''
GitHub user password
We'll use this password to generate a GitHub authorization token that Birch
Girder will use to interact with GitHub''')
        password = color_getpass(
            f"Enter the GitHub password for {config['github_username']}")
        if not password:
            return

        note = 'birch-girder'
        note_url = 'http://github.com/gene1wood/birch-girder'
        scopes = [
            'repo',
            'workflow'  # This is required for modification of the GitHub Actions file emit-comment-to-sns-github-action.yml
        ]

        # Note this method of obtaining a token is now stopped working in 2020
        # https://developer.github.com/changes/2020-02-14-deprecating-oauth-auth-endpoint/
        # TODO : Replace this with a non deprecated method

        # We can't move from classic to fine grained PATs yet because it's not implemented : https://github.com/github/roadmap/issues/601
        # When it's time for fine grained PATS the scopes will need to include
        # None
        # * gh.search.issues.get
        #
        # "Contents" repository permissions (write)
        # * gh.repos[self.github_owner][self.github_repo].contents[path].put
        # * gh.repos[self.github_owner][self.github_repo].contents[path].get
        # * gh.markdown.post
        #
        # "Issues" repository permissions (write)
        # * gh.repos[parsed_email.github_owner][parsed_email.github_repo].issues[issue_data['number']].reactions.post
        # * gh.repos[parsed_email.github_owner][parsed_email.github_repo].issues.post
        # * gh.repos[parsed_email.github_owner][parsed_email.github_repo].issues[parsed_email.issue_number].get
        # * gh.repos[parsed_email.github_owner][parsed_email.github_repo].issues[parsed_email.issue_number].patch
        # * gh.repos[parsed_email.github_owner][parsed_email.github_repo].issues[parsed_email.issue_number].comments.post
        # * gh.repos[parsed_email.github_owner][parsed_email.github_repo].issues[parsed_email.issue_number].comments.get
        # * gh.repos[parsed_email.github_owner][parsed_email.github_repo].issues[parsed_email.issue_number].comments.patch
        # * gh.repos[parsed_email.github_owner][parsed_email.github_repo].issues[parsed_email.issue_number].comments[message['comment']['id']].reactions.post
        #
        # "Pull requests" repository permissions (write)
        # * gh.repos[parsed_email.github_owner][parsed_email.github_repo].issues[parsed_email.issue_number].patch
        # * gh.repos[parsed_email.github_owner][parsed_email.github_repo].issues[parsed_email.issue_number].comments.post
        # * gh.repos[parsed_email.github_owner][parsed_email.github_repo].issues[parsed_email.issue_number].comments.get
        # * gh.repos[parsed_email.github_owner][parsed_email.github_repo].issues[parsed_email.issue_number].comments.patch
        #
        # "Workflows" repository permissions (write)
        # * deploy.py : gh.repos[owner][repo].contents['.github']['workflows'][args.github_action_filename].put

        auth = GitHub(config['github_username'], password)
        status, authorization_data = auth.authorizations.post(body={
            'scopes': scopes,
            'note': note,
            'note_url': note_url})
        if (status == 401 and 'required' in
                dict(auth.getheaders()).get('x-github-otp')):
            auth = GitHub(config['github_username'], password, get_two_factor_code())
            #  'x-github-otp': 'required; sms',
            status, authorization_data = auth.authorizations.post(body={
                'scopes': scopes,
                'note': note,
                'note_url': note_url})

        config['github_token'] = authorization_data['token']
        green_print(
            f"GitHub OAuth Token (github_token) created : "
            f"{config['github_token']}")

    gh = GitHub(token=config['github_token'])
    status, user_data = gh.user.get()

    # SNS Topic
    client = boto3.client('sns')
    response = client.create_topic(  # This action is idempotent
        Name=config['sns_topic']
    )
    if config.get('sns_topic_arn') != response['TopicArn']:
        config['sns_topic_arn'] = response['TopicArn']

    # SES Notification SNS Topic
    response = client.create_topic(  # This action is idempotent
        Name=config['ses_notification_sns_topic']
    )
    if config.get('ses_notification_sns_topic_arn') != response['TopicArn']:
        config['ses_notification_sns_topic_arn'] = response['TopicArn']

    # Alert SNS Topic
    if 'alert_sns_topic' in config:
        response = client.create_topic(  # This action is idempotent
            Name=config['alert_sns_topic']
        )
        if config['alert_sns_topic'] != response['TopicArn']:
            config['alert_sns_topic_arn'] = response['TopicArn']
    elif early_run:
        print('''No alert_sns_topic in config so no alert topic will be setup.
You can add an alert topic to config later and re-run deploy if you would like
an SNS topic created that internal Birch Girder errors will be sent to.''')

    # S3 Bucket
    client = boto3.client('s3')
    try:
        client.head_bucket(Bucket=config['ses_payload_s3_bucket_name'])
    except client.exceptions.ClientError:
        response = client.create_bucket(
            Bucket=config['ses_payload_s3_bucket_name'],
            CreateBucketConfiguration={
                'LocationConstraint': config['sns_region']
            }
        )
        green_print(f"AWS S3 Bucket {response['Location']} created")

    statement_id = 'GiveSESPermissionToWriteEmail'
    try:
        response = client.get_bucket_policy(
            Bucket=config['ses_payload_s3_bucket_name']
        )
        policy = json.loads(response['Policy'])
    except:
        policy = {
            'Version': '2008-10-17',
            'Statement': []
        }
    if statement_id not in [x['Sid'] for x in policy['Statement']]:
        policy['Statement'].append(
            {
                'Sid': statement_id,
                'Effect': 'Allow',
                'Principal': {
                    'Service': 'ses.amazonaws.com'
                },
                'Action': 's3:PutObject',
                'Resource': f"arn:aws:s3:::{config['ses_payload_s3_bucket_name']}/*",
                'Condition': {
                    'StringEquals': {
                        'aws:Referer': config['sns_topic_arn'].split(':')[4]
                    }
                }
            }
        )
        client.put_bucket_policy(
            Bucket=config['ses_payload_s3_bucket_name'],
            Policy=json.dumps(policy)
        )
        green_print(
            f"AWS S3 Bucket policy for {config['ses_payload_s3_bucket_name']} "
            f"created")

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
        green_print(
            f"AWS S3 Bucket lifecycle configuration for "
            f"{config['ses_payload_s3_bucket_name']} applied to bucket")

    # SES
    client = boto3.client('ses')
    response = client.get_account_sending_enabled()
    if not response['Enabled']:
        print('Email sending is disabled.')
        client.update_account_sending_enabled(
            Enabled=True
        )
        green_print('AWS SES Email sending has been enabled.')

    identities = get_paginated_results('ses', 'list_identities', 'Identities')
    verifications_initiated = False
    identities_that_matter = []
    for recipient in [x.lower() for x in list(config['recipient_list'].keys())]:
        domain = recipient.split('@')[1]
        if recipient not in identities and domain not in identities:
            print(
                f"Recipient {recipient} verification hasn't been initiated in AWS SES")
            response = prompt(
                f'Would you like to verify the email address {recipient} or '
                f"the domain {recipient.split('@')[1]} [email/domain]")
            if response.lower() in ['email', recipient]:
                client.verify_email_identity(
                    EmailAddress=recipient
                )
                green_print(f'Initiating AWS SES verification of {recipient}')
                verifications_initiated = True
                break
            elif response.lower() in ['domain', domain]:
                response = prompt(
                    f'Would you like to host the zone {domain} in route53 '
                    f'(for $0.50/month) or on your own [route53/myself]')
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
                        f'{x}._domainkey{suffix}    IN    CNAME    {x}.dkim.amazonses.com.'
                        for x in response['DkimTokens']])
                    green_print(f'AWS SES verification of {domain} initiated')
                    # TODO : Add DMARC?
                    # http://docs.aws.amazon.com/ses/latest/DeveloperGuide/dmarc.html
                    print(f'''To verify this domain create a DNS record in the {domain} domain with
the name "_amazonses.{domain}" and the value "{token}"
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
''')
                    verifications_initiated = True
                else:
                    return

            else:
                return
        else:
            identities_that_matter.append(
                domain if domain in identities else recipient)
    if verifications_initiated:
        print('''Aborting while you complete email/domain verifications. Run this again when
they're complete''')
        return
    response = client.get_identity_verification_attributes(
        Identities=identities_that_matter
    )

    all_verifications_completed = True
    for identity in response['VerificationAttributes']:
        status = response['VerificationAttributes'][identity][
            'VerificationStatus']
        if status == 'Pending':
            print(f"Verification for {identity} is still pending. Run this "
                  f"again when it's complete")
            all_verifications_completed = False
        elif status == 'Failed':
            print(f"Verification for {identity} failed.")
            client.delete_identity(
                Identity=identity
            )
            print(f"Verification for {identity} has been deleted. "
                  "Run this again to initiate a new verification.")
            all_verifications_completed = False
        elif status == 'TemporaryFailure':
            print(f"Verification for {identity} has temporarily failed. Wait "
                  f"and run this again.")
            all_verifications_completed = False
    if not all_verifications_completed:
        return

    # SES Notifications
    recipient_email_address_list = [x.lower() for x in list(config['recipient_list'].keys())]
    client = boto3.client('ses')
    response = client.list_identities()
    recipient_to_ses_identity_map = {}
    for recipient_email_address in recipient_email_address_list:
        if recipient_email_address in response['Identities']:
            recipient_to_ses_identity_map[recipient_email_address] = response['Identities'][recipient_email_address]
        elif recipient_email_address.partition("@")[2] in response['Identities']:
            recipient_to_ses_identity_map[recipient_email_address] = recipient_email_address.partition("@")[2]
        else:
            recipient_to_ses_identity_map[recipient_email_address] = None

    response = client.get_identity_notification_attributes(
        Identities=[x for x in recipient_to_ses_identity_map.values() if x is not None])
    existing_attributes = response['NotificationAttributes']

    processed_identities = []
    # TODO : What if we exceed the 1 call per second limit to the endpoint that sets these values?
    for recipient, identity in recipient_to_ses_identity_map.items():
        if identity in processed_identities:
            # We've already processed this identity due to another recipient in the same domain, skipping
            continue
        processed_identities.append(identity)
        for attribute in ['Bounce', 'Complaint', 'Delivery']:
            if identity is None:
                # Set new SES Notification settings
                client.set_identity_notification_topic(
                    Identity=recipient,
                    NotificationType=attribute,
                    SnsTopic=config['ses_notification_sns_topic_arn'])
                green_print(f"New SES Notification for {attribute} notifications for {recipient} set to {config['ses_notification_sns_topic_arn']}")
            elif f"{attribute}Topic" not in existing_attributes[identity] or existing_attributes[identity][f"{attribute}Topic"] != config['ses_notification_sns_topic_arn']:
                # Check and update existing SES Notification settings
                client.set_identity_notification_topic(
                    Identity=identity,
                    NotificationType=attribute,
                    SnsTopic=config['ses_notification_sns_topic_arn'])
                green_print(
                    f"Existing SES Notification for {attribute} notifications for {identity} changed from {existing_attributes[identity].get(f'{attribute}Topic', None)} to {config['ses_notification_sns_topic_arn']}")

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
}''',
        'AWSLambdaPersistence': '''{
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Action": [
            "dynamodb:CreateTable",
            "dynamodb:TagResource",
            "dynamodb:PutItem",
            "dynamodb:DescribeTable",
            "dynamodb:GetItem"
          ],
          "Resource": "arn:aws:dynamodb:*:*:table/AWSLambdaPersistence"
        }
      ]
}'''
}

    if 'alert_sns_topic_arn' in config:
        policies['SNSPublisher'] = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["sns:Publish"],
                    "Resource": config['alert_sns_topic_arn']
                }]
            }, indent=4)

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
    iam_roles = get_paginated_results('iam', 'list_roles', 'Roles')
    if args.lambda_iam_role_name in [x['RoleName'] for x in iam_roles]:
        lambda_iam_role_arn = next(
            x['Arn'] for x in iam_roles
            if x['RoleName'] == args.lambda_iam_role_name)
    else:
        green_print(f"Creating AWS IAM role {args.lambda_iam_role_name}")
        response = client.create_role(
            RoleName=args.lambda_iam_role_name,
            AssumeRolePolicyDocument=assume_role_policy_document
        )
        # https://github.com/boto/boto3/issues/1381
        while True:
            try:
                client.get_role(RoleName=args.lambda_iam_role_name)
                break
            except client.exceptions.ClientError:
                time.sleep(2)

        lambda_iam_role_arn = response['Role']['Arn']

    role_policies = get_paginated_results(
        'iam', 'list_role_policies', 'PolicyNames',
        args={'RoleName': args.lambda_iam_role_name})
    for policy_name in policies:
        if policy_name not in role_policies:
            green_print(
                f"Attaching AWS IAM policy {policy_name} to AWS IAM role "
                f"{args.lambda_iam_role_name}")
            client.put_role_policy(
                RoleName=args.lambda_iam_role_name,
                PolicyName=policy_name,
                PolicyDocument=policies[policy_name]
            )
            while True:
                try:
                    client.get_role_policy(RoleName=args.lambda_iam_role_name, PolicyName=policy_name)
                    break
                except client.exceptions.ClientError:
                    time.sleep(2)

    # Lambda function layer
    client = boto3.client('lambda')
    zip_file_name = 'artifacts/birch-girder.zip'
    hash_version_map_filename = 'artifacts/.hash_version_map.json'
    layers = get_paginated_results('lambda', 'list_layers', 'Layers')
    layer_name = 'birch-girder-layer'
    publish_layer = False
    with open(zip_file_name, mode='rb') as f:
        try:
            hash_map_file = open(hash_version_map_filename)
            hash_map = json.load(hash_map_file)
            hash_map_file.close()
        except IOError:
            hash_map = {}

        digest = hashlib.sha256(f.read()).hexdigest()
        f.seek(0)
        if layer_name not in [x['LayerName'] for x in layers]:
            # Create a new Lambda layer
            publish_layer = True
            function_needs_update = True
        else:
            function_needs_update = False
            if digest not in hash_map:
                # layer zip has changed and should be published
                publish_layer = True
                function_needs_update = True
            else:
                # layer zip hasn't changed from a published version
                birch_girder_layer_version_arn = hash_map[digest]
                try:
                    response = client.get_function(
                        FunctionName=args.lambda_function_name)
                    if birch_girder_layer_version_arn not in [x['Arn'] for x in response['Configuration'].get('Layers', [])]:
                        # Lambda function doesn't include the layer
                        function_needs_update = True
                except:
                    # There is no lambda function
                    pass
        if publish_layer:
            response = client.publish_layer_version(
                LayerName=layer_name,
                Description='Birch Girder supporting python packages',
                Content={'ZipFile': f.read()},
                CompatibleRuntimes=['python3.9', 'python3.10', 'python3.11', 'python3.12', 'python3.13', 'python3.14'])
            birch_girder_layer_version_arn = response['LayerVersionArn']
            green_print(f'AWS Lambda layer published : {birch_girder_layer_version_arn}')
            hash_map[digest] = birch_girder_layer_version_arn
            with open(hash_version_map_filename, 'w') as hash_map_file:
                json.dump(hash_map, hash_map_file, indent=4)
            function_needs_update = True


    # Lambda function
    init_filename = 'birch_girder/__init__.py'
    functions = get_paginated_results('lambda', 'list_functions', 'Functions')
    if args.lambda_function_name not in [x['FunctionName'] for x
                                         in functions]:
        # Lambda function doesn't exist, create it
        in_memory_data = io.BytesIO()
        zip_file = zipfile.ZipFile(in_memory_data, 'w')
        zip_file.writestr(
            init_filename, 'def lambda_handler(event, context):\n  pass\n')
        zip_file.close()
        while True:
            try:
                response = client.create_function(
                    FunctionName=args.lambda_function_name,
                    Runtime='python3.14',
                    Role=lambda_iam_role_arn,
                    Handler='__init__.lambda_handler',
                    Code={'ZipFile': in_memory_data.getvalue()},
                    Description='Birch Girder',
                    Timeout=30,
                    Layers=[
                        birch_girder_layer_version_arn,
                        AWS_LAMBDA_PERSISTENCE_LAYER_ARN
                    ]
                )
                break
            except client.exceptions.InvalidParameterValueException as e:
                if ('The role defined for the function cannot be assumed'
                        in str(e)):
                    # Timing issue where the role exists but Lambda doesn't see
                    # it yet
                    time.sleep(2)
                    continue
                else:
                    raise

        # https://github.com/boto/boto3/issues/1382
        while True:
            try:
                client.get_function(FunctionName=args.lambda_function_name)
                break
            except client.exceptions.ClientError:
                time.sleep(2)

        lambda_function_arn = response['FunctionArn']
        green_print(f'AWS Lambda function created : {lambda_function_arn}')
        in_memory_data.close()
    else:
        # Lambda function already exists, update it
        if function_needs_update:
            response = client.update_function_configuration(
                FunctionName=args.lambda_function_name,
                Layers=[birch_girder_layer_version_arn, AWS_LAMBDA_PERSISTENCE_LAYER_ARN]
            )
            green_print(f"AWS Lambda function configuration updated with new "
                        f"Lambda layer :{response['FunctionArn']}")
        pass

    in_memory_data = io.BytesIO()

    with zipfile.ZipFile(in_memory_data, 'w') as zip_file:
        config_file = zipfile.ZipInfo('config.yaml', time.localtime()[:6])
        config_file.compress_type = zipfile.ZIP_DEFLATED
        config_file.external_attr = 0o644 << 16
        zip_file.writestr(config_file, open(args.config).read())

        zip_file.write(
            init_filename,
            '__init__.py',
            zipfile.ZIP_DEFLATED)

        for filename in os.listdir(args.plugins_path):
            arcname = os.path.join('plugins', filename)
            full_path = os.path.join(args.plugins_path, filename)
            zip_file.write(
                full_path,
                arcname,
                zipfile.ZIP_DEFLATED)

    while True:
        try:
            response = client.update_function_code(
                FunctionName=args.lambda_function_name,
                ZipFile=in_memory_data.getvalue()
            )
            break
        except client.exceptions.ResourceConflictException:
            # The operation cannot be performed at this time. An update is in progress, so we wait
            sleep(2)
    lambda_function_arn = response['FunctionArn']
    green_print(f'AWS Lambda function updated : {lambda_function_arn}')

    in_memory_data.close()

    # Lambda function event invoke config

    response = client.get_function_event_invoke_config(
        FunctionName=args.lambda_function_name)
    if response['MaximumRetryAttempts'] != 0:
        response = client.update_function_event_invoke_config(
            FunctionName=args.lambda_function_name,
            MaximumRetryAttempts=0
        )
        green_print(
            'AWS Lambda function invoke config updated. MaximumRetryAttempts '
            f"set to {response['MaximumRetryAttempts']}")

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
        green_print(f'Permission {statement_id} added to AWS Lambda function '
                    f'{args.lambda_function_name}')

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
        green_print(f'Permission {statement_id} added to AWS Lambda function '
                    f'{args.lambda_function_name}')

    # SNS permission to invoke Lambda function
    statement_id = 'GiveSESNotificationSNSTopicPermissionToInvokeFunction'
    if (policy is None
            or statement_id not in [x['Sid'] for x
                                    in json.loads(policy)['Statement']]):
        response = client.add_permission(
            FunctionName=args.lambda_function_name,
            StatementId=statement_id,
            Action='lambda:InvokeFunction',
            Principal='sns.amazonaws.com',
            SourceArn=config['ses_notification_sns_topic_arn']
        )
        green_print(f'Permission {statement_id} added to AWS Lambda function '
                    f'{args.lambda_function_name}')

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
                green_print(f'AWS SES Rule Set {args.ses_rule_set_name} created')
                rule_set_created = True
            else:
                time.sleep(2)

    if args.ses_rule_name not in [x['Name'] for x in response['Rules']]:
        client.create_receipt_rule(
            RuleSetName=args.ses_rule_set_name,
            Rule={
                'Name': args.ses_rule_name,
                'Enabled': True,
                'Recipients': list(config['recipient_list'].keys()),
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
        green_print(f'AWS SES Rule {args.ses_rule_name} created in Rule Set '
                    f'{args.ses_rule_set_name}')
    response = client.describe_active_receipt_rule_set()
    if response['Metadata']['Name'] != args.ses_rule_set_name:
        client.set_active_receipt_rule_set(
            RuleSetName=args.ses_rule_set_name
        )
        green_print(f'AWS SES Rule Set {args.ses_rule_set_name} set as active')

    # GitHub IAM user
    policy_document = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": ["sns:Publish"],
                "Sid": "PublishToGitHubWebhookTopic",
                "Resource": [config['sns_topic_arn']],
                "Effect": "Allow"
            },
            {
                "Action": ["sns:ListTopics"],
                "Sid": "ListSNSTopics",
                "Resource": "*",
                "Effect": "Allow"
            }
        ]
    }, indent=4)
    client = boto3.client('iam')
    iam_users = get_paginated_results('iam', 'list_users', 'Users')
    if args.github_iam_username not in [x['UserName'] for x in iam_users]:
        response = client.create_user(
            UserName=args.github_iam_username
        )
        green_print(f"AWS IAM user {response['User']['UserName']} created")

    policy_name = 'PublishToGithubWebhookSNSTopic'
    user_policies = get_paginated_results(
        'iam', 'list_user_policies', 'PolicyNames',
        args={'UserName': args.github_iam_username})
    if policy_name not in user_policies:
        client.put_user_policy(
            UserName=args.github_iam_username,
            PolicyName=policy_name,
            PolicyDocument=policy_document
        )
        green_print(f'AWS IAM policy {policy_name} applied to user '
                    f'{args.github_iam_username}')

    # GitHub Actions
    for owner, repo, repo_private in set(
            [(config['recipient_list'][x].get('owner'),
              config['recipient_list'][x].get('repo'),
              config['recipient_list'][x].get('repo_private', True)) for x in config['recipient_list']]):

        if owner is None or repo is None:
            print('A recipient is missing owner or repo. Skipping')
            continue
        html_url = f'https://github.com/{owner}/{repo}'
        print(f'Processing {html_url}')
        status, repo_data = gh.repos[owner][repo].get()

        if repo_data.get('name') is None:
            body = {
                'name': repo,
                'private': repo_private,
                'auto_init': True
            }
            if owner != user_data['login']:
                org = gh.orgs[owner]
                status, org_data = org.get()
                if org_data.get('login') is None:
                    print(f'''  Recipient {html_url} has repo owner of {owner} but the github_token user we're
using is {user_data['login']} and the repo doesn't yet exist. {owner} is not a GitHub
organization so we can't create the repo. Skipping''')
                    continue
                else:
                    status, repo_data = (
                        org.repos.post(body=body))
            else:
                status, repo_data = gh.user.repos.post(body=body)
            if status == 422:
                print(f"  Got error {status} when attempting to create new "
                      f"GitHub repo {repo}")
                return
            green_print(f"  Created GitHub repo {repo_data['html_url']}")

        # GitHub Actions Secrets
        status, secrets_data = gh.repos[owner][repo].actions.secrets.get()
        if 'BIRCH_GIRDER_AWS_ACCESS_KEY_ID' not in [x['name'] for x in secrets_data['secrets']]:
            if not config.get('github_iam_user_access_key_id'):
                response = client.create_access_key(
                    UserName=args.github_iam_username
                )
                config['github_iam_user_access_key_id'] = response['AccessKey']['AccessKeyId']
                config['github_iam_user_secret_access_key'] = response['AccessKey']['SecretAccessKey']
                # These values are only needed by deploy not by the lambda function
                # We could try creating two configs, one for deploy and one for
                # lambda, or a master config with two parent dicts and only one
                # gets written to the lambda zip at deploy time, with only the
                # values that the lambda function needs
                green_print(f"Created new Access Key for AWS IAM user "
                            f"{args.github_iam_username} : "
                            f"{config['github_iam_user_access_key_id']}")

            status, public_key_data = gh.repos[owner][repo].actions.secrets['public-key'].get()

            status, _ = gh.repos[owner][repo].actions.secrets.BIRCH_GIRDER_AWS_ACCESS_KEY_ID.put(
                body={
                    'encrypted_value': encrypt_github_actions_secret(
                        public_key_data['key'],
                        config['github_iam_user_access_key_id']),
                    'key_id': public_key_data['key_id']})
            status, _ = gh.repos[owner][repo].actions.secrets.BIRCH_GIRDER_AWS_SECRET_ACCESS_KEY.put(
                body={
                    'encrypted_value': encrypt_github_actions_secret(
                        public_key_data['key'],
                        config['github_iam_user_secret_access_key']),
                    'key_id': public_key_data['key_id']})
            green_print('  New GitHub Actions secrets set')

        # GitHub Actions workflow
        status, workflow_data = gh.repos[owner][repo].contents['.github']['workflows'][args.github_action_filename].get()
        with open('emit-comment-to-sns-github-action.yml') as f:
            workflow_config = yaml.load(f.read(), Loader=yaml.SafeLoader)
            workflow_config['jobs']['emit_comment']['if'] = f"github.event.comment.user.login != '{config['github_username']}'"
            workflow_config['jobs']['emit_comment']['env']['BIRCH_GIRDER_SNS_TOPIC_REGION'] = config['sns_topic_arn'].split(':')[3]
            workflow_config['jobs']['emit_comment']['env']['BIRCH_GIRDER_SNS_TOPIC_ARN'] = config['sns_topic_arn']
            content = yaml.dump(workflow_config, default_flow_style=False)
            b64_content = base64.b64encode(content.encode('ascii')).decode('ascii')
            if status == 404:
                status, _ = gh.repos[owner][repo].contents['.github']['workflows'][args.github_action_filename].put(
                    body={
                        'message': 'Adding Birch Girder GitHub Actions workflow\n\nhttps://github.com/gene1wood/birch-girder',
                        'content': b64_content})
                if 200 <= status < 300:
                    green_print(f'  New GitHub Actions workflow '
                                f'{args.github_action_filename} deployed')
                else:
                    print(f"result from add {status} and {_}")
            elif base64.b64decode(workflow_data['content']).decode('ascii') != content:
                status, _ = gh.repos[owner][repo].contents['.github']['workflows'][args.github_action_filename].put(
                    body={
                        'message': 'Updating Birch Girder GitHub Actions workflow\n\nhttps://github.com/gene1wood/birch-girder',
                        'content': b64_content,
                        'sha': workflow_data['sha']})
                if 200 <= status < 300:
                    green_print(f'  GitHub Actions workflow '
                                f'{args.github_action_filename} updated')
                else:
                    print(f"result from update {owner}/{repo}/.github/workflows/{args.github_action_filename} {status} and {_}")

    # Subscribe Lambda function to SNS
    client = boto3.client('sns')
    subscriptions = get_paginated_results(
        'sns', 'list_subscriptions_by_topic', 'Subscriptions',
        args={'TopicArn': config['sns_topic_arn']})
    if lambda_function_arn not in [x['Endpoint'] for x in subscriptions
                                   if x['Protocol'] == 'lambda']:
        response = client.subscribe(
            TopicArn=config['sns_topic_arn'],
            Protocol='lambda',
            Endpoint=lambda_function_arn
        )
        green_print(f"Birch Girder AWS Lambda function subscribed to AWS SNS "
                    f"Topic : {response['SubscriptionArn']}")

    # Subscribe Lambda function to SES Notification SNS Topic
    subscriptions = get_paginated_results(
        'sns', 'list_subscriptions_by_topic', 'Subscriptions',
        args={'TopicArn': config['ses_notification_sns_topic_arn']})
    if lambda_function_arn not in [x['Endpoint'] for x in subscriptions
                                   if x['Protocol'] == 'lambda']:
        response = client.subscribe(
            TopicArn=config['ses_notification_sns_topic_arn'],
            Protocol='lambda',
            Endpoint=lambda_function_arn
        )
        green_print(f"Birch Girder AWS Lambda function subscribed to AWS SES "
                    f"Notification SNS Topic : {response['SubscriptionArn']}")


if __name__ == '__main__':
    main()
