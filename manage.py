#!/usr/bin/python
# -*- coding: utf-8 -*-

import boto3
import yaml
from github3 import authorize
from getpass import getpass
import argparse
from github3 import login  # https://github3py.readthedocs.io/en/master/

try:
    # Python 2
    prompt = raw_input
except NameError:
    # Python 3
    prompt = input


def grant_lambda_policy_permissions(config, lambda_function_arn):
    topic = config['sns_topic_arn']
    alert_topic = config['alert_sns_topic_arn']
    statement_id = 'GiveSESPermissionToInvokeFunction'
    client = boto3.client('lambda')
    try:
        client.remove_permission(
            FunctionName=lambda_function_arn,
            StatementId=statement_id
        )
        print('%s Lambda permission removed' % statement_id)
    except:
        pass
    response = client.add_permission(
        FunctionName=lambda_function_arn,
        StatementId=statement_id,
        Action='lambda:InvokeFunction',
        Principal='ses.amazonaws.com',
        SourceAccount=lambda_function_arn.split(':')[4]
    )
    print('Permission %s added : %s' % (statement_id, response['Statement']))

    statement_id = 'GiveGithubWebhookSNSTopicPermissionToInvokeFunction'
    try:
        client.remove_permission(
            FunctionName=lambda_function_arn,
            StatementId=statement_id
        )
        print('%s Lambda permission removed' % statement_id)

    except:
        pass
    response = client.add_permission(
        FunctionName=lambda_function_arn,
        StatementId=statement_id,
        Action='lambda:InvokeFunction',
        Principal='sns.amazonaws.com',
        SourceArn=topic
    )
    print('Permission %s added : %s' % (statement_id, response['Statement']))


def setup_ses(config,
              lambda_function_arn,
              rule_name,
              rule_set_name='birch-girder-ruleset'):
    client = boto3.client('ses')
    try:
        response = client.describe_receipt_rule_set(RuleSetName=rule_set_name)
        print('SES Rule set %s already exists' % response['Metadata']['Name'])
    except:
        client.create_receipt_rule_set(
            RuleSetName=rule_set_name
        )
        print('SES Rule Set %s created' % rule_set_name)

    client.create_receipt_rule(
        RuleSetName=rule_set_name,
        Rule={
            'Name': rule_name,
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
    print('SES Rule %s created in Rule Set' % rule_name)
    client.set_active_receipt_rule_set(
        RuleSetName=rule_set_name
    )
    print('SES Rule Set %s set as active' % rule_set_name)


def get_two_factor_code():
    code = ''
    while not code:
        code = prompt('Enter 2FA code: ')
    return code


def generate_github_token():
    user = prompt('Enter your GitHub username: ')
    password = ''

    while not password:
        password = getpass('Password for {0}: '.format(user))

    note = 'birch-girder'
    note_url = 'http://github.com/gene1wood/birch-girder'
    scopes = ['repo']

    auth = authorize(
        user, password, scopes, note, note_url,
        two_factor_callback=get_two_factor_code)

    print("GitHub OAuth Token (github_token) : %s" % auth.token)
    print("GitHub OAuth ID : %s" % auth.id)


def create_github_repo(config):
    gh = login(token=config['github_token'])
    repo = gh.create_repo(
        name=config['github_repo'],
        private=True,
        auto_init=True
    )
    print("Created GitHub repo %s" % repo.html_url)


def create_github_iam_user(config, iam_username='github-sns-publisher'):
    policy_document = '''{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "sns:Publish"
            ],
            "Sid": "Stmt0000000000000",
            "Resource": [
                "%s"
            ],
            "Effect": "Allow"
        }
    ]
}''' % config['sns_topic_arn']
    client = boto3.client('iam')
    response = client.create_user(
        UserName=iam_username
    )
    print('IAM user %s created' % response['User']['UserName'])
    policy_name = 'PublishToGithubWebhookSNSTopic'
    client.put_user_policy(
        UserName=iam_username,
        PolicyName=policy_name,
        PolicyDocument=policy_document
    )
    print('IAM policy %s applied to user %s' % (policy_name, iam_username))
    response = client.create_access_key(
        UserName=iam_username
    )
    print('AccessKeyId : %s' % response['AccessKey']['AccessKeyId'])
    print('SecretAccessKey : %s' % response['AccessKey']['SecretAccessKey'])


def create_iam_role(config, lambda_iam_role_name='birch-girder'):
    policies = {
        'LambdaBasicExecution' : '''{
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
        'S3Reader' : '''{
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
        'SESSender' : '''{
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
        'SNSPublisher': '''{
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

    }

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
    print("Creating role %s" % lambda_iam_role_name)
    response = client.create_role(
        RoleName=lambda_iam_role_name,
        AssumeRolePolicyDocument=assume_role_policy_document
        # Description='IAM role assumed by birch-girder lambda '
        #             'function'
    )
    for policy_name in policies:
        print("Attaching policy %s" % policy_name)
        response = client.put_role_policy(
            RoleName=lambda_iam_role_name,
            PolicyName=policy_name,
            PolicyDocument=policies[policy_name]
        )

def create_sns_topic(config):
    client = boto3.client('sns')
    response = client.create_topic(
        Name=config['sns_topic_arn'].split(':')[5]
    )
    print('Topic ARN : %s' % response['TopicArn'])


def subscribe_lambda_to_sns_topic(config, lambda_function_arn):
    client = boto3.client('sns')
    response = client.subscribe(
        TopicArn=config['sns_topic_arn'],
        Protocol='lambda',
        Endpoint=lambda_function_arn
    )
    print('Subscription ARN : %s' % response['SubscriptionArn'])



def configure_github_webhook(config):
    # https://stackoverflow.com/a/43522648/168874
    gh = login(token=config['github_webhook_editor_token'])
    repo = gh.repository(config['github_owner'], config['github_repo'])
    events = [u'issue_comment']
    for hook in repo.iter_hooks():
        if hook.name == u'amazonsns':
            result = hook.edit(events=events)
            print(
                'GitHub webook "amazonsns" on repo %s configured to trigger on'
                ' %s' % (repo.html_url, events))


def create_s3_bucket(config):
    client = boto3.client('s3')
    response = client.create_bucket(
        Bucket=config['ses_payload_s3_bucket_name'],
        CreateBucketConfiguration={
            'LocationConstraint': config['sns_region']
        }
    )
    print('Bucket %s created' % response['Location'])

    response = client.put_bucket_policy(
        Bucket=config['ses_payload_s3_bucket_name'],
        Policy='''{
    "Version": "2008-10-17",
    "Statement": [
        {
            "Sid": "GiveSESPermissionToWriteEmail",
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
}''' % (config['ses_payload_s3_bucket_name'], config['sns_topic_arn'].split(':')[4])
    )
    print('Bucket policy for %s created' % config['ses_payload_s3_bucket_name'])

    response = client.put_bucket_lifecycle_configuration(
        Bucket=config['ses_payload_s3_bucket_name'],
        LifecycleConfiguration={
            'Rules': [
                {
                    'Expiration': {
                        'Days': 7,
                    },
                    'ID': 'DeleteSESEmailPayloadsAfter7Days',
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
    print('Bucket lifecycle configuration for %s applied to bucket' % config['ses_payload_s3_bucket_name'])


def deploy_to_lambda():
    pass


def main():
    try:
        with open('birch_girder/config.yaml') as f:
            config = yaml.load(f.read())
    except:
        config = {}
    parser = argparse.ArgumentParser(
        description='Manage Birch Girder')
    parser.add_argument(
        'action',
        choices=[
            'generate-github-token',
            'create-github-repo',
            'grant-lambda-policy-permissions',
            'create-bucket',
            'setup-ses',
            'create-sns-topic',
            'create-github-iam-user',
            'create-lambda-iam-role',
            'subscribe-lambda-to-sns',
            'configure-github-webhook'
        ],
        help='the action to execute')
    parser.add_argument('--lambda-function-arn',
                        help='ARN of the AWS Lambda function that has been '
                             'created')
    parser.add_argument('--lambda-iam-role-name', default='birch-girder',
                        help='Name of the IAM role to be used by Lambda '
                             '(default: birch-girder)')
    parser.add_argument('--ses-rule-name', default='birch-girder-rule',
                        help='Name of the SES rule to create '
                             '(default: birch-girder-rule)')
    parser.add_argument('--github-iam-username', default='github-sns-publisher',
                        help='Name of the IAM user to be used by GitHub '
                             '(default: github-sns-publisher)')
    args = parser.parse_args()

    if args.action == 'generate-github-token':
        generate_github_token()
    elif args.action == 'create-github-repo':
        create_github_repo(config)
    elif args.action == 'grant-lambda-policy-permissions':
        grant_lambda_policy_permissions(config, args.lambda_function_arn)
    elif args.action == 'create-bucket':
        create_s3_bucket(config)
    elif args.action == 'setup-ses':
        setup_ses(config, args.lambda_function_arn, args.ses_rule_name)
    elif args.action == 'create-sns-topic':
        create_sns_topic(config)
    elif args.action == 'create-github-iam-user':
        create_github_iam_user(config, args.github_iam_username)
    elif args.action == 'create-lambda-iam-role':
        create_iam_role(config, args.lambda_iam_role_name)
    elif args.action == 'configure-github-webhook':
        configure_github_webhook(config)
    elif args.action == 'subscribe-lambda-to-sns':
        subscribe_lambda_to_sns_topic(config, args.lambda_function_arn)


if __name__ == '__main__':
    main()
