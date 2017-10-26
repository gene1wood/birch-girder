import boto3
import yaml
from github3 import authorize
from getpass import getuser, getpass
import argparse
from github3 import login  # https://github3py.readthedocs.io/en/master/

CONFIG = '''---
sns_topic_arn: arn:aws:sns:us-west-2:123456789012:GithubIssueCommentWebhookTopic
sns_region: us-west-2
github_token: 0123456789abcdef0123456789abcdef01234567
github_username: hubot
github_owner: octocat
github_repo: Spoon-Knife
ses_payload_s3_bucket_name: examplebucket
ses_payload_s3_prefix: ses-payloads/
alert_sns_region: us-west-2
alert_sns_topic_arn: arn:aws:sns:us-west-2:123456789012:BirchGirderAlerts
provider_name: Example Corp
recipient_list:
  support@example.com:
    label: Support
    name: Example-Corp-Support
  billing@example.com:
    label: Billing
    name: Example-Corp-Billing
'''

try:
    # Python 2
    prompt = raw_input
except NameError:
    # Python 3
    prompt = input


def grant_lambda_policy_permissions(config, lambda_function_arn, topic):
    statement_id = 'GiveSESPermissionToInvokeFunction'
    client = boto3.client('lambda')
    try:
        response = client.remove_permission(
            FunctionName=lambda_function_arn,
            StatementId=statement_id
        )
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

    statement_id = 'GiveSNSPermissionToInvokeFunction'
    try:
        response = client.remove_permission(
            FunctionName=lambda_function_arn,
            StatementId=statement_id
        )
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

def setup_ses(config, lambda_function_arn):
    client = boto3.client('ses')
    rule_set_name = 'birch-girder-ruleset'
    response = client.create_receipt_rule_set(
        RuleSetName=rule_set_name
    )
    print('SES Rule Set created')

    # http://boto3.readthedocs.io/en/latest/reference/services/ses.html#SES.Client.create_receipt_rule
    response = client.create_receipt_rule(
        RuleSetName=rule_set_name,
        Rule={
            'Name': 'birch-girder-rule',
            'Enabled': True,
            'Recipients': config['recipient_list'].keys(),
            'Actions': [
                {
                    'S3Action': {
                        'BucketName': config['ses_payload_s3_bucket_name'],
                        'ObjectKeyPrefix': 'ses-payloads'
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
    print('SES Rule created in Rule Set')
    response = client.set_active_receipt_rule_set(
        RuleSetName=rule_set_name
    )
    print('SES Rule Set set as active')


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

    print("GitHub OAuth Token : %s" % auth.token)
    print("GitHub OAuth ID : %s" % auth.id)


def create_github_iam_user(
        sns_topic_arn, iam_username='github-sns-publisher'):
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
}''' % sns_topic_arn
    client = boto3.client('iam')
    response = client.create_user(
        UserName=iam_username
    )
    response = client.put_user_policy(
        UserName=iam_username,
        PolicyName='PublishToSNSaws-ses-github-connector',
        PolicyDocument=policy_document
    )
    response = client.create_access_key(
        UserName=iam_username
    )
    print('AccessKeyId : %s' % response['AccessKey']['AccessKeyId'])
    print('SecretAccessKey : %s' % response['AccessKey']['SecretAccessKey'])


def create_iam_role(config, iam_rolename='birch-girder'):
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
      "Resource": "arn:aws:s3:::%(bucket_name)s/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket"
      ],
      "Resource": "arn:aws:s3:::%(bucket_name)s"
    }
  ]
}''' % {'bucket_name': config['ses_payload_s3_bucket_name']},
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
    print("Creating role %s" % iam_rolename)
    response = client.create_role(
        RoleName=iam_rolename,
        AssumeRolePolicyDocument=assume_role_policy_document
        # Description='IAM role assumed by birch-girder lambda '
        #             'function'
    )
    for policy_name in policies:
        print("Attaching policy %s" % policy_name)
        response = client.put_role_policy(
            RoleName=iam_rolename,
            PolicyName=policy_name,
            PolicyDocument=policies[policy_name]
        )

def create_sns_topic():
    client = boto3.client('sns')
    response = client.create_topic(
        Name='GithubIssueCommentWebhookTopic'
    )
    print('Topic ARN : %s' % response['TopicArn'])


def subscribe_lambda_to_sns_topic(topic, lambda_function_arn):
    client = boto3.client('sns')
    response = client.subscribe(
        TopicArn=topic,
        Protocol='lambda',
        Endpoint=lambda_function_arn
    )
    print('Subscription ARN : %s' % response['SubscriptionArn'])



def edit_github_webhook(config, repo_owner, repo_name):
    # https://stackoverflow.com/a/43522648/168874
    gh = login(token=config['github_webhook_editor_token'])
    repo = gh.repository(repo_owner, repo_name)
    for hook in repo.hooks():
        if hook.name == u'amazonsns':
            result = hook.edit(events=[u'issue_comment'])


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
    with open('birch_girder/config.yaml') as f:
        config = yaml.load(f.read())
    parser = argparse.ArgumentParser(
        description='Manage Birch Girder')
    parser.add_argument(
        'action',
        choices=['grant-lambda-policy-permissions',
                 'create-bucket',
                 'setup-ses',
                 'generate-github-token',
                 'create-sns-topic',
                 'create-iam-user',
                 'create-iam-role',
                 'subscribe-lambda-to-sns',
                 'configure-github-webhook'],
        help='the action to execute')
    parser.add_argument('--sns-topic-arn',
                        help='ARN of the SNS Topic that was created')
    parser.add_argument('--lambda-function-arn',
                        help='ARN of the AWS Lambda function that has been '
                             'created')
    parser.add_argument('--repo-owner',
                        help='GitHub username of the repo owner')
    parser.add_argument('--repo-name',
                        help='GitHub name of the repo')
    args = parser.parse_args()



    if args.action == 'grant-lambda-policy-permissions':
        grant_lambda_policy_permissions(config, args.lambda_function_arn, args.sns_topic_arn)
    elif args.action == 'create-bucket':
        create_s3_bucket(config)
    elif args.action == 'setup-ses':
        setup_ses(config, args.lambda_function_arn)
    elif args.action == 'generate-github-token':
        generate_github_token()
    elif args.action == 'create-sns-topic':
        create_sns_topic()
    elif args.action == 'create-iam-user':
        create_github_iam_user(args.sns_topic_arn)
    elif args.action == 'create-iam-role':
        create_iam_role(config)
    elif args.action == 'subscribe-lambda-to-sns':
        subscribe_lambda_to_sns_topic(args.sns_topic_arn, args.lambda_function_arn)
    elif args.action == 'configure-github-webhook':
        edit_github_webhook(config, args.repo_owner, args.repo_name)
if __name__ == '__main__':
    main()
