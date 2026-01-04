#!/usr/bin/python
# -*- coding: utf-8 -*-

import argparse
import collections
import json

from agithub.GitHub import GitHub  # pip install agithub
from botocore.exceptions import ClientError
import agithub.base
import boto3
import yaml

END_COLOR = "\033[0m"
GREEN_COLOR = "\033[92m"


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
        with open(self.filename, "w") as f:
            f.write(yaml.dump(dict(self), default_flow_style=False))

    def load(self):
        try:
            with open(self.filename) as f:
                self.update(**yaml.load(f.read()))
        except Exception:
            pass


class HookIOClient(agithub.base.Client):
    # Remove the 'delete' method as it conflicts with a hook.io path that
    # contains 'delete'
    http_methods = (
        "head",
        "get",
        "post",
        "put",
        "patch",
    )


class HookIO(agithub.base.API):
    def __init__(self, api_key=None, *args, **kwargs):
        extra_headers = dict()
        if api_key is not None:
            extra_headers["hookio-private-key"] = api_key
        props = agithub.base.ConnectionProperties(
            api_url="hook.io", secure_http=True, extra_headers=extra_headers
        )
        self.setClient(HookIOClient(*args, **kwargs))
        self.setConnectionProperties(props)


def green_print(data):
    print(GREEN_COLOR + data + END_COLOR)


def get_paginated_results(product, action, key, args=None):
    args = {} if args is None else args
    return [
        y
        for sublist in [
            x[key] for x in boto3.client(product).get_paginator(action).paginate(**args)
        ]
        for y in sublist
    ]


def update_hookio_env_vars(hook_io, new_env_vars, current_env_vars=None):
    if current_env_vars is None:
        status, current_env_vars = hook_io.env.get()

    data = dict(current_env_vars)
    for k, v in new_env_vars.items():
        data[k] = v

    created_vars = set(data.keys()) - set(current_env_vars.keys())
    updated_vars = [x for x in new_env_vars.keys() if new_env_vars[x] != data.get(x)]
    deleted_vars = [k for k, v in new_env_vars.items() if v is None]

    if created_vars or updated_vars or deleted_vars:
        status, result = hook_io.env.post(body={"env": data})
        if status != 200 or result.get("status") != "updated":
            print(f"Got error {result} when attempting to set hook.io env vars")
        else:
            message = ""
            if created_vars:
                message += f"Created {created_vars} "
            if updated_vars:
                message += f"Updated {updated_vars} "
            if deleted_vars:
                message += f"Deleted {deleted_vars}"
            green_print(f"hook.io env variables changed : {message}")


def clean(config, args):
    gh = GitHub(token=config["github_token"])
    status, user_data = gh.user.get()

    # Unsubscribe Lambda function from SNS
    client_lambda = boto3.client("lambda")
    functions = get_paginated_results("lambda", "list_functions", "Functions")

    lambda_function_arn = next(
        (
            x["FunctionArn"]
            for x in functions
            if x["FunctionName"] == args.lambda_function_name
        ),
        None,
    )
    if lambda_function_arn is not None:
        client_sns = boto3.client("sns")
        subscriptions = get_paginated_results(
            "sns",
            "list_subscriptions_by_topic",
            "Subscriptions",
            {"TopicArn": config["sns_topic_arn"]},
        )
        subscription_arn = next(
            (
                x["SubscriptionArn"]
                for x in subscriptions
                if lambda_function_arn == x["Endpoint"]
            ),
            None,
        )
        if subscription_arn is not None:
            response = client_sns.unsubscribe(SubscriptionArn=subscription_arn)
            green_print(
                "Birch Girder AWS Lambda function unsubscribed from SNS Topic :"
                f" {subscription_arn}"
            )

    hook_io = HookIO(api_key=config["hook_io_api_key"])
    status, hook_io_user = hook_io.keys.checkAccess.get(
        hook_private_key=config["hook_io_api_key"]
    )
    if not hook_io_user["hasAccess"]:
        print("""
Your hook.io API key isn't valid. Make sure the key was set up correctly.""")
        exit(1)
    hook_url = "/".join(
        ["https://hook.io", hook_io_user["user"]["name"], args.hookio_service_name]
    )

    client_iam = boto3.client("iam")
    # For each recipient
    #    Leave the created GitHub repo in place
    #    Delete GitHub webhook
    #    Delete hook.io env var GitHub webhook secret
    for recipient in config["recipient_list"]:
        owner_name = config["recipient_list"][recipient]["owner"]
        repo_name = config["recipient_list"][recipient]["repo"]
        print(f"Processing https://github.com/{owner_name}/{repo_name}")
        if (
            "owner" not in config["recipient_list"][recipient]
            or "repo" not in config["recipient_list"][recipient]
        ):
            print(f"  Recipient {recipient} missing owner or repo. Skipping")
            continue

        repo = gh.repos[owner_name][repo_name]
        status, repo_data = repo.get()
        if repo_data.get("name") is None:
            print(f"  Leaving GitHub repo {repo_data['name']} in place")

        # Delete GitHub webhook
        repo_hooks = repo.hooks
        status, hooks_data = repo_hooks.get()
        hook_data = next(
            (
                x
                for x in hooks_data
                if x["name"] == "web" and x["config"].get("url") == hook_url
            ),
            None,
        )
        if hook_data is not None:
            status, hook_delete_result = repo_hooks[hook_data["id"]].delete()
            if status == 204:
                green_print(
                    f"  GitHub webhook {hook_data['id']} deleted from repo"
                    f" {repo_data['html_url']}"
                )
            else:
                raise Exception(f"GitHub webhook deletion failed {hook_delete_result}")

        # Delete hook.io env var github-webhook-secret-map entry
        status, env_vars = hook_io.env.get()
        repo_secret_map = env_vars.get("github-webhook-secret-map", {})
        if type(repo_secret_map) is not dict:
            repo_secret_map = json.loads(repo_secret_map)
        owner_repo_key = "/".join([owner_name, repo_name])
        if owner_repo_key in repo_secret_map:
            del repo_secret_map[owner_repo_key]
            update_hookio_env_vars(
                hook_io, {"github-webhook-secret-map": repo_secret_map}, env_vars
            )

    # Delete IAM user api key
    status, env_vars = hook_io.env.get()
    try:
        client_iam.delete_access_key(
            UserName=args.github_iam_username,
            AccessKeyId=env_vars.get("aws-access-key-id"),
        )
        green_print(
            f"Access key {env_vars.get('aws-access-key-id')} deleted from AWS IAM user"
            f" {args.github_iam_username}"
        )
    except Exception:
        pass

    # Delete hook.io env_var AWS API keys
    if "aws-access-key-id" in env_vars:
        update_hookio_env_vars(
            hook_io, {"aws-access-key-id": None, "aws-secret-access-key": None}
        )

    # Delete hook.io env_var AWS API keys
    if "sns-topic-arn" in env_vars:
        update_hookio_env_vars(hook_io, {"sns-topic-arn": None})

    # Delete hook.io service
    status, hook_io_services = hook_io[hook_io_user["user"]["name"]].post(
        body={"query": {"owner": hook_io_user["user"]["name"]}}
    )

    if args.hookio_service_name in [x["name"] for x in hook_io_services]:
        status, destroy_result = hook_io[hook_io_user["user"]["name"]][
            args.hookio_service_name
        ].delete.post(body={})
        green_print(
            "Deleted hook.io service"
            f" {hook_io_user['user']['name']}/{args.hookio_service_name}"
        )

    # Delete GitHub IAM user with inline policy
    try:

        response_iterator = client_iam.get_paginator("list_user_policies").paginate(
            UserName=args.github_iam_username
        )
        user_policy_names = [
            item
            for sublist in [x["PolicyNames"] for x in response_iterator]
            for item in sublist
        ]
        for policy_name in user_policy_names:
            client_iam.delete_user_policy(
                UserName=args.github_iam_username, PolicyName=policy_name
            )
            green_print(
                f"Deleted AWS IAM user {args.github_iam_username} user policy"
                f" {policy_name}"
            )

        client_iam.delete_user(UserName=args.github_iam_username)
        green_print(f"Deleted AWS IAM user {args.github_iam_username}")
    except Exception:
        pass

    # Delete SES Receipt rule
    client_ses = boto3.client("ses")
    response = client_ses.describe_receipt_rule_set(RuleSetName=args.ses_rule_set_name)
    if args.ses_rule_name in [x["Name"] for x in response["Rules"]]:
        client_ses.delete_receipt_rule(
            RuleSetName=args.ses_rule_set_name, RuleName=args.ses_rule_name
        )
        green_print(
            f"Deleted AWS SES rule {args.ses_rule_name} from rule set"
            f" {args.ses_rule_set_name}"
        )

    # Leave SES Rule Set in place
    print(f"Leaving AWS SES rule set {args.ses_rule_set_name} in place")

    def remove_lambda_permission(statement_id, function_name, policy):
        if policy is not None and statement_id in [
            x["Sid"] for x in json.loads(policy)["Statement"]
        ]:
            client_lambda.remove_permission(
                FunctionName=function_name, StatementId=statement_id
            )
            green_print(
                f"Removed permission {statement_id} from AWS Lambda function"
                f" {function_name}"
            )

    # Revoke SES permission to invoke Lambda
    try:
        response = client_lambda.get_policy(FunctionName=args.lambda_function_name)
        policy = response["Policy"]
    except Exception:
        policy = None

    remove_lambda_permission(
        "GiveSESPermissionToInvokeFunction", args.lambda_function_name, policy
    )

    # Revoke SNS permission to invoke Lambda
    remove_lambda_permission(
        "GiveGithubWebhookSNSTopicPermissionToInvokeFunction",
        args.lambda_function_name,
        policy,
    )

    # Delete Lambda Function
    try:
        response = client_lambda.get_function(FunctionName=args.lambda_function_name)
        response = client_lambda.delete_function(FunctionName=args.lambda_function_name)
        green_print(f"Deleted AWS Lambda function {args.lambda_function_name}")
    except ClientError:
        pass

    # Delete Lambda IAM role with inline policies
    try:
        response_iterator = client_iam.get_paginator("list_role_policies").paginate(
            RoleName=args.lambda_iam_role_name
        )
        role_policy_names = [
            item
            for sublist in [x["PolicyNames"] for x in response_iterator]
            for item in sublist
        ]
        for policy_name in role_policy_names:
            client_iam.delete_role_policy(
                RoleName=args.lambda_iam_role_name, PolicyName=policy_name
            )
            green_print(
                f"Deleted AWS IAM role {args.lambda_iam_role_name} role policy"
                f" {policy_name}"
            )

        client_iam.delete_role(RoleName=args.lambda_iam_role_name)
        green_print(f"Deleted AWS IAM role {args.lambda_iam_role_name}")
    except Exception:
        pass

    # Leave Lambda CloudWatch logs
    print(
        "Leaving AWS CloudWatch logs for AWS Lambda function"
        f" {args.lambda_function_name} as they are"
    )

    # for recipient in config['recipient_list']:
    #    Leave SES recipient domains in a verified state
    print("Leaving SES recipient domains in a verified state")

    # Leave SES account sending enabled
    print("Leaving SES account sending enabled")

    client_s3 = boto3.client("s3")
    # Delete S3 Lifecycle policies on S3 bucket DeleteSESEmailPayloadsAfter7Days
    # lifecycle_id = 'DeleteSESEmailPayloadsAfter7Days'
    # lifecycle_configuration = client_s3.get_bucket_lifecycle_configuration(
    #     Bucket=config['ses_payload_s3_bucket_name']
    # )
    # if lifecycle_id in [x['ID'] for x in lifecycle_configuration['Rules']]:
    #     lifecycle_configuration['Rules'] = [
    #         x for x in lifecycle_configuration['Rules']
    #         if x['ID'] != lifecycle_id]
    #     client_s3.put_bucket_lifecycle_configuration(
    #         Bucket=config['ses_payload_s3_bucket_name'],
    #         LifecycleConfiguration=lifecycle_configuration
    #     )
    #     print('Bucket lifecycle configuration for S3 bucket %s updated and '
    #           'rule %s removed' % (config['ses_payload_s3_bucket_name'],
    #                                lifecycle_id))
    print(
        "Leaving AWS S3 bucket lifecycle configuration for S3 bucket"
        f" {config['ses_payload_s3_bucket_name']} in place. Content will be deleted in"
        " 7 days"
    )

    # Revoke SES permission to write to S3 bucket
    # in bucket policy GiveSESPermissionToWriteEmail
    statement_id = "GiveSESPermissionToWriteEmail"
    try:
        response = client_s3.get_bucket_policy(
            Bucket=config["ses_payload_s3_bucket_name"]
        )
        policy = json.loads(response["Policy"])
    except Exception:
        policy = {"Version": "2008-10-17", "Statement": []}
    if statement_id in [x["Sid"] for x in policy["Statement"]]:
        policy["Statement"] = [
            x for x in policy["Statement"] if x["Sid"] != statement_id
        ]
        if len(policy["Statement"]) > 0:
            client_s3.put_bucket_policy(
                Bucket=config["ses_payload_s3_bucket_name"], Policy=json.dumps(policy)
            )
            green_print(
                f"AWS S3 Bucket policy updated and statement {statement_id} removed"
            )
        else:
            client_s3.delete_bucket_policy(Bucket=config["ses_payload_s3_bucket_name"])
            green_print("AWS S3 Bucket policy removed")

    # Leave S3 bucket in place
    print(f"Leaving AWS S3 Bucket {config['ses_payload_s3_bucket_name']} in place")

    # Leave S3 contents ses-payloads/
    print(
        "Leaving s3 files in place as the lifecycle configuration will take care of it"
    )

    # Delete Alert SNS topic
    client_sns = boto3.client("sns")

    if "alert_sns_topic_arn" in config:
        try:
            response = client_sns.get_topic_attributes(
                TopicArn=config["alert_sns_topic_arn"]
            )
            client_sns.delete_topic(TopicArn=config["alert_sns_topic_arn"])
            green_print(f"AWS SNS Topic {response['Attributes']['TopicArn']} deleted")
        except ClientError:
            pass

    # Delete SNS topic
    try:
        response = client_sns.get_topic_attributes(TopicArn=config["sns_topic_arn"])
        client_sns.delete_topic(TopicArn=config["sns_topic_arn"])
        green_print(f"AWS SNS Topic {response['Attributes']['TopicArn']} deleted")
    except ClientError:
        pass

    # Leave GitHub OAuth token
    print("Leaving GitHub OAuth token in place")


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Clean Birch Girder. This tool will delete a Birch Girder deployment,"
            " returning accounts back to a clean state"
        )
    )
    parser.add_argument(
        "--config",
        default="birch_girder/config.yaml",
        help="Location of config.yaml (defualt : birch_girder/config.yaml)",
    )
    parser.add_argument(
        "--lambda-function-name",
        default="birch-girder",
        help="Name of the AWS Lambda function (default: birch-girder)",
    )
    parser.add_argument(
        "--hookio-service-name",
        default="birch-girder-webhook",
        help="Name of the hook.io service (default: birch-girder-webhook)",
    )
    parser.add_argument(
        "--github-iam-username",
        default="github-sns-publisher",
        help=(
            "Name of the IAM user to be used by GitHub (default: github-sns-publisher)"
        ),
    )
    parser.add_argument(
        "--ses-rule-set-name",
        default="default-rule-set",
        help="Name of the SES ruleset (default: default-rule-set)",
    )
    parser.add_argument(
        "--ses-rule-name",
        default="birch-girder-rule",
        help="Name of the SES rule to create (default: birch-girder-rule)",
    )
    parser.add_argument(
        "--lambda-iam-role-name",
        default="birch-girder",
        help="Name of the IAM role to be used by Lambda (default: birch-girder)",
    )
    args = parser.parse_args()
    config = Config(args.config)

    clean(config, args)


if __name__ == "__main__":
    main()
