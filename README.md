# Birch Girder

An Email Interface for GitHub Issues

# Overview

Birch Girder adds an email interface to your GitHub repo's issues. It allows
people without a GitHub account to open new issues by sending an email and
enables GitHub users to reply to those people via email by leaving comments
in a GitHub issue.

This let's you use GitHub issues as your customer service help desk software
for free (as in beer).

# What do you need

* A free GitHub user account
* A free Amazon Web Services (AWS) account. This requires giving AWS a credit
  card but as long as you send and receive 1000 emails or less per month it's
  free ([$0.10 for every additional 1000 emails](https://aws.amazon.com/ses/pricing/))

Notably you don't need a server to run Birch Girder.

# Features

* Receive inbound email and create a new GitHub issue based on the content of
  the email
* Store email attachments in GitHub and reference them in the issue
* Enable people to send email replies to their initial email to add comments
  to the GitHub issue
* Send email replies when a GitHub user comments in an issue
* Allow issue comments which *do not* trigger an email reply

# Diagram

![Birch Girder Diagram](https://raw.githubusercontent.com/gene1wood/birch-girder/master/docs/birch-girder-diagram.png)

<!--

    digraph G {
      "user@example.com" -> "support@example.com" [ label = "SMTP", color="0.650 0.700 0.700" ]
      "support@example.com" -> "SES" [ color="0.650 0.700 0.700" ]
      "SES" -> "S3:mybucket" [ color="0.650 0.700 0.700" ]
      "SES" -> "Lambda:birch-girder" [ color="0.650 0.700 0.700" ]
      "Lambda:birch-girder" -> "S3:mybucket" [ color="0.650 0.700 0.700" ]
      "Lambda:birch-girder" -> "GitHub Issue 123" [ label = "GitHub API v3", color="0.650 0.700 0.700" ]
      "GitHub Issue 123" -> "SNS:GithubIssueCommentWebhookTopic" [ label = "sns:Publish\nIssueCommentEvent", color="0.348 0.839 0.839" ]
      "SNS:GithubIssueCommentWebhookTopic" -> "Lambda:birch-girder" [ color="0.348 0.839 0.839" ]
      "Lambda:birch-girder" -> "SES" [ color="0.348 0.839 0.839" ]
      "SES" ->  "user@example.com" [ label = "SMTP" , color="0.348 0.839 0.839" ]
      "support tech" -> "GitHub Issue 123" [ label = "add issue\ncomment", color="0.348 0.839 0.839" ]
      { rank=same; "support@example.com"; "user@example.com"; }
      { rank=same; "support tech"; "SNS:GithubIssueCommentWebhookTopic"; }
    }

-->

# Flows

## Email received flow

* A user sends an email to support@example.com, one of the email addresses
  in the `recipient_list` in `config.yaml`
* That email is delivered to AWS SES
* AWS SES follows the rule in the rule set that says to save the email body
  into an S3 bucket and to trigger the Birch Girder AWS Lambda function
* The Lambda function runs and
  * Fetches the email payload from S3
  * Looks and sees that the email is a reply to an existing issue
    * If it is not a reply and is instead a new issue
      * Calls the GitHub API and creates a new GitHub issue with the content of the email
      * Calls AWS SES to send an email response back to the user acknowledging reciept of their email
    * Otherwise if it is a reply to an existing issue
      * Calls the GitHub API and adds a comment to the existing GitHub issue

Additionally if the email contains attachments, those attachments will be committed
to the git repo and added by link to the issue comment as well as to a table
in the body of the issue.

## Issue comment flow

### Private comment

* A support tech sees that there's a new GitHub issue that's been
  created from an email sent in by a user
* The support tech adds a comment to the issue that they don't wish to trigger
  an email to the user
* GitHub's webhook sees the new comment and calls AWS SNS using the configured
  AWS IAM user with the details about the new comment
* The Birch Girder AWS Lambda function, which subscribes to the SNS topic which
  GitHub just published to, gets the new SNS notification from GitHub
* The Lambda function parses the information and sees that the comment did not
  contain the reserved mention word indicating that it is a reply to the user.
  As a result the Lambda function ignores the new comment.

### Reply comment

* A support tech decides to ask the user some questions about their issue
  so they add a comment to the GitHub issue and include somewhere in the
  comment the reserved mention word. This is the `@` at sign followed by
  the `github_username` configured in Birch Girder, for example `@hubot`
* GitHub's webhook sees the new comment and calls AWS SNS using the configured
  AWS IAM user with the details about the new comment
* The Birch Girder AWS Lambda function, which subscribes to the SNS topic which
  GitHub just published to, gets the new SNS notification from GitHub
* The Lambda function parses the information and sees that the comment
  included the reserved mention word and was an issue originally created from
  an email submitted by a user. As a result the Lambda function will send
  the comment to the user as an email reply.
* The Lambda function calls AWS SES with the email reply to send to the user

# Get it

The process to deploy Birch Girder in your GitHub and AWS account is currently
a mix of manual steps and commands run with the `manage.py` tool

```
./manage.py generate-github-token
```

* Add the github_token returned to config.yaml
* Fill out all remaining fields in config.yaml

```
./manage.py create-github-repo
    Created GitHub repo https://github.com/octocat/Spoon-Knife
./manage.py create-bucket
    Bucket http://examplebucket.s3.amazonaws.com/ created
    Bucket policy for examplebucket created
    Bucket lifecycle configuration for examplebucket applied to bucket
```

* Verify a DNS domain with Amazon SES

```
./manage.py create-lambda-iam-role
    Creating role birch-girder
    Attaching policy SNSPublisher
    Attaching policy S3Reader
    Attaching policy LambdaBasicExecution
    Attaching policy SESSender
```

* Zip and deploy AWS Lambda function

```
./manage.py grant-lambda-policy-permissions --lambda-function-arn arn:aws:lambda:us-west-2:123456789012:function:birch-girder
    Permission GiveSESPermissionToInvokeFunction added : {"Sid":"GiveSESPermissionToInvokeFunction","Effect":"Allow","Principal":{"Service":"ses.amazonaws.com"},"Action":"lambda:InvokeFunction","Resource":"arn:aws:lambda:us-west-2:123456789012:function:birch-girder","Condition":{"StringEquals":{"AWS:SourceAccount":"123456789012"}}}
    Permission GiveBirchGirderSNSTopicPermissionToInvokeFunction added : {"Sid":"GiveBirchGirderSNSTopicPermissionToInvokeFunction","Effect":"Allow","Principal":{"Service":"sns.amazonaws.com"},"Action":"lambda:InvokeFunction","Resource":"arn:aws:lambda:us-west-2:BirchGirderAlerts:function:birch-girder","Condition":{"ArnLike":{"AWS:SourceArn":"arn:aws:sns:us-west-2:123456789012:GithubIssueCommentWebhookTopic"}}}
    Permission GiveBirchGirderAlertSNSTopicPermissionToInvokeFunction added : {"Sid":"GiveBirchGirderAlertSNSTopicPermissionToInvokeFunction","Effect":"Allow","Principal":{"Service":"sns.amazonaws.com"},"Action":"lambda:InvokeFunction","Resource":"arn:aws:lambda:us-west-2:BirchGirderAlerts:function:birch-girder","Condition":{"ArnLike":{"AWS:SourceArn":"arn:aws:sns:us-west-2:123456789012:BirchGirderAlerts"}}}
./manage.py setup-ses --lambda-function-arn arn:aws:lambda:us-west-2:123456789012:function:birch-girder
    SES Rule Set birch-girder-ruleset created
    SES Rule birch-girder-rule created in Rule Set
    SES Rule Set birch-girder-ruleset set as active
./manage.py create-sns-topic
    Topic ARN : arn:aws:sns:us-west-2:123456789012:GithubIssueCommentWebhookTopic
./manage.py create-github-iam-user --github-iam-user staging-github-sns-publisher
    AccessKeyId :  AKIAIOSFODNN7EXAMPLE
    SecretAccessKey :  wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

* Setup the GitHub integration with AWS SNS in the GitHub web UI (instructions below)

```
./manage.py configure-github-webhook
    GitHub webook "amazonsns" on repo https://github.com/octocat/Spoon-Knife configured to trigger on [u'issue_comment']
./manage.py subscribe-lambda-to-sns --lambda-function-arn arn:aws:lambda:us-west-2:123456789012:function:birch-girder
    Subscription ARN : arn:aws:sns:us-west-2:123456789012:GithubIssueCommentWebhookTopic:e4c5eb60-b40d-4bf2-aa33-07d74ab81856
```

## Setup config

Create a `config.yaml` file looking like [`example.config.yaml`](https://github.com/gene1wood/birch-girder/tree/master/birch_girder/config.example.yaml)


* `sns_topic_arn` : Replace `123456789012` with your AWS account number which
  you can get by running `aws sts get-caller-identity --output text --query 'Account'`
* `sns_region` : Choose the [AWS region](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html#concepts-available-regions)
  that you want your SNS topic and SES to operate in
* `github_token` : Generate a GitHub token by running
  `./manage.py generate-github-token`. Use the GitHub user that you want to
  comment in GitHub issues
* `github_username` : The GitHub username of the user you used to create the
  `github_token`
* `github_owner` : The GitHub username of the GitHub repo owner
* `github_repo` : The GitHub repo name
* `ses_payload_s3_bucket_name` : The name of the S3 bucket to use
* `ses_payload_s3_prefix` : The directory prefix in the S3 bucket to temporarily
  put all SES email payloads in
* `alert_sns_region` : Choose the [AWS region](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html#concepts-available-regions)
  that you want your alert SNS topic to run in
* `alert_sns_topic_arn` : Replace `123456789012` with your AWS account number
  which you can get by running `aws sts get-caller-identity --output text --query 'Account'`
* `provider_name` : The name of the service provider that Birch Girder is
  accepting emails for. This shows up in the footer of emails from Birch Girder
* `initial_email_reply` : The text in the initial email response Birch Girder
  sends back to a user when they email a new request that generates a GitHub
  issue
* `known_machine_senders` : List of email addresses for which no initial email
  reply should be sent. These are email addresses of senders that are other
  ticketing systems or automated (non-human)
* `recipient_list` : A list of email addresses at which you want to receive
  inbound emails that will trigger the creation of GitHub issues.
  * `label` : For each recipient, the [GitHub label](https://help.github.com/articles/about-labels/)
    to apply to issues generated for that recipient
  * `name` : The name to put in the `From` field of emails sent back to users
    from this recipient

## Setup email received flow
* A GitHub repository that you want to have Birch Girder create
  issues in.
* An S3 bucket to temporarily store the SES email payloads. Configure the bucket
  name in `connector.yaml` in the `ses_payload_s3_bucket_name` field.
  * `manage.py:create_s3_bucket()`
* An S3 bucket policy that grants [SES rights to write to the bucket](http://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-permissions.html).
  * `manage.py:create_s3_bucket()`
* An S3 bucket lifecycle policy to automatically delete email payloads from the
  bucket after a few days.
  * `manage.py:create_s3_bucket()`
* A DNS zone or name created at which email will be received. This zone or
  email address must go through the [SES domain verification process](https://us-west-2.console.aws.amazon.com/ses/home?region=us-west-2#verified-senders-domain:)
  before use and have the needed `_amazonses.example.com` and
  `_domainkey.example.com` DNS records created as well as an SPF record 
* An IAM Role to be used by the birch_girder lambda function. 
  * `manage.py:create_iam_role(config, lambda_iam_role_name)`
* A Lambda function containing the birch-girder code
  * `manage.py:deploy_to_lambda()` is not completed yet, instead follow instructions in `docs/build-and-upload-birch-girder.rst`.
* A Lambda Policy for the Lambda function that  
  [grants SES permission to invoke the function](http://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-permissions.html)
  and [grants SNS permission to invoke the function](http://docs.aws.amazon.com/lambda/latest/dg/with-sns-create-x-account-permissions.html)
  via Lambda AddPermission calls.
  * `manage.py:grant_lambda_policy_permissions(config, lambda_function_arn)`
* An SES receipt rule set containing an SES receipt rule that
  * S3Action to deposit the received email payload in the S3 bucket created above
  * LambdaAction to trigger the Birch Girder lambda function
  * `manage.py:setup_ses(config, lambda_function_arn)`
* Activate the SES rule set created
  * `manage.py:setup_ses(config, lambda_function_arn)`

## Setup issue comment flow
* An SNS topic to receive notifications from GitHub integration/service.
  Configure this in `config.yaml` in the `sns_topic_arn` and `sns_region`
  fields
  * `manage.py:create_sns_topic()`
* An IAM user to be used by GitHub to `Publish` notifications to the SNS topic.
  This user needs to have `sns:Publish` permissions on the SNS topic.
  * `manage.py:create_github_iam_user(config, iam_username)`
* An API key pair for the IAM user. This key pair is configured in the GitHub
  integration/service settings
  * `manage.py:create_github_iam_user(config, iam_username)`
* A GitHub integration/service of type "Amazon SNS" configured on that
  repository that tells GitHub to publish a notification to the SNS topic
  you've created each time something happens in that repository.
  * Browse to your GitHub repo... `Settings`... [`Integrations & services`](https://github.com/iocoop/birch-girder-test-issue-repo/settings/installations)
  * Click Add Service and search for `Amazon SNS`
  * Enter the `AccessKeyId` obtained in the create-github-iam-user step into the `Aws key` field
  * Enter the `sns_topic_arn` from config.yaml into the `Sns topic` field
  * Enter the `sns_region` from config.yaml into the `Sns region` field
  * Enter the `SecretAccessKey` obtained in the create-github-iam-user step into the `Aws secret` field
  * Click `Add Service`
* An added webhook for the IssueComment event type on the Amazon SNS service
  * `manage.py:configure_github_webhook(config, repo_owner, repo_name)`
* An SNS topic subscription, subscribing the Birch Girder lambda function
  to the SNS topic above
  * `manage.py:subscribe_lambda_to_sns_topic(config, lambda_arn)`

# Usage

## How to replay an email

If something goes wrong with Birch Girder or a plugin and you want to replay an
email you've already received so that it will be processed again and a new
issue will be created, you can send an event to the lambda function in the
format below passing the message ID of the email you want to replay.

You may want to rename the existing GitHub issue to avoid conflicts.


```json
{
  "replay-email": "nvk908umpjst57s3er4or1e4usb7b0pr0vh72jo1"
}
```