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

## Setup email received flow
* An S3 bucket to temporarily store the SES email payloads. Configure the bucket
  name in `connector.yaml` in the `ses_payload_s3_bucket_name` field.
  * `manage.py:create_s3_bucket()`
* An S3 bucket policy that grants [SES rights to write to the bucket](http://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-permissions.html).
  * `manage.py:create_s3_bucket()`
* An S3 bucket lifecycle policy to automatically delete email payloads from the
  bucket after a few days.
  * `manage.py:create_s3_bucket()`
* A GitHub repository that you want to have Birch Girder create
  issues in.
* A DNS zone or name created at which email will be received
* An IAM Role to be used by the birch_girder lambda function. 
  * `manage.py:create_iam_role(config, iam_rolename)`
* A Lambda function containing the birch-girder code
  * `manage.py:deploy_to_lambda()` is not completed yet, instead follow instructions in `docs/build-and-upload-birch-girder.rst`.
* A Lambda Policy for the Lambda function that  
  [grants SES permission to invoke the function](http://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-permissions.html)
  and [grants SNS permission to invoke the function](http://docs.aws.amazon.com/lambda/latest/dg/with-sns-create-x-account-permissions.html)
  via Lambda AddPermission calls.
  * `manage.py:grant_lambda_policy_permissions(config, lambda_function_arn, topic)`
* An SES receipt rule set containing an SES receipt rule that
  * S3Action to deposit the received email payload in the S3 bucket created above
  * LambdaAction to trigger the aws-ses-connector lambda function
  * `manage.py:setup_ses(config, lambda_function_arn)`
* Activate the SES rule set created
  * `manage.py:setup_ses(config, lambda_function_arn)`

## Setup issue comment flow
* An SNS topic to receive notifications from GitHub integration/service.
  Configure this in `connector.yaml` in the `sns_topic_arn` and `sns_region`
  fields
  * `manage.py:create_sns_topic()`
* An IAM user to be used by GitHub to `Publish` notifications to the SNS topic.
  This user needs to have `sns:Publish` permissions on the SNS topic.
  * `manage.py:create_github_iam_user(sns_topic_arn, iam_username)`
* An API key pair for the IAM user. This key pair is configured in the GitHub
  integration/service settings
  * `manage.py:create_github_iam_user(sns_topic_arn, iam_username)`
* A GitHub integration/service of type "Amazon SNS" configured on that
  repository that tells GitHub to publish a notification to the SNS topic
  you've created each time something happens in that repository.
* An added webhook for the IssueComment event type on the Amazon SNS service
  * `manage.py:edit_github_webhook(config, repo_owner, repo_name)`
* An SNS topic subscription, subscribing the aws-ses-github-connector lambda
  to the SNS topic above
  * `manage.py:subscribe_lambda_to_sns_topic(topic, lambda_arn)`
