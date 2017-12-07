# Birch Girder

An Email Interface for GitHub Issues

# Overview

Birch Girder adds an email interface to your GitHub repo's issues. It allows
people without a GitHub account to open new GitHub issues by sending an email
and enables GitHub users to reply to those people via email by leaving comments
in a GitHub issue.

This let's you use GitHub issues as your customer service help desk software
for free (as in beer).

# What do you need

* A free GitHub user account
* A free Amazon Web Services (AWS) account. This requires giving AWS a credit
  card but as long as you send and receive 1000 emails or less per month it's
  free ([$0.10 for every additional 1000 emails](https://aws.amazon.com/ses/pricing/))
* A domain name for which you can have all email destined to addresses in that
  domain, sent to AWS. This can be a subdomain of an existing domain. If you have
  no domain name you can [buy one from AWS for $9/year](http://docs.aws.amazon.com/Route53/latest/DeveloperGuide/domain-register.html)
  or from other registrars for a couple bucks a year.

Notably you don't need a server to run Birch Girder.

# Features

* Receive inbound email and create a new GitHub issue based on the content of
  the email
* Store email attachments in GitHub and reference them in the issue
* Enable people to send email replies to their initial email to add comments
  to the GitHub issue
* Send email replies when a GitHub user comments in an issue
* Allow issue comments which *do not* trigger an email reply

# How to deploy Birch Girder

## Initial deployment

```Shell
$ ./deploy.py
```

```text
No recipient_list in config. Continuing with setup but not
setting up any recipients. Later, configure recipients in the config and run
deploy again.

Provider Name
Your provider name is the name of your organization to be displayed in the
suffix of emails sent.
Example : Example Corporation
Enter the provider name :
```

> Example Corporation

```text
AWS S3 Bucket Name
This will be the name of the AWS S3 bucket that stores, temporarily, the
inbound email body. AWS S3 bucket names must be unique across all AWS accounts
in the world, so you'll have to pick a bucket name.
Example : birch-girder-example-corporation
Enter the AWS S3 bucket name:
```

> birch-girder-example-corporation

```text
GitHub Username
What GitHub user would you like Birch Girder to act as. This user needs access
to all repos which you'd like Birch Girder to manage.
Enter the GitHub username :
```

> octocat

```text
Setting ses_payload_s3_prefix to default of ses-payloads/
Setting sns_topic to default of GithubWebhookTopic

GitHub user password
We'll use this password to generate a GitHub
authorization token that Birch Girder will use to interact with GitHub
Enter the GitHub password for octocat:
```

> password


```
Enter 2FA code:
```

> 123456

```
GitHub OAuth Token (github_token) created : 0123456789abcdef0123456789abcdef01234567
No alert_sns_topic in config so no alert topic will be setup.
You can add an alert topic to config later and re-run deploy if you would like
an SNS topic created that internal Birch Girder errors will be sent to.
Bucket http://birch-girder-example-corporation.s3.amazonaws.com/ created
Bucket policy for birch-girder-example-corporation created
Bucket lifecycle configuration for birch-girder-example-corporation applied to bucket
Lambda function created : arn:aws:lambda:us-west-2:012345678901:function:birch-girder
Permission GiveSESPermissionToInvokeFunction added
Permission GiveGithubWebhookSNSTopicPermissionToInvokeFunction added
SES Rule birch-girder-rule created in Rule Set
IAM user github-sns-publisher created
IAM policy PublishToGithubWebhookSNSTopic applied to user github-sns-publisher
Birch Girder subscribed to GitHub Webhook SNS Topic  : arn:aws:sns:us-west-2:012345678901:GithubWebhookTopic:01234567-89ab-cdef-0123-456789abcdef
```

## Add recipients

Now that Birch Girder is setup, you'll want to configure email recipients and
associate them with GitHub repositories. This is done by adding recipients to
your `config.yaml` file.

```yaml
recipient_list:
  finance@support.example.com:
    owner: example-corp
    repo: finance
  techsupport@support.example.com:
    owner: example-corp
    repo: techsupport
```

Create a `recipient_list` mapping recipient email addresses to GitHub
repositories.

You can also define a `name` with the email sender name to use, for example

```yaml
recipient_list:
  finance@support.example.com:
    owner: example-corp
    repo: finance
    name: Example Corp Finance Department
```

Would result in emails coming from `Example Corp Finance Department <finance@support.example.com>`

Once you have your recipients added to your config, run `deploy.py` again

```shell
$ ./deploy.py
```

```
Recipient finance@support.example.com verification hasn't been initiated in AWS SES
Would you like to verify the email address finance@support.example.com or the domain support.example.com [email/domain]:
```

> domain

```text
Would you like to host the zone support.example.com in route53 (for $0.50/month) or on your own [route53/myself]:
```

> myself

```text
Verification of support.example.com initiated

To verify this domain create a DNS record in the support.example.com domain with the 
name "_amazonses.support.example.com" and the value "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG="

The record in the example.com zone would look like this:

_amazonses.support    IN    TXT    "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG="

Create an DNS SPF record so email that Amazon sends from the email address
finance@support.example.com is considered to not be spam.
The record in the example.com zone would look like this:

support    IN    TXT    "v=spf1 include:amazonses.com -all"

Create DNS DKIM CNAME records so that Amazon can sign email sent from
finance@support.example.com to further ensure it isn't considered spam.
The records in the example.com zone would look like this:

2huz4qkplcqbkrt7if5vrni7tieag2l5._domainkey.support    IN    CNAME    abcdefghijklmnopqrstuvwxyz012345.dkim.amazonses.com.
anafzfmcwku4adkux7ifzi4wokvcpywc._domainkey.support    IN    CNAME    6789ABCDEFGHIJKLMNOPQRSTUVWXYZab.dkim.amazonses.com.
2lbcro7jkqtc3o2ng34aip5amz3ogczr._domainkey.support    IN    CNAME    cdefghijklmnopqrstuvwxyz01234567.dkim.amazonses.com.

Create a DNS MX record so inbound email destined for support.example.com is
delivered to AWS SES. The MX record in the example.com zone would look like this:

support    IN    MX    10    inbound-smtp.us-west-2.amazonaws.com.

Aborting while you complete email/domain verifications. Run this again when they're complete
```

## Verify DNS domains

Follow the instructions returned and add the required DNS entries into the
nameservers for your domain name.

Once all the DNS records have been added, run `deploy.py` again

## Finish enabling recipients

```shell
$ ./deploy.py
```

```text
Lambda function updated : arn:aws:lambda:us-west-2:012345678901:function:birch-girder
Created GitHub repo https://github.com/example-corp/finance
Created new Access Key for IAM user github-sns-publisher : ABCDEFGHIJKLMNOPQRST
New amazonsns webhook installed in https://github.com/example-corp/finance with user access key ABCDEFGHIJKLMNOPQRST
GitHub webook "amazonsns" on repo https://github.com/example-corp/finance configured to trigger on [u'push', u'issue_comment']
```

## Test your new deployment

1. Send an email to the recipient you've setup, in our example `finance@support.example.com`
2. Go check if a new issue is created in the associated repository, in our
   example https://github.com/example-corp/finance
3. Confirm that you received a response email acknowledging reciept of your
   email. In our example it would be sent by `Example Corp Finance Department <finance@support.example.com>`
4. In the newly created GitHub issue, add a comment and mention in the comment
   the GitHub user that Birch Girder is running as, in our example `octocat`.
   Add the mention by putting in the comment the username prepended with the `@`
   symbol. For example we'd add a line saying `@octocat`
5. Check your email to see that you received an email with this new comment.

## What if something goes wrong

If you encounter a problem you can fix it and just re-run `deploy.py`. It can
be run as many times as you want as each time is just attempts to converge your
deployed setup in GitHub and AWS with what you've defined in your `config.yaml`
MX 
# Usage

## Create a new issue

Send an email to any email in the `recipient_list` and that email will be added
as an issue to the repository associated with the email address in the
`recipient_list`

## Reply to the requestor from a GitHub ticket

Add a comment in a GitHub issue created by Birch Girder and include in the
comment somewhere an `@` mention of the Birch Girder GitHub user. For example
after your comment add a line that says `@octocat` if the GitHub user that
Birch Girder is configured to use was `octocat`

## Add comments to a ticket via email

The original requestor can reply to the initial reply email that they received
or any other emails from Birch Girder and their reply will be incorporated
into the ticket they're replying to as a comment.

## Attachments

Any email sent to Birch Girder can have attachments. Those attachments are
stored in the associated GitHub repository and referenced in the issue.

## Replay an email

If something goes wrong with Birch Girder or a plugin and you want to replay an
email you've already received so that it will be processed again and a new
issue will be created, you can send an event to the lambda function in the
format below passing the message ID of the email you want to replay.

You may want to rename the existing GitHub issue lest your replay be added
as a comment to the existing issue.


```json
{
  "replay-email": "nvk908umpjst57s3er4or1e4usb7b0pr0vh72jo1"
}
```

# How does it work?

## Diagram

![Birch Girder Diagram](https://raw.githubusercontent.com/gene1wood/birch-girder/master/docs/birch-girder-diagram.png)

<!--

    digraph G {
      "user@example.com" -> "support@example.com" [ label = "SMTP", color="0.650 0.700 0.700" ]
      "support@example.com" -> "SES" [ color="0.650 0.700 0.700" ]
      "SES" -> "S3:mybucket" [ color="0.650 0.700 0.700" ]
      "SES" -> "Lambda:birch-girder" [ color="0.650 0.700 0.700" ]
      "Lambda:birch-girder" -> "S3:mybucket" [ color="0.650 0.700 0.700" ]
      "Lambda:birch-girder" -> "GitHub Issue 123" [ label = "GitHub API v3", color="0.650 0.700 0.700" ]
      "GitHub Issue 123" -> "SNS:GithubWebhookTopic" [ label = "sns:Publish\nIssueCommentEvent", color="0.348 0.839 0.839" ]
      "SNS:GithubWebhookTopic" -> "Lambda:birch-girder" [ color="0.348 0.839 0.839" ]
      "Lambda:birch-girder" -> "SES" [ color="0.348 0.839 0.839" ]
      "SES" ->  "user@example.com" [ label = "SMTP" , color="0.348 0.839 0.839" ]
      "support tech" -> "GitHub Issue 123" [ label = "add issue\ncomment", color="0.348 0.839 0.839" ]
      { rank=same; "support@example.com"; "user@example.com"; }
      { rank=same; "support tech"; "SNS:GithubWebhookTopic"; }
    }

-->

## Flows

### Email received flow

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

### Issue comment flow

#### Private comment

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

#### Reply comment

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
