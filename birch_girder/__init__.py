#!/usr/local/bin/python
# -*- coding: utf-8 -*-

import json
import logging
import re
from datetime import datetime
from string import Template
import boto3
import github3  # https://github3py.readthedocs.io/en/master/
import yaml  # pip install PyYAML
from dateutil import tz  # sudo pip install python-dateutil
import email
from email_reply_parser import \
    EmailReplyParser  # pip install email_reply_parser
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

TIME_ZONE = tz.gettz('America/Los_Angeles')

# Example "Re: [examplecorp/support] Add myself to user list. (#2)"
# Example "Re" ": "
EMAIL_SUBJECT_PREFIX = re.compile(
    '([\[\(] *)?(RE?S?|FYI|RIF|I|FS|VB|RV|ENC|ODP|PD|YNT|ILT|SV|VS|VL|AW|WG|ΑΠ|ΣΧΕΤ|ΠΡΘ|תגובה|הועבר|主题|转发|FWD?) *([-:;)\]][ :;\])-]*|$)|\]+ *$',
    re.IGNORECASE)

# "[examplecorp/support] Add myself to user list. (#2)"
# "[examplecorp/support] Add myself to user list." "2"
EMAIL_SUBJECT_ISSUE_SUFFIX = re.compile(r'^(.*)\s+\(#([0-9]+)\)$')

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
ISSUE_TEMPLATE = Template('''<!--
$hidden_content_block
-->
| `$from_address` | 
| ----- | 

$body

$attachment_table
---

Note : To trigger sending an email comment back to `$from_address` include @$github_username in your comment.
<!--
$headers
-->''')
COMMENT_TEMPLATE = Template('''| `$from_address` | 
| ----- | 

$body

$comment_attachments
<!--
$headers
-->''')

SUBJECT_TEMPLATE = Template('$subject (#$issue_number)')
EMAIL_TEXT_TEMPLATE = Template('''##- Please type your reply above this line -##
$text_body

--------------------------------
This email is a service from $provider.









$issue_reference
''')
EMAIL_HTML_TEMPLATE = Template(
    '''<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    <html>
    <head>
      <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
      <style type="text/css">
        table td {
          border-collapse: collapse;
        }
        body[dir=rtl] .directional_text_wrapper { direction: rtl; unicode-bidi: embed; }
    
      </style>
    </head>
    <body  style="width: 100%!important; margin: 0; padding: 0;">
      <div style="padding: 10px ; line-height: 18px; font-family: 'Lucida Grande',Verdana,Arial,sans-serif; font-size: 12px; color:#444444;">
        <div style="color: #b5b5b5;">##- Please type your reply above this line -##</div>
         $html_body
        <div style="color: #aaaaaa; margin: 10px 0 14px 0; padding-top: 10px; border-top: 1px solid #eeeeee;">
         This email is a service from $provider.
        </div>
      </div>
    <span style="color:#FFFFFF">$issue_reference</span></body>
    </html>''')

CONTENT_PATTERN = r"""%s(.*)%s"""
DELIMITER_TAG = "----- %s -----"
HIDDEN_DELIMITER_TAG = "<!-- ----- %s ----- -->"
TAGS = {
    'hidden_content': DELIMITER_TAG % '%s ISSUE METADATA',
    'attachments': HIDDEN_DELIMITER_TAG % '%s ATTACHMENT TABLE'
}

RE_OBJECTS = {}
for block_name in TAGS:
    RE_OBJECTS[block_name] = re.compile(
        CONTENT_PATTERN % (TAGS[block_name] % 'BEGIN',
                           TAGS[block_name] % 'END'),
        re.MULTILINE | re.DOTALL)


def pst_time(secs):
    from_zone = tz.gettz('UTC')
    to_zone = TIME_ZONE
    utc = datetime.fromtimestamp(secs)
    utc = utc.replace(tzinfo=from_zone)
    pst = utc.astimezone(to_zone)
    return pst.timetuple()


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
if len(logging.getLogger().handlers) == 0:
    logger.addHandler(logging.StreamHandler())
logging.getLogger().setLevel(logging.INFO)
# fmt = "[%(levelname)s]   %(asctime)s.%(msecs)dZ  %(aws_request_id)s  %(message)s"
fmt = "[%(levelname)s] %(asctime)s %(message)s\n"
# datefmt = "%Y-%m-%dT%H:%M:%S"
datefmt = "%m/%d/%Y %H:%M:%S {}".format(TIME_ZONE.tzname(datetime.now()))
formatter = logging.Formatter(fmt=fmt, datefmt=datefmt)
formatter.converter = pst_time
logging.getLogger().handlers[0].setFormatter(formatter)

# Disable boto logging
logging.getLogger('boto3').setLevel(logging.CRITICAL)
logging.getLogger('botocore').setLevel(logging.CRITICAL)
logging.getLogger('requests').setLevel(logging.CRITICAL)
logging.getLogger('urllib3').setLevel(logging.CRITICAL)
logging.getLogger('github3').setLevel(logging.CRITICAL)


# TODO : See if this log suppression worked


def get_event_type(event):
    """Determine where an event originated from based on it's contents

    :param event: A dictionary of metadata for an event
    :return: Either the name of the source of the event or False if no
    source can be determined
    """
    if 'source' in event and event['source'] == 'aws.events':
        # CloudWatch Scheduled Event
        return 'cloudwatch'
    elif ('Records' in event and
                  type(event['Records']) == list and
                  len(event['Records']) > 0 and
                  type(event['Records'][0]) == dict):
        if ('eventSource' in event['Records'][0]
            and event['Records'][0]['eventSource'] == 'aws:ses'):
            # SES received email
            # Note the lower case 'eventSource'
            return 'ses'
        elif ('EventSource' in event['Records'][0]
              and event['Records'][0]['EventSource'] == 'aws:sns'):
            # SNS published message
            # Note the upper case 'EventSource'
            return 'sns'
    else:
        return False


def parse_hidden_content(body):
    """Parse the GitHub issue body, finding the hidden content within
    the TAGS delimiters. If none is found return False, otherwise
    attempt to parse the YAML contained within the delimiters. If
    successful return the data, if not return False

    :param str body: The GitHub issue body
    :return: A dictionary of data parsed from the content block
    """
    result = RE_OBJECTS['hidden_content'].search(body)
    if result is None:
        # hidden content is missing
        return False
    else:
        try:
            return yaml.safe_load(result.group(1))
        except:
            # Can't parse the hidden data
            return False


def get_content_block(name, data):
    """Given a content type and content, return a delimited block of
    content with the delimiters designated in the TAGS map.

    :param name:
    :param data:
    :return:
    """
    template = Template('''$begin
$data
$end''')
    return template.substitute(
        begin=TAGS[name] % 'BEGIN',
        data=data,
        end=TAGS[name] % 'END',
    )


def produce_attachment_table(attachments):
    """Given a dictionary of attachment filenames as keys and URLs as values
    generate and return a markdown table listing the attachment links

    :param dict attachments: Dict of attachment filenames and URLs
    :return: A string of a markdown table of attachment links
    """
    attachment_table = ''
    if len(attachments) > 0:
        attachment_table += '| Attachments |\n| --- |\n'
        attachment_table += '\n'.join(
            ['| [%s](%s) |' % (x, attachments[x])
             for x in attachments])
    return attachment_table


def send_email(email_subject, from_name, from_address, to_address,
               message_id, references, html, text):
    client = boto3.client('ses')
    msg = MIMEMultipart('alternative')
    msg['Subject'] = email_subject
    msg['From'] = (
        from_address if from_name is None
        else "%s <%s>" % (from_name, from_address))
    msg['To'] = to_address
    msg['In-Reply-To'] = message_id
    msg['References'] = references
    part1 = MIMEText(text, 'plain')
    part2 = MIMEText(html, 'html')
    msg.attach(part1)
    msg.attach(part2)
    return client.send_raw_email(
        Source=from_address,
        Destinations=[
            to_address,
        ],
        RawMessage={
            'Data': msg.as_string()
        }
    )


class EventHandler:
    def __init__(self, config, event, context):
        """

        :param config:
        :param event:
        :param context:
        """
        self.config = config
        self.event = event
        self.context = context
        self.gh = github3.login(token=self.config['github_token'])
        self.new_attachment_urls = {}
        self.email_body = ''

    def parse_email(self, email_string):
        """Parse a raw mime email into an email.message.Message object.
        Write any attachments into the github repo and add a link to those
        files to the new_attachment_urls dict.

        Add attachment links to self.new_attachment_urls
        Add the main body of the email to self.email_body

        :param str email_string: The raw email body
        :return: nothing
        """
        # TODO : Change to using pyzmail so that we can get the html body
        # instead of the text body (when available)
        # http://www.magiksys.net/pyzmail/
        email_message = email.message_from_string(email_string)
        self.email_body = "Unable to parse body from email"
        timestamp = email.utils.mktime_tz(
            email.utils.parsedate_tz(email_message['Date']))
        if email_message.is_multipart():
            for part in email_message.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get('Content-Disposition'))
                if ((content_type == 'text/plain') and
                        ('attachment' not in content_disposition)):
                    # We've found the body of the email
                    self.email_body = part.get_payload(decode=True)  # decode
                elif 'attachment' in content_disposition:
                    # We've found an attachment
                    filename = part.get_filename()
                    storage_filename = "%s-%s" % (
                        timestamp,
                        filename)
                    repo = self.gh.repository(self.config['github_owner'],
                                              self.config['github_repo'])
                    result = repo.create_file(
                        path='attachments/%s' % storage_filename,
                        message='Add attachment %s' % filename,
                        content=part.get_payload(decode=True)
                    )
                    html_url = result['content'].html_url
                    self.new_attachment_urls[filename] = html_url
        else:  # not multipart - i.e. plain text, no attachments
            self.email_body = email_message.get_payload(decode=True)

    def parse_subject(self, raw_subject):
        """Parse the raw email subject, stripping off the leading Re: and
        Fw:, extracting the GitHub issue number. If an issue number is found
        return it with the stripped subject, if not search the GitHub issues
        for a matching issue title. If one is found return the stripped subject
        and issue number, if not return the stripped subject and False.

        :param str raw_subject: The email subject
        :return: tuple (subject, issue_number)
        """
        stripped_subject = EMAIL_SUBJECT_PREFIX.sub(
            '', raw_subject).strip()
        match = EMAIL_SUBJECT_ISSUE_SUFFIX.match(stripped_subject)
        if match is not None:
            # The inbound email has an existing issue number in the subject
            # Add a comment to the issue
            subject, issue_number = match.groups()
            return subject, issue_number
        else:
            # The inbound email has no issue number in the subject
            # Search for an existing issue with a matching subject
            subject = stripped_subject

            gh_query = ""
            gh_query += "author:%s " % self.config['github_username']
            gh_query += "type:issue "
            gh_query += "repo:%s/%s " % (self.config['github_owner'],
                                         self.config['github_repo'])
            gh_query += "in:title \"%s\" " % subject
            gh_query += ("label:%s " % self.config['issue_label']
                         if 'issue_label' in self.config else "")
            results = self.gh.search_issues(gh_query)
            results_list = list(results)
            logger.log(
                logging.DEBUG,
                "Search triggered by inbound \"%s\" email yielded %s results" %
                (subject, len(results_list))
            )

            if len(results_list) == 0 or len(results_list) > 1:
                # No matching issue found or multiple matching issues found
                # Create a new issue
                return subject, False
            else:
                # One matching issue found but the subject didn't have an
                # issue number
                # Add a comment to the issue
                return subject, results_list[0].issue.number

    def get_email_payload(self, message_id):
        """Wait for an S3 object to exist with a filename of the email
        message_id. Once the object exists, fetch an return it.

        :param str message_id: The message_id of the email
        :return: The payload of the email message
        """
        s3 = boto3.client('s3')
        bucket = self.config['ses_payload_s3_bucket_name']
        prefix = self.config['ses_payload_s3_prefix']
        key = prefix + message_id
        logger.debug("Using waiter to wait for %s %s to persist through s3 "
                     "service" % (bucket, key))
        waiter = s3.get_waiter('object_exists')
        waiter.wait(Bucket=bucket, Key=key)
        response = s3.get_object(Bucket=bucket, Key=key)
        logger.debug("Fetched s3 object : %s" % response)
        return response['Body'].read()
        # We're not deleting the s3 object as it's taken care of by S3
        # lifecycle which automatically deletes old data

    def update_issue(self, body, message_id):
        """Parse the hidden content from the GitHub issue body, update it to
        reflect the newly added attachments and replace the hidden_content
        in the issue body with this updated content. Also update the
        existing table of attachments displayed in the issue or create a
        table if none exists. Return the updated body

        :param str body: The GitHub issue body
        :param str message_id: The RFC 2392 Message-ID of the most recent
        email in the thread related to this GitHub issue
        :return: The updated issue body
        """
        data = parse_hidden_content(body)
        if not data:
            self.alert(
                "While attempting to add new links to attachments '%s' we "
                "encountered a problem in that we couldn't parse the hidden "
                "content in the issue body. As a result we couldn't "
                "determine what the current list of attachments were and "
                "couldn't add these new attachment links to the table. "
                "Though this attachment has been saved to the repo at %s the "
                "issue has not been updated to reflect this" % (
                    self.new_attachment_urls.keys(),
                    self.new_attachment_urls.values()
                )
            )
            return body

        attachments = data.get('attachments', {})
        attachments.update(self.new_attachment_urls)
        if len(attachments) > 0 and len(self.new_attachment_urls) > 0:
            data['attachments'] = attachments
            body = RE_OBJECTS['attachments'].sub(
                get_content_block(
                    'attachments',
                    produce_attachment_table(attachments)
                ),
                body
            )

        data['message_id'] = message_id
        body = RE_OBJECTS['hidden_content'].sub(
            get_content_block(
                'hidden_content',
                yaml.safe_dump(data, default_flow_style=False)
            ),
            body
        )
        return body

    def alert(self, message=''):
        """Publish an alert to SNS

        :param str message: The message to send in the alert
        :return: Dictionary containing the MessageId of the published SNS
        message
        """
        if len(message) > 0:
            message += "\n"
        logger.error('Alerting on events %s' % self.event)
        message += json.dumps(self.event)
        message += "Log stream is : %s" % self.context.log_stream_name
        subject = 'Alert from Birch Girder'
        client = boto3.client(
            'sns', region_name=self.config['alert_sns_region'])
        return client.publish(
            TopicArn=self.config['alert_sns_topic_arn'],
            Message=message,
            Subject=subject
        )

    def process_event(self):
        """Determine event type and call the associated processor

        :return:
        """
        try:
            event_type = get_event_type(self.event)
            if event_type == 'ses':
                self.incoming_email()
            elif event_type == 'sns':
                self.github_hook()
            else:
                logger.error("Unable to determine message type from event "
                             "%s" % self.event)
        except Exception as e:
            self.alert("Uncaught exception thrown %s %s" % (e.__class__, e))
            raise

    def incoming_email(self):
        """When a new email is received by AWS SES, search the existing github
        issues for an issue where the title matches the email subject.
          * If none are found create a new issue
          * If more than one is found create a new issue because we don't know
            where to put the comment
          * If one is found, add a comment to the issue, re-opening the issue
            if it's been closed
        If a new issue is created, label it with the email address to which
        the email was sent or a value looked up from label value in the
        recipient_list and email the sender with a link to the issue.
        If the email has any attachments, save those attachments in the
        GitHub repo. If a new issue is created, add links to those
        attachments to the hidden content and attachment table in the issue
        body. If the issue already exists, add link to those attachments to
        the new comment on the issue and update the existing attachments
        table and hidden content to add the new attachment links.

        :return:
        """
        # https://gist.github.com/gene1wood/26fbae0e2388b02d6292
        # https://github3py.readthedocs.io/en/master/examples/oauth.html
        if len(self.event['Records']) > 1:
            raise Exception(
                "Multiple records from SES %s" % self.event['Records'])
        record = self.event['Records'][0]
        from_address = (
            record['ses']['mail']['commonHeaders']['from'][0]
            if len(record['ses']['mail']['commonHeaders']['from']) == 1
            else ', '.join(record['ses']['mail']['commonHeaders']['from']))
        message_id = record['ses']['mail']['commonHeaders']['messageId']
        to_address = False
        if len(record['ses']['mail']['commonHeaders']['to']) > 1:
            for possible_recipient in self.config['recipient_list']:
                # Assign the first matching address in recipient_list to
                # to_address
                # Note : It's possible we could determine the actual correct
                #  To address from record['ses']['receipt']['recipients']
                if possible_recipient in [
                    x.lower() for x
                    in record['ses']['mail']['destination']]:
                    to_address = possible_recipient
                    break
        else:
            to_address = record['ses']['mail']['destination'][0].lower()
        if not to_address:
            to_address = self.config['recipient_list'].keys()[0].lower()
            self.alert(
                "None of the 'To' addresses in '%s' were found in the"
                "recipient_list '%s'. As a result we're just going to assign"
                "%s as the 'To' address. This means that the ticket may have"
                "the wrong metadata in the GitHub issue hidden content and "
                "the reply email back to the submitter may come from a "
                "different email address than they sent the request to." % (
                    record['ses']['mail']['destination'],
                    self.config['recipient_list'].keys(),
                    to_address
                ))
        date = record['ses']['mail']['commonHeaders']['date']
        subject, issue_number = self.parse_subject(
            record['ses']['mail']['commonHeaders']['subject']
        )
        raw_body = self.get_email_payload(record['ses']['mail']['messageId'])

        self.parse_email(raw_body)
        stripped_reply = EmailReplyParser.parse_reply(self.email_body)
        logger.info(
            "Received an email from %s to %s with a message_id of %s. The "
            "subject is '%s' and issue number is %s" % (
                from_address,
                to_address,
                message_id,
                subject,
                issue_number
            ))

        if issue_number:
            # Add a comment to the existing issue
            issue = self.gh.issue(
                self.config['github_owner'],
                self.config['github_repo'],
                issue_number)
            if issue.is_closed():
                issue.reopen()

            if len(self.new_attachment_urls) > 0:
                comment_attachments = '''| Attachments |\n| --- |\n'''
                comment_attachments += '\n'.join(
                    ['| [%s](%s) |' % (x, self.new_attachment_urls[x])
                     for x in self.new_attachment_urls])
            else:
                comment_attachments = ''
            # TODO : I'll ignore the "References" header for now because I
            # don't know what AWS SES does with it
            issue.edit(body=self.update_issue(issue.body, message_id))

            comment_message = COMMENT_TEMPLATE.substitute(
                from_address=from_address,
                to_address=to_address,
                date=date,
                headers=json.dumps(record['ses']['mail']['headers']),
                body=stripped_reply,
                comment_attachments=comment_attachments)
            logger.info(
                "Adding a comment to the existing issue %s." % issue_number)
            issue.create_comment(comment_message)
        else:
            # Create new issue
            labels = ([self.config['issue_label']]
                      if 'issue_label' in self.config
                      else [])
            # Either label the issue with the label from the recipient_list or
            # just use the username of the email to_address
            labels.append(
                self.config['recipient_list'][to_address].get(
                    'label', to_address.split('@')[0]))

            email_metadata = {
                'from': from_address,
                'to': to_address,
                'date': date,
                'message_id': message_id
            }

            if len(self.new_attachment_urls) > 0:
                email_metadata['attachments'] = self.new_attachment_urls

            issue_message = ISSUE_TEMPLATE.substitute(
                hidden_content_block=get_content_block(
                    'hidden_content',
                    yaml.safe_dump(email_metadata, default_flow_style=False)),
                from_address=from_address,
                to_address=to_address,
                date=date,
                github_username=self.config['github_username'],
                headers=json.dumps(record['ses']['mail']['headers']),
                body=stripped_reply,
                attachment_table=get_content_block(
                    'attachments',
                    produce_attachment_table(self.new_attachment_urls)
                )
            )
            issue = self.gh.create_issue(
                self.config['github_owner'],
                self.config['github_repo'],
                subject,
                body=issue_message,
                labels=labels
            )
            logger.info(
                "Created new issue %s." % issue_number)
            body = (
                '''Thanks for contacting us. One of our members will get back to you as soon as
                possible. You can reply to this email if you have additional information to
                add to your request. If you are a member of the cooperative you can track this
                request here : %s''')
            text_url = 'https://github.com/%s/%s/issues/%s' % (
                self.config['github_owner'],
                self.config['github_repo'],
                issue.number
            )
            issue_reference = '%s/%s#%s' % (
                self.config['github_owner'],
                self.config['github_repo'],
                issue.number
            )
            html_url = '<a href="%s">%s</a>' % (
                text_url,
                issue_reference
            )
            email_subject = SUBJECT_TEMPLATE.substitute(
                subject=subject,
                issue_number=issue.number)

            # TODO : what do we do if the inbound email had CCs?

            logger.info(
                "Sending an email to %s confirming that a new issue has "
                "been created." % from_address)
            response = send_email(
                email_subject=email_subject,
                from_name=self.config['recipient_list'][to_address].get(
                    'name'),
                from_address=to_address,
                to_address=from_address,
                message_id=message_id,
                references=message_id,
                html=EMAIL_HTML_TEMPLATE.substitute(
                    html_body=body % html_url,
                    issue_reference=issue_reference,
                    provider=self.config['provider_name']),
                text=EMAIL_TEXT_TEMPLATE.substitute(
                    text_body=body % text_url,
                    issue_reference=issue_reference,
                    provider=self.config['provider_name']))

    def github_hook(self):
        """Process new GitHub issue comments.
        When a GitHub event occurs, GitHub generates an SNS notification
        using the configured AWS IAM User's API keys. That SNS notification
        in turn triggers this Lambda function which processes the event.

        This method looks at the GitHub event to determine :
        * if it's an "IssueCommentEvent" event
        * if the user that reported the issue is self.config['github_username']
        * if the user that commented is *not* self.config['github_username']
        * if the action is "created" (we won't email on comment editing or
          deletion
        * if the comment body contains an @mention of the bot name

        If these are all true then the issue was created via the
        incoming_email() method and as a result, this issue comment should
        trigger an new email be sent back to the email address that first
        caused the creation of the issue

        Parse the body of the issue to extract the From and To email
        addresses from the hidden content

        Formulate an email with the comment and send it to the From address
        with a reply-to of the To address

        https://developer.github.com/v3/activity/events/types/#issuecommentevent

        :return:
        """

        message = json.loads(self.event['Records'][0]['Sns']['Message'])
        mention = '@%s' % self.config['github_username']
        if ('action' not in message
            or message['action'] != 'created'
            or 'comment' not in message
            or 'issue' not in message
            or message['issue']['user']['login'] != self.config[
                'github_username']
            or message['comment']['user']['login'] == self.config[
                'github_username']
            or mention not in message['comment']['body']):
            # not a conforming message
            logger.info(
                "Received a GitHub event notification but it was not a "
                "conforming message so we're ignoring it.")
            return False

        # Read the hidden content
        data = parse_hidden_content(message['issue']['body'])
        if not data:
            self.alert(
                "Comment %s added to issue %s should have triggered sending "
                "an email back to the reporter of the issue but we can't "
                "determine who to send it to because the hidden content was "
                "either missing or couldn't be parsed. No email will be "
                "sent." % (
                    message['comment']['html_url'],
                    message['issue']['number'])
            )
            return False
        logger.info(
            "Received a GitHub event notification of a new issue comment.")

        # Create email
        subject = SUBJECT_TEMPLATE.substitute(
            subject=message['issue']['title'],
            issue_number=message['issue']['number'])
        author = message['comment']['user']['login']

        stripped_comment = re.sub(
            r'(^|\s)@%s($|\s)' % re.escape(self.config['github_username']),
            '',
            message['comment']['body'])

        text_email_body = "%s writes:\n%s" % (author, stripped_comment)

        html_comment = github3.markdown(
            stripped_comment,
            mode='gfm',
            context='%s/%s' % (
                self.config['github_owner'],
                self.config['github_repo'])
        )
        html_email_body = (
            '<a href="https://github.com/{username}">@{username}</a> writes :'
            '<br>\n{html_comment}'.format(username=author,
                                          html_comment=html_comment))

        issue_reference = '%s/%s#%s' % (
            self.config['github_owner'],
            self.config['github_repo'],
            message['issue']['number']
        )

        logger.info(
            "Sending an email notification to %s with the new issue "
            "comment." % data['from'])
        response = send_email(
            email_subject="Re: %s" % subject,
            from_name=self.config['recipient_list'][data['to']].get(
                'name'),
            from_address=data['to'],
            to_address=data['from'],
            message_id=data['message_id'],
            references=data['message_id'],
            html=EMAIL_HTML_TEMPLATE.substitute(
                html_body=html_email_body,
                issue_reference=issue_reference,
                provider=self.config['provider_name']),
            text=EMAIL_TEXT_TEMPLATE.substitute(
                text_body=text_email_body,
                issue_reference=issue_reference,
                provider=self.config['provider_name']))

        self.update_issue(message['issue']['body'], response['MessageId'])

        # TODO : Rename the project to something catchy. Birch Girder?

        # TODO : Rewrite readme from scratch

        # TODO : Test everything

        # TODO : Add a visual cue to the comment to indicate it's been sent
        # as an email. For example a heart "reaction"

        # TODO : create a list of configurable senders who are blacklisted
        # from getting the initial email reply with the issue number. This
        # is for senders that are computers not humans

        # TODO : fix this : user emails the system, system adds comment to
        # issue, system emails user with new comment (which they just wrote)

        # TODO : What about a random person just adding a (#123) to their
        # email subject and injecting their email into an existing ticket.
        # Maybe we should be using in-reply-to to map emails to tickets

        # TODO : Add plugable transformers to take inbound emails and
        # transform the subject line

        # I'm keeping creds in config.yaml which seems like a bad idea,
        # I should move that to credstash, hmm but that requires a kms key
        # which isn't free. Ah well
        #
        # Next : update manage.py to add a package and upload lambda
        # function step. run that to upload the function. Also that manage
        # step should wire it into the SNS topic
        #
        # Also add to the description the fact that you have to @mention the
        #  bot in a comment to trigger an email to the person who opened the
        #  issue via email


def lambda_handler(event, context):
    """
    Given an event determine if it's and incoming email or an SNS webhook alert
    and trigger the appropriate method

    :param event: A dictionary of metadata for an event
    :param context: The AWS Lambda context object
    :return: A list of checks which resulted in failures
    """
    logger.debug('got event {}'.format(event))
    with open('config.yaml') as f:
        config = yaml.load(f.read())
    handler = EventHandler(config, event, context)
    handler.process_event()


def main():
    """
    Run monitor for two example rules

    :return:
    """
    event = {
        'resources':
            [
                'arn:aws:events:us-west-2:123456789123:rule/AWSLambdaMonitor5Minutes',
                'arn:aws:events:us-west-2:123456789123:rule/AWSLambdaMonitorDaily']}
    context = type('context', (), {'log_stream_name': None})()
    lambda_handler(event, context)


if __name__ == '__main__':
    main()
