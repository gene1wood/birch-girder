#!/usr/bin/python
# -*- coding: utf-8 -*-

import base64
import email.utils
import glob
import importlib
import json
import logging
import os.path
import re
import traceback
import urllib.parse

from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from string import Template

import boto3  # pip install boto3
import bs4  # pip install beautifulsoup4
import pyzmail  # pip install pyzmail36
import yaml  # pip install PyYAML
from agithub.GitHub import GitHub  # pypi install agithub
from dateutil import tz  # sudo pip install python-dateutil
from email_reply_parser \
    import EmailReplyParser  # pip install email_reply_parser

TIME_ZONE = tz.gettz('America/Los_Angeles')

# Example "Re: [examplecorp/support] Add myself to user list. (#2)"
# https://stackoverflow.com/questions/9153629/regex-code-for-removing-fwd-re-etc-from-email-subject/11640925#comment81160171_11640925
EMAIL_SUBJECT_PREFIX = re.compile(
    r'^([\[(] *)?(RE?S?|FYI|RIF|I|FS|VB|RV|ENC|ODP|PD|YNT'
    r'|ILT|SV|VS|VL|AW|WG|ΑΠ|ΣΧΕΤ|ΠΡΘ|תגובה|הועבר|主题|转发|FWD?)'
    r' *([-:;)\]][ :;\])-]*|$)|]+ *$',
    re.IGNORECASE)

# "[examplecorp/support] Add myself to user list. (#2)"
# "[examplecorp/support] Add myself to user list." "2"
EMAIL_SUBJECT_ISSUE_SUFFIX = re.compile(r'^(.*)\s+\(#([0-9]+)\)$')

ISSUE_TEMPLATE = Template('''<!--
$hidden_content_block
-->
| `$from_address` | 
| ----- | 

$body

$attachment_table
---

Note : To trigger sending an email comment back to `$from_address` include
@$github_username in your comment.
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


def logging_local_time_converter(secs):
    """Convert a UTC epoch time to a local timezone time for use as a logging
    Formatter

    :param secs: Time expressed in seconds since the epoch
    :return: a time.struct_time 8-tuple
    """
    from_zone = tz.gettz('UTC')
    to_zone = TIME_ZONE
    utc = datetime.fromtimestamp(secs)
    utc = utc.replace(tzinfo=from_zone)
    pst = utc.astimezone(to_zone)
    return pst.timetuple()


log_level = os.getenv('LOG_LEVEL', 'INFO')

logger = logging.getLogger(__name__)
logger.setLevel(logging.getLevelName(log_level))
if len(logging.getLogger().handlers) == 0:
    logging.getLogger().addHandler(logging.StreamHandler())
logging.getLogger().setLevel(logging.getLevelName(log_level))
# fmt = "[%(levelname)s]   %(asctime)s.%(msecs)dZ  %(aws_request_id)s  %(message)s"
fmt = "[%(levelname)s] %(asctime)s %(message)s\n"
# datefmt = "%Y-%m-%dT%H:%M:%S"
datefmt = f"%m/%d/%Y %H:%M:%S {TIME_ZONE.tzname(datetime.now())}"
formatter = logging.Formatter(fmt=fmt, datefmt=datefmt)
formatter.converter = logging_local_time_converter
logging.getLogger().handlers[0].setFormatter(formatter)

# Disable boto logging
logging.getLogger('boto3').setLevel(logging.CRITICAL)
logging.getLogger('botocore').setLevel(logging.CRITICAL)
logging.getLogger('requests').setLevel(logging.CRITICAL)
logging.getLogger('urllib3').setLevel(logging.CRITICAL)
logging.getLogger('email_reply_parser').setLevel(logging.CRITICAL)


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
    elif 'replay-email' in event:
        return 'replay-email'
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
        return {}
    try:
        return yaml.safe_load(result.group(1))
    except yaml.YAMLError:
        # Can't parse the hidden data
        return {}


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
            [f'| [{x}]({attachments[x]}) |' for x in attachments])
    return attachment_table


def send_email(email_subject, from_name, from_address, to_address,
               in_reply_to, references, html, text):
    """Send an email using AWS SES in both a text and html format

    :param str email_subject:
    :param str from_name:
    :param str from_address:
    :param str to_address:
    :param str in_reply_to: The Message-ID of the email to which this sent
        email is a reply to
    :param str references:
    :param str html: The HTML email body
    :param str text: The text email body
    :return: The new Message-ID of the sent email
    """
    client = boto3.client('ses')
    msg = MIMEMultipart('alternative')
    msg['Subject'] = email_subject
    msg['From'] = (
        from_address if from_name is None
        else f"{from_name} <{from_address}>")
    msg['To'] = to_address
    if in_reply_to is not None:
        msg['In-Reply-To'] = in_reply_to
    if references is not None:
        msg['References'] = references
    part1 = MIMEText(text, 'plain')
    part2 = MIMEText(html, 'html')
    msg.attach(part1)
    msg.attach(part2)
    response = client.send_raw_email(
        Source=from_address,
        Destinations=[
            to_address,
        ],
        RawMessage={
            'Data': msg.as_string()
        }
    )
    return response['MessageId']


def clean_sender_address(sender):
    """Revert rewritten sender email address

    https://stackoverflow.com/a/47103997/168874
    https://github.com/vstakhov/rspamd/blob/master/rules/forwarding.lua
    https://github.com/bruceg/ezmlm-idx/blob/master/lib/sender.c

    TODO : SRS, Google forward, btv1

    :param str sender: The sender email address
    :return: A cleaned sender email address
    """

    local_part, domain = sender.lower().split('@')
    # prvs=4480132787=billing@example.com
    if not sender.startswith('prvs='):
        return sender
    elements = local_part.split('=')
    if len(elements) == 3:
        try:
            int(elements[1], 16)
            tag_val = elements[1]
            loc_core = elements[2]
        except ValueError:
            try:
                int(elements[2], 16)
                tag_val = elements[2]
                loc_core = elements[1]
            except ValueError:
                raise Exception(
                    'Neither the second nor third elements in the '
                    'local-part of the address are valid prvs tag-val '
                    'syntax')
    else:
        raise Exception(
            'local-part of address appears to be prvs but there are not '
            'three "=" delimited values')
    return f'{loc_core}@{domain}'


class Alerter:
    def __init__(self, config, event, context):
        self.config = config
        self.event = event
        self.context = context

    def alert(self, message=''):
        """Publish an alert to SNS

        :param str message: The message to send in the alert
        :return: Dictionary containing the MessageId of the published SNS
        message
        """
        if 'alert_sns_topic_arn' not in self.config:
            return

        if len(message) > 0:
            message += "\n"
        logger.error(f'Alerting on events {self.event}')
        message += "\n\n"
        message += json.dumps(self.event, indent=4)
        message += f"\nLog stream is : {self.context.log_stream_name}"
        subject = 'Alert from Birch Girder'
        client = boto3.client(
            'sns', region_name=self.config['alert_sns_region'])
        client.publish(
            TopicArn=self.config['alert_sns_topic_arn'],
            Message=message,
            Subject=subject
        )


class Email:
    def __init__(self, config, event, alerter, gh, dryrun=False):
        self.config = config
        self.event = event
        self.alerter = alerter
        self.gh = gh
        self.dryrun = dryrun
        self.record = self.event['Records'][0]
        self.raw_subject = (self.record['ses']['mail']
                            ['commonHeaders']['subject'])
        self.from_address = ''
        self.source = self.record['ses']['mail']['source'].lower()
        self.to_address = ''
        self.s3_payload_filename = self.record['ses']['mail']['messageId']
        self.message_id = self.record['ses']['mail']['commonHeaders'].get(
            'messageId')
        self.date = self.record['ses']['mail']['commonHeaders']['date']
        self.subject = ''
        self.issue_number = ''
        self.github_owner = ''
        self.github_repo = ''
        self.raw_body = ''
        self.email_body = ''
        self.email_body_text = ''
        self.stripped_reply = ''
        self.timestamp = 0
        self.publish_to_github = True
        self.new_attachment_urls = {}
        self.s3 = boto3.client('s3')
        self.parse_email()

    def parse_email(self):
        """Parse an inbound email, adding structured data to the Email object.
        Parse the from and to headers and the subject. Fetch the raw email from
        S3. Parse the mime encoded raw message extracting the text or html
        body and all attachments. Strip off any quoted replies from earlier in
        the thread.

        :return:
        """
        self.from_address = (
            self.record['ses']['mail']['commonHeaders']['from'][0]
            if len(self.record['ses']['mail']['commonHeaders']['from']) == 1
            else ', '.join(
                self.record['ses']['mail']['commonHeaders']['from']))
        possible_recipients = list(self.config['recipient_list'].keys())

        logger.debug(
            'Multiple email destinations found. Looking for an applicable one '
            f": {self.record['ses']['mail']['destination']}")
        for possible_recipient in possible_recipients:
            # Assign the first matching address in recipient_list to
            # to_address
            # Note : It's possible we could determine the actual correct
            #  To address from record['ses']['receipt']['recipients']
            if possible_recipient in [
                    x.lower() for x
                    in self.record['ses']['mail']['destination']]:
                self.to_address = possible_recipient.lower()
                logger.debug(
                    f"Found possible recipient {possible_recipient} in "
                    f"destination list "
                    f"{self.record['ses']['mail']['destination']}")
                break

        if not self.to_address:
            self.to_address = possible_recipients[0].lower()
            logger.debug('No applicable email was found in destination list '
                         f"so we will use {self.to_address} : "
                         f"{self.record['ses']['mail']['destination']}")

            self.alerter.alert(
                "None of the 'To' addresses in '%s' were found in the"
                "recipient_list '%s'. As a result we're just going to assign"
                "%s as the 'To' address. This means that the ticket may have"
                "the wrong metadata in the GitHub issue hidden content and "
                "the reply email back to the submitter may come from a "
                "different email address than they sent the request to." % (
                    self.record['ses']['mail']['destination'],
                    possible_recipients,
                    self.to_address
                ))

        try:
            self.source = clean_sender_address(self.source)
        except Exception as e:
            logger.error(
                f'Failed to clean sender address {self.source} due to "{e}"')

        self.github_owner = self.config['recipient_list'][self.to_address].get(
            'owner')
        self.github_repo = self.config['recipient_list'][self.to_address].get(
            'repo')

        self.parse_subject()
        if not self.raw_body:
            self.get_email_payload()
            self.parse_email_payload()
        self.stripped_reply = EmailReplyParser.parse_reply(
            self.email_body_text
            if self.email_body_text != ''
            else self.email_body)

    def parse_subject(self):
        """Parse the raw email subject, stripping off the leading Re: and
        Fw:, extracting the GitHub issue number. If an issue number is found
        set it and the stripped subject, if not search the GitHub issues
        for a matching issue title. If one is found set the stripped subject
        and issue number, if not set the stripped subject and set the issue
        number to False.

        :return:
        """
        stripped_subject = EMAIL_SUBJECT_PREFIX.sub(
            '', self.raw_subject).strip()
        match = EMAIL_SUBJECT_ISSUE_SUFFIX.match(stripped_subject)
        if match is not None:
            # The inbound email has an existing issue number in the subject
            # Add a comment to the issue
            self.subject, self.issue_number = match.groups()
            logger.debug(
                f'Inbound email with subject "{stripped_subject}" contains '
                f'existing issue number {self.issue_number} and results in '
                f'subject "{self.subject}"')
            return
        if not self.config.get('allow_issue_merging_by_subject', True):
            # Issue merging by matching subject is disabled, create a new issue
            self.subject = stripped_subject
            self.issue_number = False
            return
        # The inbound email has no issue number in the subject
        # Search for an existing issue with a matching subject
        self.subject = stripped_subject

        gh_query = ""
        gh_query += f"author:{self.config['github_username']} "
        gh_query += "type:issue "
        gh_query += f"repo:{self.github_owner}/{self.github_repo} "
        if 'label' in self.config['recipient_list'][self.to_address]:
            gh_query += (
                f"label:{self.config['recipient_list'][self.to_address]['label']} ")
        status, data = self.gh.search.issues.get(q=gh_query)
        results_list = []
        for issue_search_result in data['items']:
            if self.subject not in issue_search_result['title']:
                continue
            issue_data = parse_hidden_content(issue_search_result['body'])
            # This doesn't account for cases where there are multiple
            # source addresses
            issue_source = issue_data['source'] if 'source' in issue_data else issue_data.get('from')
            if self.source in issue_source:
                results_list.append(issue_search_result['number'])
            else:
                logger.debug(
                    "Encountered an inbound email that has a subject "
                    "which matches issue #%s in %s/%s but which was sent "
                    "by %s not by %s who created the existing issue. "
                    "Creating a new issue." % (
                        issue_search_result['number'],
                        self.github_owner,
                        self.github_repo,
                        self.source,
                        issue_source))

        logger.debug(
            f'Search "{gh_query}" triggered by inbound "{self.subject}" '
            f'email matched issue(s) {results_list}')

        if len(results_list) == 0 or len(results_list) > 1:
            # No matching issue found or multiple matching issues found
            # Create a new issue
            self.issue_number = False
        else:
            # One matching issue found but the subject didn't have an
            # issue number
            # Add a comment to the issue
            self.issue_number = results_list[0]


    def get_email_payload(self):
        """Wait for an S3 object to exist with a filename of the SES internal
        messageId value (s3_payload_filename). Once the object exists, fetch
        and set self.raw_body.

        :return:
        """
        bucket = self.config['ses_payload_s3_bucket_name']
        prefix = self.config['ses_payload_s3_prefix']
        key = prefix + self.s3_payload_filename
        logger.debug(f"Using waiter to wait for {bucket} {key} to persist "
                     f"through s3 service")
        waiter = self.s3.get_waiter('object_exists')
        waiter.wait(Bucket=bucket, Key=key)
        response = self.s3.get_object(Bucket=bucket, Key=key)
        logger.debug(f"Fetched s3 object : {response}")
        self.raw_body = response['Body'].read()
        # We're not deleting the s3 object as it's taken care of by S3
        # lifecycle which automatically deletes old data

    def parse_email_payload(self):
        """Parse a raw mime email into a pyzmail.PyzMessage object.
        Write any attachments into the github repo and add a link to those
        files to the new_attachment_urls dict.

        Add attachment links to self.new_attachment_urls
        Add the main body of the email to self.email_body

        :return: nothing
        """
        msg = pyzmail.PyzMessage.factory(self.raw_body)
        self.timestamp = email.utils.mktime_tz(
            email.utils.parsedate_tz(msg.get_decoded_header('Date')))

        if msg.text_part is not None:
            payload, used_charset = pyzmail.decode_text(
                msg.text_part.get_payload(),
                msg.text_part.charset,
                None)
            self.email_body_text = payload
        else:
            self.email_body_text = ''

        if msg.html_part is not None:
            soup = bs4.BeautifulSoup(
                msg.html_part.get_payload(), 'html.parser')
            self.email_body = ''.join(
                str(x) for x in (
                    soup.body.contents
                    if soup.body is not None else soup.contents)
                if not isinstance(x, bs4.Comment))
        elif msg.text_part is not None:
            self.email_body = self.email_body_text
        else:
            # Didn't find text or html
            self.email_body = "Unable to parse body from email"

        for mailpart in msg.mailparts:
            if mailpart.is_body in ['text/plain', 'text/html']:
                continue
            # This mailpart is an attachment
            # Note: We have to check for specific values of is_body because
            # pyzmail doesn't set is_body to None as the docs indicate
            filename = mailpart.sanitized_filename
            storage_filename = f"{self.timestamp}-{filename}"
            logger.info(f'Adding attachment {filename} to repo')
            if self.dryrun:
                self.new_attachment_urls[filename] = 'https://example.com'
                continue
            path = f'attachments/{urllib.parse.quote(storage_filename)}'
            status, data = (
                self.gh.repos[self.github_owner]
                [self.github_repo].contents[path].put(
                    body={
                        'message': f'Add attachment {filename}',
                        'content': base64.b64encode(
                            mailpart.get_payload()).decode('utf-8')
                    }
                )
            )
            html_url = data['content']['html_url']
            self.new_attachment_urls[filename] = html_url


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
        self.alerter = Alerter(self.config, self.event, self.context)
        self.gh = GitHub(token=self.config['github_token'])
        self.s3 = boto3.client('s3')
        self.dryrun_tag = (
            self.config['dryrun_tag'] if 'dryrun_tag' in self.config
            else '--#_##DRYRUN##_#--')
        self.dryrun = False

    def update_issue(self, body, message_id, new_attachment_urls):
        """Parse the hidden content from the GitHub issue body, update it to
        reflect the newly added attachments and replace the hidden_content
        in the issue body with this updated content. Also update the
        existing table of attachments displayed in the issue or create a
        table if none exists. Return the updated body

        :param new_attachment_urls: Dict of new attachments to the issue with
          the keys containing filenames and values containing URLs
        :param str body: The GitHub issue body
        :param str message_id: The RFC 2392 Message-ID of the most recent
        email in the thread related to this GitHub issue
        :return: The updated issue body
        """
        data = parse_hidden_content(body)
        if not data:
            self.alerter.alert(
                "While attempting to add new links to attachments '%s' we "
                "encountered a problem in that we couldn't parse the hidden "
                "content in the issue body. As a result we couldn't "
                "determine what the current list of attachments were and "
                "couldn't add these new attachment links to the table. "
                "Though this attachment has been saved to the repo at %s the "
                "issue has not been updated to reflect this" % (
                    list(new_attachment_urls.keys()),
                    list(new_attachment_urls.values())
                )
            )
            return body

        attachments = data.get('attachments', {})
        attachments.update(new_attachment_urls)
        if len(attachments) > 0 and len(new_attachment_urls) > 0:
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

    def fetch_replay(self, s3_payload_filename):
        """Fetch an event stored in S3 based on the SES internal messageId
        value (s3_payload_filename) and overwrite self.event with the fetched
        event in order to replay that email again.

        :param str s3_payload_filename: The SES internal messageId value of the
            email to replay
        :return:
        """
        bucket = self.config['ses_payload_s3_bucket_name']
        prefix = self.config['ses_payload_s3_prefix'] + 'email-events/'
        key = prefix + s3_payload_filename
        response = self.s3.get_object(Bucket=bucket, Key=key)
        self.event = json.loads(response['Body'].read())
        logger.info(
            f"Email with SES internal messageID {s3_payload_filename} fetched "
            f"from S3 and will now be replayed")

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
            elif event_type == 'replay-email':
                self.fetch_replay(self.event['replay-email'])
                self.incoming_email()
            else:
                logger.error(f"Unable to determine message type from event "
                             f"{self.event}")
        except Exception as e:
            self.alerter.alert(
                f"Uncaught exception thrown\n{e.__class__}\n{e}\n"
                f"{traceback.format_exc()}")
            raise

    def add_comment_to_issue(self, issue, parsed_email):
        """Add a comment to the existing issue

        :param issue: agithub prepared query for the GitHub issue
        :param parsed_email: Email object of the parsed email
        :return: None
        """

        status, issue_data = issue.get()
        if issue_data['state'] == 'closed' and not self.dryrun:
            status, issue_data = issue.patch(body={'state': 'open'})

        if len(parsed_email.new_attachment_urls) > 0:
            comment_attachments = '''| Attachments |\n| --- |\n'''
            comment_attachments += '\n'.join(
                [f'| [{x}]({parsed_email.new_attachment_urls[x]}) |'
                 for x in parsed_email.new_attachment_urls])
        else:
            comment_attachments = ''
        # TODO : I'll ignore the "References" header for now because I
        # don't know what AWS SES does with it
        if not self.dryrun:
            new_body = self.update_issue(
                issue_data['body'], parsed_email.message_id,
                parsed_email.new_attachment_urls)
            status, issue_data = issue.patch(body={'body': new_body})

        comment_message = COMMENT_TEMPLATE.substitute(
            from_address=parsed_email.from_address,
            to_address=parsed_email.to_address,
            date=parsed_email.date,
            headers=json.dumps(
                parsed_email.record['ses']['mail']['headers']),
            body=parsed_email.stripped_reply,
            comment_attachments=comment_attachments)
        logger.info(
            f"Adding a comment to the existing issue "
            f"{parsed_email.issue_number}.")
        if not self.dryrun:
            status, comment_data = issue.comments.post(
                body={'body': comment_message})

    def send_email_to_reporter(self, parsed_email, issue_data):
        """Send an email to the issue reporter

        :param parsed_email: Email object of the parsed email
        :param issue_data: Dictionary of attributes of the GitHub issue
        :return: The message ID of the email sent
        """
        if ('known_machine_senders' in self.config
                and parsed_email.source.lower() in
                [x.lower() for x in self.config['known_machine_senders']]):
            logger.info(
                f"Not sending an email to {parsed_email.source} because "
                f"they are a known machine sender.")
            return True
        body = (
            self.config['initial_email_reply']
            if 'initial_email_reply' in self.config
            else '''Thanks for contacting us. We will get back to you as soon
as possible. You can reply to this email if you have additional information
to add to your request.''')
        status, html_body = self.gh.markdown.post(
            body={
                'text': body,
                'mode': 'gfm',
                'context': '/'.join([
                    parsed_email.github_owner, parsed_email.github_repo])
            }
        )
        text_url = "https://github.com/%s/%s/issues/%s" % (
            parsed_email.github_owner,
            parsed_email.github_repo,
            issue_data['number']
        )
        issue_reference = '%s/%s#%s' % (
            parsed_email.github_owner,
            parsed_email.github_repo,
            issue_data['number']
        )
        html_url = f'<a href="{text_url}">{issue_reference}</a>'
        email_subject = SUBJECT_TEMPLATE.substitute(
            subject=parsed_email.subject,
            issue_number=issue_data['number'])

        # TODO : what do we do if the inbound email had CCs?

        logger.info(
            f"Sending an email to {parsed_email.from_address} confirming "
            f"that a new issue has been created.")
        if self.dryrun:
            return '1'
        template_args = {
            'issue_reference': issue_reference,
            'provider': self.config['provider_name']}
        message_id = send_email(
            email_subject=email_subject,
            from_name=(self.config['recipient_list']
                       [parsed_email.to_address].get('name')),
            from_address=parsed_email.to_address,
            to_address=parsed_email.from_address,
            in_reply_to=parsed_email.message_id,
            references=parsed_email.message_id,
            html=EMAIL_HTML_TEMPLATE.substitute(
                html_body=html_body.decode('utf-8').format(html_url),
                **template_args),
            text=EMAIL_TEXT_TEMPLATE.substitute(
                text_body=body.format(text_url),
                **template_args))

        # Add a reaction to the issue indicating the sender has been
        # replied to
        repo = (
            self.gh.repos[parsed_email.github_owner][parsed_email.github_repo])
        issue = repo.issues[issue_data['number']]
        status, reaction_data = issue.reactions.post(
            body={'content': 'rocket'},
            headers={
                'Accept': 'application/vnd.github.squirrel-girl-preview+json'})
        if int(status / 100) == 2:
            logger.info(
                f"Just added a reaction to issue "
                f"#{issue_data['number']} after sending an email")
        else:
            logger.error(
                f"Unable to add reaction to issue "
                f"#{issue_data['number']} after {status} : "
                f"{reaction_data}")
        return message_id

    def create_issue(self, repo, parsed_email):
        """Create a new GitHub issue
        Also label th issue with the label from the recipient_list or just
        use the username of the email to_address

        :param repo: agithub prepared query for the GitHub repo
        :param parsed_email: Email object of the parsed email
        :return: A dictionary of attributes of the created GitHub issue
        """

        labels = [
            self.config['recipient_list'][parsed_email.to_address].get(
                'label', parsed_email.to_address.split('@')[0])]

        email_metadata = {
            'from': parsed_email.from_address,
            'source': parsed_email.source,
            'to': parsed_email.to_address,
            'date': parsed_email.date,
            'message_id': parsed_email.message_id
        }

        if len(parsed_email.new_attachment_urls) > 0:
            email_metadata['attachments'] = parsed_email.new_attachment_urls

        issue_message = ISSUE_TEMPLATE.substitute(
            hidden_content_block=get_content_block(
                'hidden_content',
                yaml.safe_dump(email_metadata, default_flow_style=False)),
            from_address=parsed_email.from_address,
            to_address=parsed_email.to_address,
            date=parsed_email.date,
            github_username=self.config['github_username'],
            headers=json.dumps(
                parsed_email.record['ses']['mail']['headers']),
            body=parsed_email.stripped_reply,
            attachment_table=get_content_block(
                'attachments',
                produce_attachment_table(parsed_email.new_attachment_urls)
            )
        )
        if not self.dryrun:
            status, issue_data = repo.issues.post(
                body={
                    'title': parsed_email.subject,
                    'body': issue_message,
                    'labels': labels
                }
            )
        else:
            issue_data = {'number': 1}
        logger.info(
            f"Created new issue {issue_data['number']}.")
        return issue_data

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
        recipient_list and if the sender is not in `known_machine_senders`
        email them with a link to the issue.
        If the email has any attachments, save those attachments in the
        GitHub repo. If a new issue is created, add links to those
        attachments to the hidden content and attachment table in the issue
        body. If the issue already exists, add link to those attachments to
        the new comment on the issue and update the existing attachments
        table and hidden content to add the new attachment links.

        :return:
        """
        # https://gist.github.com/gene1wood/26fbae0e2388b02d6292

        if len(self.event['Records']) > 1:
            raise Exception(
                f"Multiple records from SES {self.event['Records']}")

        if (self.dryrun_tag in
                self.event['Records'][0]['ses']['mail']
                ['commonHeaders']['subject']):
            self.dryrun = True
            logger.info('Running in dryrun mode')

        bucket = self.config['ses_payload_s3_bucket_name']
        prefix = self.config['ses_payload_s3_prefix'] + 'email-events/'
        key = prefix + self.event['Records'][0]['ses']['mail']['messageId']

        response = self.s3.put_object(
            Body=json.dumps(self.event, indent=2),
            Bucket=bucket,
            ContentType='application/json',
            Key=key
        )

        logger.debug(f"Wrote s3 object {key} and got etag {response['ETag']}")

        all_plugins = [
            importlib.import_module(f'plugins.{os.path.basename(x)[:-3]}')
            for x in glob.glob("plugins/*.py")
            if os.path.isfile(x) and not x.endswith('__init__.py')]
        plugin_list = [
            x for x in all_plugins if hasattr(x, 'is_matching_email')
            and hasattr(x, 'transform_email')]

        parsed_email = Email(
            self.config, self.event, self.alerter, self.gh, self.dryrun)

        for plugin in plugin_list:
            is_matching_email = getattr(plugin, 'is_matching_email')
            transform_email = getattr(plugin, 'transform_email')
            if is_matching_email(parsed_email):
                transform_email(parsed_email)
                logger.debug(f'Email transformed by plugin {plugin.__name__}')
            else:
                logger.debug(
                    f'Incoming email did not match plugin {plugin.__name__}')

        logger.info(
            f"Received an email from {parsed_email.from_address} to "
            f"{parsed_email.to_address} with a SES internal messageId value "
            f"of {parsed_email.s3_payload_filename} and Message-ID of "
            f"{parsed_email.message_id}. The subject is "
            f"'{parsed_email.subject}' and issue number is "
            f"{parsed_email.issue_number}")

        if not parsed_email.publish_to_github:
            logger.info('This inbound email will not be published to GitHub')
            return

        repo = (
            self.gh.repos[parsed_email.github_owner][parsed_email.github_repo])
        if parsed_email.issue_number:
            issue = repo.issues[parsed_email.issue_number]
            self.add_comment_to_issue(issue, parsed_email)
        else:
            issue_data = self.create_issue(repo, parsed_email)
            message_id = self.send_email_to_reporter(parsed_email, issue_data)
            logger.debug(
                f'Initial email reply sent to {parsed_email.from_address} '
                f'with Message-ID {message_id}')

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
        mention = f"@{self.config['github_username']}"
        mention_regex = r'\B%s\b' % mention

        if 'comment' not in message or 'issue' not in message:
            logger.debug('Non IssueCommentEvent webhook event received : %s'
                         % self.event['Records'][0]['Sns']['Message'])
            return False
        if 'action' not in message:
            logger.error('action key missing from SNS message : %s'
                         % self.event['Records'][0]['Sns']['Message'])
            return False

        if message['action'] not in ['created', 'edited']:
            logger.info(
                "GitHub IssueCommentEvent action in SNS message was "
                "'{message['action']}' so it will be ignored")
            return False
        github_usernames = self.config.get('historical_github_usernames', []) + [self.config['github_username']]
        if message['issue']['user']['login'] not in github_usernames:
            logger.info(
                f"GitHub issue was not created by "
                f"{self.config['github_username']} so it will be ignored")
            return False
        if message['comment']['user']['login'] in github_usernames:
            logger.info(
                f"GitHub issue comment was made by "
                f"{self.config['github_username']} so it will be ignored")
            return False
        if re.search(mention_regex, message['comment']['body']) is None:
            logger.info(
                f'GitHub issue comment does not contain "{mention}" so it '
                f'will be ignored')
            return False

        # Read the hidden content
        data = parse_hidden_content(message['issue']['body'])
        if not data:
            self.alerter.alert(
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

        text_email_body = f"{author} writes:\n{stripped_comment}"

        status, html_comment = self.gh.markdown.post(
            body={
                'text': stripped_comment,
                'mode': 'gfm',
                'context': '/'.join([
                    message['repository']['owner']['login'],
                    message['repository']['name']])
            }
        )

        html_email_body = (
            f'<a href="https://github.com/{author}">@{author}</a> writes :'
            f'<br>\n{html_comment.decode("utf-8")}')

        issue_reference = '%s/%s#%s' % (
            message['repository']['owner']['login'],
            message['repository']['name'],
            message['issue']['number']
        )

        if self.dryrun_tag in message['comment']['body']:
            logger.info(f"Running in dryrun mode. No email notification for "
                        f"{data['from']} sent")
            return
        logger.info(
            f"Sending an email notification to {data['from']} with the "
            f"new issue comment.")
        message_id = send_email(
            email_subject=f"Re: {subject}",
            from_name=self.config['recipient_list'][data['to']].get(
                'name'),
            from_address=data['to'],
            to_address=data['from'],
            in_reply_to=data['message_id'],
            references=data['message_id'],
            html=EMAIL_HTML_TEMPLATE.substitute(
                html_body=html_email_body,
                issue_reference=issue_reference,
                provider=self.config['provider_name']),
            text=EMAIL_TEXT_TEMPLATE.substitute(
                text_body=text_email_body,
                issue_reference=issue_reference,
                provider=self.config['provider_name']))

        self.update_issue(
            message['issue']['body'],
            message_id,
            {})

        # Add a reaction to the comment indicating it's been emailed out
        comment = (self.gh.repos[message['repository']['full_name']].
                   issues.comments[message['comment']['id']])
        status, reaction_data = comment.reactions.post(
            body={'content': 'rocket'},
            headers={
                'Accept': 'application/vnd.github.squirrel-girl-preview+json'})
        logger.info(f"Just added a reaction to a comment in issue "
                    f"#{message['comment']['id']} after sending an email")


def lambda_handler(event, context):
    """Given an event determine if it's and incoming email or an SNS webhook alert
    and trigger the appropriate method

    :param event: A dictionary of metadata for an event
    :param context: The AWS Lambda context object
    :return:
    """
    # logger.debug(f'got event {event}')
    with open('config.yaml') as f:
        config = yaml.load(f.read(), Loader=yaml.SafeLoader)
    handler = EventHandler(config, event, context)
    handler.process_event()


def main():
    """Process a fake inbound email

    :return:
    """
    with open('../docs/example-event-payloads.json') as f:
        example_event_payloads = json.load(f)
    event = example_event_payloads['SES Event']
    context = type('context', (), {'log_stream_name': None})()
    lambda_handler(event, context)


if __name__ == '__main__':
    main()
