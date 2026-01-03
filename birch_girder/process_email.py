import urllib.parse
import base64
import re
import email
import logging
import os
import glob
import json
import importlib
from datetime import datetime
import boto3
from .utils import parse_hidden_content, update_issue, get_content_block, produce_attachment_table, send_email
from .templates import COMMENT_TEMPLATE, ISSUE_TEMPLATE, SUBJECT_TEMPLATE, EMAIL_HTML_TEMPLATE, EMAIL_TEXT_TEMPLATE
from agithub.GitHub import GitHub  # pypi install agithub

from email_reply_parser \
    import EmailReplyParser  # pip install email_reply_parser
import bs4  # pip install beautifulsoup4
import yaml  # pip install PyYAML

logger = logging.getLogger(__name__)

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


class Email:
    def __init__(self, config, event, dryrun=False):
        self.config = config
        self.event = event
        self.gh = GitHub(token=config['github_token'])
        self.dryrun = dryrun
        self.record = self.event['Records'][0]
        self.raw_subject = (self.record['ses']['mail']
                            ['commonHeaders']['subject'])
        self.from_address = ''
        self.source = ''
        self.replyto = ''
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
            if possible_recipient.lower() in [
                    x.lower() for x
                    in self.record['ses']['mail']['destination']]:
                self.to_address = possible_recipient
                logger.debug(
                    f"Found possible recipient {possible_recipient} in "
                    f"destination list "
                    f"{self.record['ses']['mail']['destination']}")
                break

        if not self.to_address:
            self.to_address = possible_recipients[0]
            logger.debug('No applicable email was found in destination list '
                         f"so we will use {self.to_address} : "
                         f"{self.record['ses']['mail']['destination']}")

            logger.critical(
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

        if 'replyTo' in self.record['ses']['mail']['commonHeaders']:
            self.replyto = (
                self.record['ses']['mail']['commonHeaders']['replyTo'][0])
        try:
            self.source = clean_sender_address(
                self.record['ses']['mail']['source'])
        except Exception as e:
            logger.error(
                f"Failed to clean sender address "
                f"{self.record['ses']['mail']['source']} due to \"{e}\"")

        self.github_owner = self.config['recipient_list'][self.to_address].get(
            'owner')
        self.github_repo = self.config['recipient_list'][self.to_address].get(
            'repo')

        self.parse_subject()
        if not self.raw_body:
            self.get_email_payload()
            self.parse_email_payload()
        body_to_parse = (self.email_body_text if self.email_body_text != ''
                         else self.email_body)
        if self.issue_number:
            self.stripped_reply = EmailReplyParser.parse_reply(body_to_parse)
        else:
            self.stripped_reply = body_to_parse

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
                    "which matches issue #%s in %s/%s but which has a mail "
                    "envelope MAILFROM source of %s not %s who created the "
                    "existing issue. Creating a new issue." % (
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
        """Parse a raw MIME email using the stdlib email package.
        Write any attachments into the github repo and add a link to those
        files to the new_attachment_urls dict.

        Add attachment links to self.new_attachment_urls
        Add the main body of the email to self.email_body

        :return: nothing
        """

        msg = email.message_from_bytes(self.raw_body, policy=email.policy.default)

        # Timestamp
        if msg['Date']:
            self.timestamp = int(
                email.utils.parsedate_to_datetime(msg['Date']).timestamp()
            )
        else:
            self.timestamp = 0

        self.email_body_text = ''
        self.email_body = ''

        # Walk message parts
        for part in msg.walk():
            if part.is_multipart():
                continue

            content_type = part.get_content_type()
            disposition = part.get_content_disposition()

            # Plain text body
            if content_type == 'text/plain' and disposition != 'attachment':
                self.email_body_text = part.get_content()

            # HTML body
            elif content_type == 'text/html' and disposition != 'attachment':
                soup = bs4.BeautifulSoup(part.get_content(), 'html.parser')
                self.email_body = ''.join(
                    str(x) for x in (
                        soup.body.contents
                        if soup.body is not None else soup.contents
                    )
                    if not isinstance(x, bs4.Comment)
                )

        # Fallbacks
        if not self.email_body:
            if self.email_body_text:
                self.email_body = self.email_body_text
            else:
                self.email_body = "Unable to parse body from email"

        # Attachments
        for part in msg.iter_attachments():
            filename = part.get_filename()
            if not filename:
                continue

            storage_filename = f"{self.timestamp}-{filename}"
            logger.info(f'Adding attachment {filename} to repo')

            if self.dryrun:
                self.new_attachment_urls[filename] = 'https://example.com'
                continue

            content_bytes = part.get_payload(decode=True)
            path = f'attachments/{urllib.parse.quote(storage_filename)}'

            status, data = (
                self.gh.repos[self.github_owner]
                [self.github_repo].contents[path].put(
                    body={
                        'message': f'Add attachment {filename}',
                        'content': base64.b64encode(content_bytes).decode('utf-8')
                    }
                )
            )

            if int(status / 100) != 2:
                if status == 422 and '"sha" wasn\'t supplied' in data.get('message', ''):
                    status, data = (
                        self.gh.repos[self.github_owner]
                        [self.github_repo].contents[path].get()
                    )
                    logger.info(
                        'Attachment already exists; referencing existing file'
                    )
                    html_url = data['html_url']
                else:
                    logger.error(
                        f'Failed to save attachment {filename} {status} {data}'
                    )
                    continue
            else:
                html_url = data['content']['html_url']

            self.new_attachment_urls[filename] = html_url


def send_email_to_reporter(parsed_email, issue_data, persistent_data, config, dryrun):
    """Send an email to the issue reporter

    :param parsed_email: Email object of the parsed email
    :param issue_data: Dictionary of attributes of the GitHub issue
    :return: The message ID of the email sent
    """
    gh = GitHub(token=config['github_token'])
    if 'known_machine_senders' in config:
        known_machine_senders = [x.lower() for x
                                 in config['known_machine_senders']]
        should_send_email = True
        if parsed_email.source.lower() in known_machine_senders:
            should_send_email = False
        if parsed_email.from_address.lower() in known_machine_senders:
            # This is a value like "John Smith <john@example.com>"
            should_send_email = False
        if (parsed_email.replyto != '' and parsed_email.replyto
                in known_machine_senders):
            should_send_email = False
        if not should_send_email:
            logger.info(
                f"Not sending an email to {parsed_email.source}/"
                f"{parsed_email.from_address}/{parsed_email.replyto} "
                f"because they are a known machine sender.")
            return None
    body = (
        config['initial_email_reply']
        if 'initial_email_reply' in config
        else '''Thanks for contacting us. We will get back to you as soon
as possible. You can reply to this email if you have additional information
to add to your request.''')
    status, html_body = gh.markdown.post(
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

    to_address = (parsed_email.from_address if parsed_email.replyto == ''
                  else parsed_email.replyto)
    logger.info(
        f"Sending an email to {to_address} confirming "
        f"that a new issue has been created.")
    if dryrun:
        return '1'
    template_args = {
        'issue_reference': issue_reference,
        'provider': config['provider_name']}
    message_id = send_email(
        email_subject=email_subject,
        from_name=(config['recipient_list']
                   [parsed_email.to_address].get('name')),
        from_address=parsed_email.to_address,
        to_address=to_address,
        in_reply_to=parsed_email.message_id,
        references=parsed_email.message_id,
        html=EMAIL_HTML_TEMPLATE.substitute(
            html_body=html_body.decode('utf-8').format(html_url),
            **template_args),
        text=EMAIL_TEXT_TEMPLATE.substitute(
            text_body=body.format(text_url),
            **template_args))
    if 'sent_mail' not in persistent_data:
        persistent_data['sent_mail'] = dict()
    persistent_data['sent_mail'][message_id] = {
        'repo_owner': parsed_email.github_owner,
        'repo_name': parsed_email.github_repo,
        'issue_number': issue_data['number'],
        'datetime': datetime.now()
    }
    logger.debug(f"Stored sent email to reporter in persistent data for message_id {message_id}")
    logger.debug(f"persistent_data['sent_mail'] is {persistent_data['sent_mail']}")
    return message_id


def create_issue(repo, parsed_email, config, dryrun=False):
    """Create a new GitHub issue
    Also label the issue with the label from the recipient_list or just
    use the username of the email to_address

    :param repo: agithub prepared query for the GitHub repo
    :param parsed_email: Email object of the parsed email
    :return: A dictionary of attributes of the created GitHub issue
    """

    labels = [
        config['recipient_list'][parsed_email.to_address].get(
            'label', parsed_email.to_address.split('@')[0])]

    email_metadata = {
        'from': parsed_email.from_address,
        'source': parsed_email.source,
        'to': parsed_email.to_address,
        'date': parsed_email.date,
        'message_id': parsed_email.message_id
    }
    if parsed_email.replyto != '':
        email_metadata['reply_to'] = parsed_email.replyto

    if len(parsed_email.new_attachment_urls) > 0:
        email_metadata['attachments'] = parsed_email.new_attachment_urls

    issue_message = ISSUE_TEMPLATE.substitute(
        hidden_content_block=get_content_block(
            'hidden_content',
            yaml.safe_dump(email_metadata, default_flow_style=False)),
        from_address=parsed_email.from_address,
        reply_to=(parsed_email.from_address if parsed_email.replyto == ''
                  else parsed_email.replyto),
        to_address=parsed_email.to_address,
        date=parsed_email.date,
        github_username=config['github_username'],
        headers=json.dumps(
            parsed_email.record['ses']['mail']['headers']),
        body=parsed_email.stripped_reply,
        attachment_table=get_content_block(
            'attachments',
            produce_attachment_table(parsed_email.new_attachment_urls)
        )
    )
    if not dryrun:
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


def add_comment_to_issue(issue, parsed_email, dryrun=False):
    """Add a comment to the existing issue

    :param issue: agithub prepared query for the GitHub issue
    :param parsed_email: Email object of the parsed email
    :return: None
    """

    status, issue_data = issue.get()
    if issue_data['state'] == 'closed' and not dryrun:
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
    if not dryrun:
        new_body = update_issue(
            issue_data['body'], parsed_email.message_id,
            parsed_email.new_attachment_urls)
        status, issue_data = issue.patch(body={'body': new_body})

    comment_message = COMMENT_TEMPLATE.substitute(
        from_address=parsed_email.from_address,
        to_address=parsed_email.to_address,
        date=parsed_email.date,
        headers=json.dumps(
            parsed_email.record['ses']['mail']['headers'], indent=4),
        body=parsed_email.stripped_reply,
        comment_attachments=comment_attachments)
    logger.info(
        f"Adding a comment to the existing issue "
        f"{parsed_email.issue_number}.")
    if not dryrun:
        status, comment_data = issue.comments.post(
            body={'body': comment_message})


def process_email(event, persistent_data, config, send_email=True):
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

    if len(event['Records']) > 1:
        raise Exception(
            f"Multiple records from SES {event['Records']}")

    dryrun_tag = config['dryrun_tag'] if 'dryrun_tag' in config else '--#_##DRYRUN##_#--'
    if (dryrun_tag in
            event['Records'][0]['ses']['mail']
            ['commonHeaders']['subject']):
        dryrun = True
        logger.info('Running in dryrun mode')
    else:
        dryrun = False

    gh = GitHub(token=config['github_token'])
    bucket = config['ses_payload_s3_bucket_name']
    prefix = config['ses_payload_s3_prefix'] + 'email-events/'
    key = prefix + event['Records'][0]['ses']['mail']['messageId']

    client = boto3.client('s3')
    response = client.put_object(
        Body=json.dumps(event, indent=2),
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
        config, event, dryrun)

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
        gh.repos[parsed_email.github_owner][parsed_email.github_repo])
    if parsed_email.issue_number:
        issue = repo.issues[parsed_email.issue_number]
        add_comment_to_issue(issue, parsed_email)
    else:
        issue_data = create_issue(repo, parsed_email, config)
        if not send_email:
            logger.debug('Skipping sending email reply for this replay')
            return
        message_id = send_email_to_reporter(parsed_email, issue_data, persistent_data, config, dryrun)
        if message_id is not None:
            logger.debug(
                f'Initial email reply sent with Message-ID {message_id}')