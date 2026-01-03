import logging
import re
from string import Template
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import yaml  # pip install PyYAML
import boto3

logger = logging.getLogger(__name__)

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


def update_issue(body, message_id, new_attachment_urls):
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
        logger.critical(
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