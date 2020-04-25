import os
import random
import time
import re
import cgi
import logging
import dateutil.parser
import uuid
import boto3
import requests
from agithub.GitHub import GitHub
import bs4


# This must be first verified with AWS SES by sending an email and hitting the link
# TODO : Do this programatically
RESTMAIL_USER = os.environ.get('FROM_EMAIL_ADDRESS', 'replace-this-value')
RESTMAIL_ADDRESS_FORMAT = '{}@restmail.net'
# This must be setup as a birch-girder recipient
TO_EMAIL_ADDRESS = os.environ.get('TO_EMAIL_ADDRESS', 'support@example.com')
RETURN_PATH = os.environ.get('RETURN_PATH', 'john.doe@example.net')

# TODO : Parse these values from the email instead
REPO_OWNER = os.environ.get('REPO_OWNER', 'octocat')
REPO_NAME = os.environ.get('REPO_NAME', 'Spoon-Knife')
GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN', 'your-github-token-goes-here')

WORD_LIST = [line.strip() for line in open('/usr/share/dict/words')]
SUBJECT_PATTERN = re.compile(r'.*\(#([0-9]+)\)$')
EMAIL_VERIFICATION_PATTERN = re.compile(
    r'^https://email-verification\.[^.]+.amazonaws.com/.*$')

"""
Tests to create

* Add comment to GitHub issue without mention
* Check that nothing is sent to restmail address

* Add comment to GitHub issue with mention
* Check that email is sent to restmail address
"""


def get_paginated_results(product, action, key, args=None):
    args = {} if args is None else args
    return [y for sublist in [x[key] for x in boto3.client(product).get_paginator(action).paginate(**args)] for y in sublist]


def verify_email(username):
    email_address = RESTMAIL_ADDRESS_FORMAT.format(username)
    identities = get_paginated_results(
        'ses', 'list_identities', 'Identities',
        {'IdentityType': 'EmailAddress'})
    logging.info('Verified identities : {}'.format(identities))
    if email_address not in identities:
        client = boto3.client('ses')
        logging.info('Initiating identity verification : {}'.format(email_address))
        client.verify_email_identity(EmailAddress=email_address)
        email = get_restmail(
            username,
            lambda x: x['from']['address'] == 'no-reply-aws@amazon.com'
                      and 'Email Address Verification Request'
                      in x['headers']['subject']
                      and EMAIL_VERIFICATION_PATTERN.match(
                email['text']) is not None)
        match = EMAIL_VERIFICATION_PATTERN.match(email['text'])
        verification_url = match.group(0)
        result = requests.get(verification_url, allow_redirects=False)
        return result.status_code == 302 and '://aws.amazon.com/ses/verifysuccess' in result.headers.get('location')
    else:
        return True


def get_restmail(username, test_func):
    checks = 0
    email = None
    while True:
        checks += 1
        response = requests.get('https://restmail.net/mail/{}'.format(username))
        for item in response.json():
            if test_func(item):
                email = item
        if email:
            break
        # Check that the email arrived at restmail before 1 minute elapses
        assert checks <= 12
        time.sleep(5)
    return email


def get_words(length):
    return [random.choice(WORD_LIST) for x in range(length)]


def get_body():
    words = get_words(10)
    text = '\n'.join(get_words(10))
    html = '<ul>\n{}\n</ul>'.format('\n'.join(['<li>{}</li>'.format(x) for x in words]))
    return text, html


def test_all():
    """
    * Send email to SES
      * send from restmail address
      * attach attachment
    * Check to see that a response email was sent to restmail address
    * Check that a new GitHub issue is created
    * TODO Check the attachment
    * Send a reply to email in restmail
    * attach attachment
    * Check that a comment is added to the GitHub issue
    * TODO Check for attachment

    :return:
    """
    identities = get_paginated_results(
        'ses', 'list_identities', 'Identities',
        {'IdentityType': 'EmailAddress'})

    assert RETURN_PATH in identities

    email_address = RESTMAIL_ADDRESS_FORMAT.format(RESTMAIL_USER)
    result = requests.request(
        'delete', 'https://restmail.net/mail/{}'.format(RESTMAIL_USER))
    assert result.status_code == 200

    assert verify_email(RESTMAIL_USER)

    client = boto3.client('ses')
    subject = ' '.join(get_words(3))
    text, html = get_body()
    result = client.send_email(
        Source=email_address,
        Destination={'ToAddresses': [TO_EMAIL_ADDRESS]},
        Message={
            'Subject': {'Data': subject},
            'Body': {
                'Text': {'Data': text},
                'Html': {'Data': html}
            }
        },
        ReturnPath=RETURN_PATH)
    message_id = result.get('MessageId')
    logging.info('Message {} sent to {}'.format(email_address, message_id))

    # Check that SES send succeeded
    assert message_id is not None

    # TODO : Stuck here. But I haven't checked what's showing up in birch girder
    # Lambda logs. Trigger the test, then look at the lambda logs to see why
    # we're not getting a reply email over at restmail
    email = get_restmail(
        RESTMAIL_USER, lambda x: subject in x['headers']['subject'])

    issue_number = SUBJECT_PATTERN.search(email['headers']['subject']).group(1)
    gh = GitHub(token=GITHUB_TOKEN)
    status, data = gh.repos[REPO_OWNER][REPO_NAME].issues[issue_number].get()

    # Check that a GitHub issue was created from the email sent
    assert status == 200

    client = boto3.client('ses')
    soup = bs4.BeautifulSoup(email['html'], 'html.parser')
    reply_quote = ''.join(
        unicode(x) for x in (
            soup.body.contents
            if soup.body is not None else soup.contents)
        if not isinstance(x, bs4.Comment))
    reply = '''{message}
<br>
<div class="gmail_quote">
    <div dir="ltr">On {date} at {time}, {from} wrote:
        <br>
    </div>
    <blockquote class="gmail_quote" style="margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex">
        <div dir="ltr">
            <div dir="ltr">
                {quote}
            </div>
        </div>
    </blockquote>
</div>'''
    reply_datetime = dateutil.parser.parse(email['date'])
    message = ' '.join(get_words(3))
    fields = {
        'date': reply_datetime.strftime('%a, {} %b %Y').format(reply_datetime.strftime('%d').strip('0')),
        'time': reply_datetime.strftime('%H:%M'),
        'from': cgi.escape(email['headers']['from']),
        'quote': reply_quote,
        'message': '<b>{}</b>'.format(message)
    }

    # TODO : Message ID should be the same so it's clear it's a reply
    result = client.send_email(
        Source=email_address,
        Destination={'ToAddresses': [email['from'][0]['address']]},
        Message={
            'Subject': {'Data': 'Re: {}'.format(email['headers']['subject'])},
            'Body': {
                'Html': {'Data': reply.format(**fields)}
            }
        }
    )

    # Check that SES accepted our reply email to be sent
    assert result.get('MessageId') is not None

    gh = GitHub(token=GITHUB_TOKEN)
    checks = 0
    comment = None
    while checks <= 12:
        checks += 1
        status, comments = gh.repos[REPO_OWNER][REPO_NAME].issues[issue_number].comments.get()
        for item in comments:
            if message in item['body']:
                comment = item
        if comment:
            break
        time.sleep(5)

    # Check that our reply email created a comment in the GitHub issue
    assert comment is not None