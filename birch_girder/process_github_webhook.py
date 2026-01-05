import json
import logging
import re
from datetime import datetime

from agithub.GitHub import GitHub  # pypi install agithub

from .templates import SUBJECT_TEMPLATE, EMAIL_HTML_TEMPLATE, EMAIL_TEXT_TEMPLATE
from .utils import parse_hidden_content, send_email, update_issue

logger = logging.getLogger(__name__)


def process_github_webhook(event, persistent_data, config):
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
    gh = GitHub(token=config["github_token"])
    message = json.loads(event["Records"][0]["Sns"]["Message"])
    mention = f"@{config['github_username']}"
    mention_regex = rf"\B{mention}\b"

    if message.get("notificationType") == "AmazonSnsSubscriptionSucceeded":
        logger.debug(
            "Ignoring AmazonSnsSubscriptionSucceeded event : "
            f"{event['Records'][0]['Sns']['Message']}"
        )
        return False
    if "comment" not in message or "issue" not in message:
        logger.debug(
            "Non IssueCommentEvent webhook event received :"
            f" {event['Records'][0]['Sns']['Message']}"
        )
        return False
    if "action" not in message:
        logger.error(
            "action key missing from SNS message :"
            f" {event['Records'][0]['Sns']['Message']}"
        )
        return False

    if message["action"] not in ["created", "edited"]:
        logger.info(
            "GitHub IssueCommentEvent action in SNS message was "
            "'{message['action']}' so it will be ignored"
        )
        return False
    github_usernames = config.get("historical_github_usernames", []) + [
        config["github_username"]
    ]
    if message["issue"]["user"]["login"] not in github_usernames:
        logger.info(
            "GitHub issue was not created by "
            f"{config['github_username']} so it will be ignored"
        )
        return False
    if message["comment"]["user"]["login"] in github_usernames:
        logger.info(
            "GitHub issue comment was made by "
            f"{config['github_username']} so it will be ignored"
        )
        return False
    if re.search(mention_regex, message["comment"]["body"]) is None:
        logger.info(
            f'GitHub issue comment does not contain "{mention}" so it will be ignored'
        )
        return False

    # Read the hidden content
    data = parse_hidden_content(message["issue"]["body"])
    if not data:
        logger.critical(
            f"Comment {message['comment']['html_url']} added to issue"
            f" {message['issue']['number']} should have triggered sending an email back"
            " to the reporter of the issue but we can't determine who to send it to"
            " because the hidden content was either missing or couldn't be parsed. No"
            " email will be sent."
        )
        return False
    logger.info("Received a GitHub event notification of a new issue comment.")

    # Create email
    subject = SUBJECT_TEMPLATE.substitute(
        subject=message["issue"]["title"], issue_number=message["issue"]["number"]
    )
    author = message["comment"]["user"]["login"]

    re_safe_username = re.escape(config["github_username"])
    stripped_comment = re.sub(
        rf"(^|\s)@{re_safe_username}($|\s)", "", message["comment"]["body"]
    )

    text_email_body = f"{author} writes:\n{stripped_comment}"

    status, html_comment = gh.markdown.post(
        body={
            "text": stripped_comment,
            "mode": "gfm",
            "context": "/".join(
                [message["repository"]["owner"]["login"], message["repository"]["name"]]
            ),
        }
    )

    html_email_body = (
        f'<a href="https://github.com/{author}">@{author}</a> writes :'
        f'<br>\n{html_comment.decode("utf-8")}'
    )

    issue_reference = (
        f"{message['repository']['owner']['login']}/{message['repository']['name']}"
        f"#{message['issue']['number']}"
    )

    dryrun_tag = (
        config["dryrun_tag"] if "dryrun_tag" in config else "--#_##DRYRUN##_#--"
    )
    if dryrun_tag in message["comment"]["body"]:
        logger.info(
            "Running in dryrun mode. No email notification for "
            f"{data['reply_to'] if 'reply_to' in data else data['from']} sent"
        )
        return
    logger.info(
        f"Sending an email notification to {data['from']} with the new issue comment."
    )
    message_id = send_email(
        email_subject=f"Re: {subject}",
        from_name=config["recipient_list"][data["to"]].get("name"),
        from_address=data["to"],
        to_address=data["reply_to"] if "reply_to" in data else data["from"],
        in_reply_to=data["message_id"],
        references=data["message_id"],
        html=EMAIL_HTML_TEMPLATE.substitute(
            html_body=html_email_body,
            issue_reference=issue_reference,
            provider=config["provider_name"],
        ),
        text=EMAIL_TEXT_TEMPLATE.substitute(
            text_body=text_email_body,
            issue_reference=issue_reference,
            provider=config["provider_name"],
        ),
    )
    if "sent_mail" not in persistent_data:
        persistent_data["sent_mail"] = dict()
    persistent_data["sent_mail"][message_id] = {
        "repo_owner": message["repository"]["owner"]["login"],
        "repo_name": message["repository"]["name"],
        "comment_id": message["comment"]["id"],
        "datetime": datetime.now(),
    }
    logger.debug(
        "Stored sent email in response to GitHub event in persistent data for"
        f" message_id {message_id}"
    )
    logger.debug(f"persistent_data['sent_mail'] is {persistent_data['sent_mail']}")

    update_issue(message["issue"]["body"], message_id, {})
