import logging
import json
from agithub.GitHub import GitHub  # pypi install agithub

logger = logging.getLogger(__name__)

def process_ses_notification(event, persistent_data, github_token):
    """Lookup the associated GitHub issue or comment and add a reaction

    Bounce : Create a `-1` reaction to issue or comment
    Complaint : Create a `confused` reaction to issue or comment
    Delivery : Create a `rocket` reaction to issue or comment

    This requires persisting information about the sent email in
    aws-lambda-persistence which we use via a Lamda Layer. When an email
    is sent, we store a record of it. Later when AWS SES emits an
    event to SNS, reporting the disposition of that sent email, we can
    map it back to the email that was sent and add the reaction to the
    correct issue or comment. This is all keyed off of the email's
    message-id.

    :return:
    """
    if len(event['Records']) > 1:
        raise Exception(
            f"Multiple records from SES {event['Records']}")

    gh = GitHub(token=github_token)
    ses_notification = json.loads(event['Records'][0]['Sns']['Message'])

    if ses_notification['notificationType'] == 'Bounce':
        reaction_content = '-1'
    elif ses_notification['notificationType'] == 'Complaint':
        reaction_content = 'confused'
    elif ses_notification['notificationType'] == 'Delivery':
        reaction_content = 'rocket'
    else:
        raise Exception(f"Unexpected AWS SES notificationType of #{ses_notification['notificationType']} in event")

    message_id = ses_notification['mail']['messageId']
    # Note : We don't want self.event['Records'][0]['Sns']['MessageId'] as this is the outer message ID which we're not using
    if message_id in persistent_data['sent_mail']:
        # The SES notification received maps to an email that we previously sent
        issue_or_comment = persistent_data['sent_mail'][message_id]
        if 'comment_id' in issue_or_comment:
            # The email was sent in response to a comment
            reaction_target = (gh.repos[issue_or_comment['repo_owner']][issue_or_comment['repo_name']].
               issues.comments[issue_or_comment['comment_id']])
            logger.info(
                f"Adding reaction {reaction_content} to comment {issue_or_comment['comment_id']} in repo {issue_or_comment['repo_owner']}/{issue_or_comment['repo_name']} due to SES notification")

        elif 'issue_number' in issue_or_comment:
            # The email was sent in response to the creation of an issue
            repo = (
                gh.repos[issue_or_comment['repo_owner']][issue_or_comment['repo_name']])
            reaction_target = repo.issues[issue_or_comment['issue_number']]
            logger.info(
                f"Adding reaction {reaction_content} to issue {issue_or_comment['issue_number']} in repo {issue_or_comment['repo_owner']}/{issue_or_comment['repo_name']} due to SES notification")
        else:
            raise Exception(
                f"The information stored in the PersistentMap['sent_mail'] for message "
                f"#{message_id} appears malformed. It contains #{issue_or_comment}")
    else:
        # This is an SES notification about a messageId we haven't seen before
        raise Exception(
            f"An SES notification was received with message_id {message_id} which doesn't map to an email "
            f"that we've seen before. persistent_data is {persistent_data} and the event is {event}")


    status, reaction_data = reaction_target.reactions.post(
        body={'content': reaction_content},
        headers={
            'Accept': 'application/vnd.github+json'})
    del persistent_data['sent_mail'][message_id]
    if ses_notification['notificationType'] in ['Bounce', 'Complaint']:
        # Add details about the failure in a hidden section of the issue or comment
        reaction_details = (
            f"\n<!--\nSES Event when the email of this issue/comment was sent :\n"
            f"{json.dumps(event, indent=4)}\n-->")
        if 'comment_id' in issue_or_comment:
            comment = (gh.repos[issue_or_comment['repo_owner']][issue_or_comment['repo_name']].issues.
                comments[issue_or_comment['comment_id']])
            status, comment_update_result = (
                gh.repos[issue_or_comment['repo_owner']][issue_or_comment['repo_name']].issues.
                comments[issue_or_comment['comment_id']].patch(body={'body': comment['body'] + reaction_details}, headers={
            'Accept': 'application/vnd.github+json'}))
        elif 'issue_number' in issue_or_comment:
            status, issue = (gh.repos[issue_or_comment['repo_owner']][issue_or_comment['repo_name']].issues.
                issue_or_comment['issue_number'])
            status, issue_update_result = (
                gh.repos[issue_or_comment['repo_owner']][issue_or_comment['repo_name']].issues.
                issue_or_comment['issue_number'].patch(
                    body={'body': issue['body'] + reaction_details}, headers={
            'Accept': 'application/vnd.github+json'}))
        else:
            raise Exception(
                f"The information stored in the PersistentMap['sent_mail'] for message "
                f"#{message_id} appears malformed. It contains #{issue_or_comment}")