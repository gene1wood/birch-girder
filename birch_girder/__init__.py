#!/usr/bin/python
# -*- coding: utf-8 -*-

import json
import logging
import os

import boto3
import yaml  # pip install PyYAML
from aws_lambda_persistence import PersistentMap  # pip install aws-lambda-persistence

from . import process_email, process_github_webhook, process_ses_notification
from .setup_logging import setup_logging, set_invocation_context

# ---- one-time logging setup (cold start) ----
setup_logging(
    sns_topic_arn="arn:aws:sns:us-west-2:651671559233:BirchGirderStagingAlerts"
)

logger = logging.getLogger(__name__)


def get_event_type(event, config):
    """Determine where an event originated from based on it's contents

    :param event: A dictionary of metadata for an event
    :param config: The config
    :return: Either the name of the source of the event or False if no
    source can be determined
    """
    if "source" in event and event["source"] == "aws.events":
        # CloudWatch Scheduled Event
        return "cloudwatch"
    elif (
        "Records" in event
        and type(event["Records"]) is list
        and len(event["Records"]) > 0
        and type(event["Records"][0]) is dict
    ):
        topic_arn = event["Records"][0].get("Sns", {}).get("TopicArn")
        if topic_arn == config["ses_notification_sns_topic_arn"]:
            return "ses_notification"
        elif topic_arn == config["sns_topic_arn"]:
            return "github"
        elif event["Records"][0].get("eventSource") == "aws:ses":
            # SES received email
            # Note the lower case 'eventSource'
            return "ses_email"
        else:
            return "unknown"
    elif "replay-email" in event:
        return "replay-email"
    else:
        return False


def fetch_replay(
    s3_payload_filename, ses_payload_s3_bucket_name, ses_payload_s3_prefix
):
    """Fetch an event stored in S3 based on the SES internal messageId
    value (s3_payload_filename) and overwrite self.event with the fetched
    event in order to replay that email again.

    :param str s3_payload_filename: The SES internal messageId value of the
        email to replay
    :param ses_payload_s3_bucket_name:
    :param ses_payload_s3_prefix:
    :return:
    """
    bucket = ses_payload_s3_bucket_name
    prefix = ses_payload_s3_prefix + "email-events/"
    key = prefix + s3_payload_filename
    client = boto3.client("s3")
    response = client.get_object(Bucket=bucket, Key=key)
    logger.info(
        f"Email with SES internal messageID {s3_payload_filename} fetched "
        "from S3 and will now be replayed"
    )
    return json.loads(response["Body"].read())


def process_event(event, context, config):
    """Determine event type and call the associated processor

    :return:
    """
    try:
        event_type = get_event_type(event, config)
        if event_type == "ses_email":
            process_email.process_email(event, persistent_data, config, send_email=True)
        elif event_type == "github":
            process_github_webhook.process_github_webhook(
                event, persistent_data, config
            )
        elif event_type == "ses_notification":
            process_ses_notification.process_ses_notification(
                event, persistent_data, config["github_token"]
            )
        elif event_type == "replay-email":
            synthetic_event = fetch_replay(
                event["replay-email"],
                config["ses_payload_s3_bucket_name"],
                config["ses_payload_s3_prefix"],
            )
            send_email = os.getenv("SEND_REPLAY_EMAIL", "True").lower() == "false"
            process_email.process_email(
                synthetic_event, persistent_data, config, send_email
            )

        else:
            logger.error(f"Unable to determine message type from event {event}")
    except Exception:
        logger.critical("Uncaught exception thrown", exc_info=True)
        raise


def lambda_handler(event, context):
    """Given an event determine if it's and incoming email or an SNS webhook alert
    and trigger the appropriate method

    :param event: A dictionary of metadata for an event
    :param context: The AWS Lambda context object
    :return:
    """
    # This will make the event and context available later for logging
    set_invocation_context(event, context)

    # logger.debug(f'got event {event}')
    with open("config.yaml") as f:
        config = yaml.load(f.read(), Loader=yaml.SafeLoader)
    global persistent_data
    if "persistent_data" not in globals():
        # data isn't present in Lambda cache already
        persistent_data = PersistentMap()  # aws-lambda-persistence
        logger.debug("persistent_data isn't in Lambda cache, fetching from DynamoDB")
        logger.debug(f"persistent_data is {persistent_data}")

    process_event(event, context, config)


def main():
    """Process a fake inbound email

    :return:
    """
    with open("../docs/example-event-payloads.json") as f:
        example_event_payloads = json.load(f)
    event = example_event_payloads["SES Event"]
    context = type("context", (), {"log_stream_name": None})()
    lambda_handler(event, context)


if __name__ == "__main__":
    main()
