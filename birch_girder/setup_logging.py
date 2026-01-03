from datetime import datetime
import os
import logging
from dateutil import tz  # sudo pip install python-dateutil
import boto3
import json
import contextvars
from typing import Any, Dict

_lambda_event = contextvars.ContextVar("lambda_event", default=None)
_lambda_context = contextvars.ContextVar("lambda_context", default=None)

TIME_ZONE = tz.gettz('America/Los_Angeles')

_old_factory = logging.getLogRecordFactory()

def record_factory(*args, **kwargs) -> logging.LogRecord:
    record = _old_factory(*args, **kwargs)

    event = _lambda_event.get()
    context = _lambda_context.get()

    record.lambda_event = json.dumps(event, indent=4, default=str)
    record.lambda_context = json.dumps({
        "function_name": getattr(context, "function_name", None),
        "function_version": getattr(context, "function_version", None),
        "aws_request_id": getattr(context, "aws_request_id", None),
        "invoked_function_arn": getattr(context, "invoked_function_arn", None),
        "log_group_name": getattr(context, "log_group_name", None),
        "log_stream_name": getattr(context, "log_stream_name", None),
    }, indent=4, default=str) if context else None
    return record


class SNSCriticalHandler(logging.Handler):
    """
    Emits CRITICAL log records to SNS.
    """
    def __init__(self, topic_arn: str) -> None:
        super().__init__(level=logging.CRITICAL)
        self._sns = boto3.client("sns", region_name=topic_arn.split(':')[3])
        self._topic_arn = topic_arn

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = self.format(record)
            self._sns.publish(
                TopicArn=self._topic_arn,
                Subject="Alert from Birch Girder",
                Message=message,
            )
        except Exception:
            # Never allow logging failures to crash the app
            self.handleError(record)

_logging_configured = False



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


def setup_logging(sns_topic_arn: str) -> None:
    """
    One-time logging setup. Safe to call multiple times.
    """
    global _logging_configured
    if _logging_configured:
        return

    # Install factory FIRST
    logging.setLogRecordFactory(record_factory)

    root_logger = logging.getLogger()
    root_logger.setLevel(os.getenv('LOG_LEVEL', 'INFO'))

    # Disable boto logging
    logging.getLogger('boto3').setLevel(logging.CRITICAL)
    logging.getLogger('botocore').setLevel(logging.CRITICAL)
    logging.getLogger('s3transfer').setLevel(logging.CRITICAL)
    logging.getLogger('requests').setLevel(logging.CRITICAL)
    logging.getLogger('urllib3').setLevel(logging.CRITICAL)
    logging.getLogger('email_reply_parser').setLevel(logging.CRITICAL)

    # Reconfigure default Lambda handler
    for handler in root_logger.handlers:
        # fmt = "[%(levelname)s]   %(asctime)s.%(msecs)dZ  %(aws_request_id)s  %(message)s"
        fmt = "[%(levelname)s] %(asctime)s %(message)s\n"
        # Maybe we don't need the time in the message since AWS knows the time for each log line anyway
        fmt = "[%(levelname)s] %(message)s\n"
        # datefmt = "%Y-%m-%dT%H:%M:%S"
        datefmt = f"%m/%d/%Y %H:%M:%S {TIME_ZONE.tzname(datetime.now())}"

        if not isinstance(handler, SNSCriticalHandler):
            handler.setFormatter(
                logging.Formatter(fmt=fmt, datefmt=datefmt)
            )

    # ---- SNS handler (CRITICAL only) ----
    sns_handler = SNSCriticalHandler(sns_topic_arn)
    sns_format = '''%(message)s

# Event

%(lambda_event)s

# Context

%(lambda_context)s

# Additional Context

{
    "level": "%(levelname)s",
    "module": "%(module)s",
    "function": "%(funcName)s",
    "line": "%(lineno)d",
}
'''
    sns_handler.setFormatter(logging.Formatter(sns_format))

    root_logger.addHandler(sns_handler)



    _logging_configured = True


def set_invocation_context(event: Any, context: Any) -> None:
    _lambda_event.set(event)
    _lambda_context.set(context)


def dump_loggers():
    manager = logging.Logger.manager
    root = logging.getLogger()

    print(f"{'Logger name':40} {'Level':10} {'Effective':10} {'Propagate'}")
    print("-" * 75)

    # Include root explicitly
    print(
        f"{'root':40} "
        f"{logging.getLevelName(root.level):10} "
        f"{logging.getLevelName(root.getEffectiveLevel()):10} "
        f"{root.propagate}"
    )

    for name, logger in sorted(manager.loggerDict.items()):
        if isinstance(logger, logging.PlaceHolder):
            continue

        print(
            f"{name:40} "
            f"{logging.getLevelName(logger.level):10} "
            f"{logging.getLevelName(logger.getEffectiveLevel()):10} "
            f"{logger.propagate}"
        )

