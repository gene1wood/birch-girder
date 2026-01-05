#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def is_matching_email(email):
    """Determine if the email was sent from john@example.net and contains the
    subject of 'All mimsy were the borogoves'.

    :param email: Parsed email object of type Email
    :return: Whether or not the email matches this plugins criteria
    """

    plugin_enabled = False
    if not plugin_enabled:
        return False
    if (
        email.source == "john@example.net"
        and email.raw_subject == "All mimsy were the borogoves"
    ):
        return True
    else:
        return False


def transform_email(email):
    """Suppress the creation of a GitHub issue

    :param email: Parsed email object of type Email
    :return:
    """

    email.publish_to_github = False
