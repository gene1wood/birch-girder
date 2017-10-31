#!/usr/bin/python
# -*- coding: utf-8 -*-

def is_matching_email(email):
    """Determine if the email was sent from john@example.net or contains the
    string BANANA CREAM PIE in the subject or was sent before 1980.

    :param email: Parsed email object of type Email
    :return:
    """

    plugin_enabled = False
    if not plugin_enabled:
        return False
    if (email.source == 'john@example.net' or
            'BANANA CREAM PIE' in email.raw_subject or
            email.timestamp < 315532800):
        return True
    else:
        return False


def transform_email(email):
    """Add the word TESTING to the end of the email subject and re-parse the
    email

    :param email: Parsed email object of type Email
    :return:
    """
    email.raw_subject += ' TESTING'
    email.parse_email()
