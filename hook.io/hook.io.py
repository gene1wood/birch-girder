import hmac
import hashlib
import datetime
import urllib.parse
import requests
from pprint import pformat
import logging

Hook = {} if 'Hook' not in globals() else globals()['Hook']

logging.basicConfig()
logger = logging.getLogger()
logger.setLevel(logging.ERROR)


def sign(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()


def get_signature_key(key, date_stamp, region_name, service_name):
    key_date = sign(('AWS4' + key).encode('utf-8'), date_stamp)
    key_region = sign(key_date, region_name)
    key_service = sign(key_region, service_name)
    key_signing = sign(key_service, 'aws4_request')
    return key_signing


def check_github_signature(signature_header, payload, github_webhook_secret):
    hash_type, signature = signature_header.split('=', 1)
    # For signature to match we must use quote_plus
    body = 'payload={}'.format(urllib.parse.quote_plus(payload))
    hmac_object = hmac.new(
        github_webhook_secret.encode(), body.encode(), hash_type)
    logger.info('HMAC is {}'.format(hmac_object))
    digest = hmac_object.hexdigest()
    logger.info('Digest is {}'.format(digest))
    signature_valid = hmac.compare_digest(signature, digest)
    if not signature_valid:
        logger.error('GitHub signature {} is invalid'.format(signature))

    return signature_valid


def post_to_sns(
        sns_topic_arn,
        message,
        aws_access_key_id,
        aws_secret_access_key,
        region='us-west-2'):

    # We use POST instead of GET because the payload is larger than the max
    # allowed size of a GET request
    method = 'POST'
    service = 'sns'
    host = 'sns.{}.amazonaws.com'.format(region)
    endpoint = 'https://sns.{}.amazonaws.com'.format(region)
    content_type = 'application/x-www-form-urlencoded'

    request_parameters = {
        'Action': 'Publish',
        'Message': message,
        'TopicArn': sns_topic_arn,
        'Version': '2010-03-31'
    }

    # Sort the content and encode it based on AWS rules (derived from botocore)
    pairs = []
    for param in sorted(request_parameters):
        pairs.append(
            urllib.parse.quote(param.encode('utf-8'), safe='') + '=' +
            urllib.parse.quote(
                request_parameters[param].encode('utf-8'), safe='-_~'))
    payload = '&'.join(pairs)

    logging.info('payload : {}'.format(payload))

    access_key = aws_access_key_id
    secret_key = aws_secret_access_key
    if access_key is None or secret_key is None:
        print('No access key is available.')
        return False

    now = datetime.datetime.utcnow()
    amz_date = now.strftime('%Y%m%dT%H%M%SZ')
    date_stamp = now.strftime('%Y%m%d')

    canonical_uri = '/'
    canonical_querystring = ''

    # Header names must be trimmed and lowercase, and sorted in code point
    # order from low to high. Note that there is a trailing \n.
    canonical_headers = (
        'content-type:' + content_type + '\n' + 'host:' + host + '\n' +
        'x-amz-date:' + amz_date + '\n')
    signed_headers = 'content-type;host;x-amz-date'
    payload_hash = hashlib.sha256(payload.encode('utf-8')).hexdigest()

    canonical_request = (
        method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' +
        canonical_headers + '\n' + signed_headers + '\n' + payload_hash)
    logger.info('Canonical request : {}'.format(canonical_request))

    algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = (
            date_stamp + '/' + region + '/' + service + '/' + 'aws4_request')
    logger.info('Credential scope : {}'.format(credential_scope))

    string_to_sign = (
        algorithm + '\n' + amz_date + '\n' + credential_scope + '\n' +
        hashlib.sha256(canonical_request.encode('utf-8')).hexdigest())

    signing_key = get_signature_key(secret_key, date_stamp, region, service)
    signature = hmac.new(
        signing_key,
        string_to_sign.encode('utf-8'),
        hashlib.sha256).hexdigest()
    authorization_header = (
        algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope +
        ', ' + 'SignedHeaders=' + signed_headers + ', ' + 'Signature=' +
        signature)
    logger.info('Authorization header : {}'.format(authorization_header))

    # The request can include any headers, but MUST include "host",
    # "x-amz-date", and "Authorization". "host" and "x-amz-date" must
    # be included in the canonical_headers and signed_headers, as noted
    # earlier. Order here is not significant.
    # Python note: The 'host' header is added automatically by the Python
    # 'requests' library.
    headers = {
        'Content-Type': content_type,
        'x-amz-date': amz_date,
        'Authorization': authorization_header}
    request_url = endpoint + canonical_uri

    logger.info('Request URL = ' + request_url)
    logger.info('Headers = ' + pformat(dict(headers)))

    r = requests.post(request_url, data=payload, headers=headers)

    logger.info('Response status code = ' + pformat(r.status_code))
    logger.info('Headers = ' + pformat(dict(r.headers)))
    logger.info('Payload = ' + pformat(r.content))
    return r.status_code == 200


def main():
    github_webhook_secret = Hook['env'].get('github-webhook-secret')
    sns_topic_arn = Hook['env'].get('sns-topic-arn')
    aws_access_key_id = Hook['env'].get('aws-access-key-id')
    aws_secret_access_key = Hook['env'].get('aws-secret-access-key')

    if check_github_signature(
            Hook['req']['headers'].get('X-Hub-Signature'.lower()),
            Hook['params']['payload'],
            github_webhook_secret):
        result = post_to_sns(
            sns_topic_arn,
            Hook['params']['payload'],
            aws_access_key_id,
            aws_secret_access_key)
        if result:
            print('Success')
        else:
            print('Failure')
    else:
        print('Failure')

main()
