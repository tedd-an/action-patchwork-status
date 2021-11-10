#!/usr/bin/env python3
import os
import sys
import logging
import argparse
import subprocess
import re
import smtplib
import email.utils
import requests
import configparser
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

logger = None
config = None

PW_BASE_URL = "https://patchwork.kernel.org/api/1.2"
PW_BT_PROJECT_ID= "395"

BODY_FOOTER = '''

------------
Best Regards
BlueZ Team
'''

def send_email(sender, receiver, msg):
    """ Send email """

    email_cfg = config['email']

    if 'EMAIL_TOKEN' not in os.environ:
        logger.warning("missing EMAIL_TOKEN. Skip sending email")
        return

    try:
        session = smtplib.SMTP(email_cfg['server'], int(email_cfg['port']))
        session.ehlo()
        if 'starttls' not in email_cfg or email_cfg['starttls'] == 'yes':
            session.starttls()
        session.ehlo()
        session.login(sender, os.environ['EMAIL_TOKEN'])
        session.sendmail(sender, receiver, msg.as_string())
        logger.info("Successfully sent email")
    except Exception as e:
        logger.error("Exception: {}".format(e))
    finally:
        session.quit()

    logger.info("Sending email done")

def get_receivers():
    """
    Get list of receivers
    """

    logger.debug("Get Receivers list")
    email_cfg = config['email']

    receivers = []
    if 'only-maintainers' in email_cfg and email_cfg['only-maintainers'] == 'yes':
        # Send only to the addresses in the 'maintainers'
        maintainers = "".join(email_cfg['maintainers'].splitlines()).split(",")
        receivers.extend(maintainers)
    else:
        # Send to default-to address and submitter
        receivers.append(email_cfg['default-to'])

    return receivers

def get_sender():
    """
    Get Sender from configuration
    """
    email_cfg = config['email']
    return email_cfg['user']

def get_default_to():
    """
    Get Default address which is a mailing list address
    """
    email_cfg = config['email']
    return email_cfg['default-to']

def is_maintainer_only():
    """
    Return True if it is configured to send maintainer-only
    """
    email_cfg = config['email']

    if 'only-maintainers' in email_cfg and email_cfg['only-maintainers'] == 'yes':
        return True

    return False

def datetime_to_str(date):
    """
    Convert datetime to ISO 8601 format
    """
    return datetime(date.year, date.month, date.day,
                    date.hour, date.minute, date.second).isoformat()

def get_n_days(days):
    """
    Get the datetime object of n days ago
    """
    return datetime.today() - timedelta(days=days)

def compose_email(title, body):
    """
    Compose and send email
    """

    receivers = get_receivers()
    sender = get_sender()

    # Create message
    msg = MIMEMultipart()
    msg['From'] = sender
    msg['To'] = ", ".join(receivers)
    msg['Subject'] = title

    # In case to use default-to address, set Reply-To to mailing list in case
    # submitter reply to the result email.
    if not is_maintainer_only():
        msg['Reply-To'] = get_default_to()

    logger.debug("Message Body: %s" % body)
    msg.attach(MIMEText(body, 'plain'))

    logger.debug("Mail Message: {}".format(msg))

    # Send email
    send_email(sender, receivers, msg)

def requests_url(url):
    """ Helper function to requests GET with URL """
    resp = requests.get(url)
    if resp.status_code != 200:
        raise requests.HTTPError("GET {}".format(resp.status_code))

    return resp

def requests_patch(url, headers, content):
    """ Helper function to post data to URL """

    resp = requests.patch(url, content, headers=headers)
    if resp.status_code != 200:
        raise requests.HTTPError("POST {}".format(resp.status_code))

    return resp

def pw_get_series(sid):
    """ Get series detail from patchwork """

    url = PW_BASE_URL + "/series/" + sid + "/"
    req = requests_url(url)

    return req.json()

def pw_get_patches_by_state(state, before=0, since=0):
    """
    Get the array of patches with given state
    """

    patches = []

    url = '{}/patches/?project={}&state={}&archived=0'.format(PW_BASE_URL,
                                                              PW_BT_PROJECT_ID,
                                                              state)

    if before != 0:
        # Get the list of patches with "New" and older than 3 days
        before_str = datetime_to_str(get_n_days(before))
        url = url + '&before={}'.format(before_str)

    if since != 0:
        # Get the list of patches with "New" and older than 3 days
        since_str = datetime_to_str(get_n_days(since))
        url = url + '&since={}'.format(since_str)

    while True:
        resp = requests_url(url)
        patches = patches + resp.json()

        if "next" not in resp.links:
            logger.debug("Read all patches: Total %d" % len(patches))
            break

        logger.debug("Read Next Page")
        url = resp.links["next"]["url"]

    return patches

def pw_set_patch_state(patch, state):
    """
    Get Patch State
    """

    logger.debug("URL: %s" % patch['url'])

    headers = {}
    if 'PATCHWORK_TOKEN' not in os.environ:
        logger.error("Patchwork Token doens't exist in the env")
        return None

    token = os.environ['PATCHWORK_TOKEN']
    headers['Authorization'] = f'Token {token}'
    print(headers['Authorization'])

    content = {
        'state' : "Queued"
    }

    req = requests_patch(patch['url'], headers, content)

    return req.json()

def pw_set_series_patch_state(series, state):
    """
    Set the state of the patches in the series
    """
    series_full = pw_get_series(str(series['id']))

    for patch in series_full['patches']:
        pw_set_patch_state(patch, state)

def pw_get_patch_comments(patch):
    """
    Get Patch comments
    """
    url = '{}/patches/{}/comments/'.format(PW_BASE_URL, patch['id'])

    resp = requests_url(url)

    return resp.json()

def check_series_reviewed(series, reviewers):
    """
    This checks if the patch series are reviewed by the reviewers.
    It goes through the comments from the patches and find it from the reviewers
    list.
    Returns True if the commenter is in the reviewrs list otherwise False
    """

    series_full = pw_get_series(str(series['id']))

    for patch in series_full['patches']:
        comments = pw_get_patch_comments(patch)

        # no comments and skip to next
        if comments == None:
            continue

        # If the comment was done by the maintainers, the review is done for
        # this series.
        for comment in comments:
            submitter = comment['submitter']['email']
            if submitter in reviewers:
                logger.debug("Found (%s) from the reviewer list" % submitter)
                return True


    # If the comment was not done by the reviewers, the reviewers still need to
    # review it.
    logger.debug("No review comment found fromm the reviwer list")
    return False

def id_exist(list, id):
    """
    Check if the id exist in the list. The list item should have "id" field
    Return True if the id exist in the list, otherwise return false
    """
    for item in list:
        if "id" in item and item["id"] == id:
            return True
    return False

def get_series_from_patches(patches):
    """
    This function exams the patch in the patch list to get the series id and
    add series to the series list if it doens't exist.
    """

    series_list =[]

    for patch in patches:
        # Skip if "series" not exist
        if "series" not in patch:
            continue

        for series in patch["series"]:
            # Check if series.id in the list
            if id_exist(series_list, series["id"]) == False:
                logger.debug("Add series %d to series list" % series["id"])
                series_list.append(series)

    return series_list

def parse_series(series):
    """
    Read series and format the output
    """
    output =  "* SID:{}({})\n".format(series['id'], series['web_url'])
    output += "  Patches:\n"

    for patch in series['patches']:
        output += "      {}\n".format(patch['name'])

    return output

def task_status():

    body_header = '''
List of patch series in New state
=================================

'''

    logger.debug("Start Task: Status")

    # Get the list of patches with "New" state(1)
    patches = pw_get_patches_by_state(1)

    # Get the list of series from the patch list
    series_list = get_series_from_patches(patches)

    title = "[BlueZ Internal] List of Patchwork patches in open state - Weekly Report"
    body = body_header

    for series in series_list:
        series_full = pw_get_series(str(series['id']))
        body += parse_series(series_full)
        body += "\n\n"

    body += BODY_FOOTER

    return (title, body)

def task_triage():

    new_series_list = []

    logger.debug("Start Task: Triage")

    title = "[BlueZ Internal] Patchwork status daily update"
    body_header = '''
Dear Maintainers,

The following patch series are in New state for 3 days or more, but it looks like
no feedback was provided to the submitter yet.
========================================================================

'''
    body = body_header

    # Get the list of patches with "New" state(1) and 3 days or older
    patches = pw_get_patches_by_state(1, before=3)

    # No patches are available
    if not patches:
        logger.info("No new patches found. Nothing to notify the maintainers")
        return (None, None)
        # body += "Great work! No New patches are found!"
        # body += BODY_FOOTER
        # return (title, body)

    # Get the list of series from the patch list
    series_list = get_series_from_patches(patches)

    reviewers = "".join(config['triage']['reviewers'].splitlines()).split(',')
    logger.debug("Reviewers: %s" % reviewers)

    # If the series/patches has comments from the reviewers, then no need to
    # notify to the maintainers since they already took an action.
    for series in series_list:
        if not check_series_reviewed(series, reviewers):
            logger.debug("Add SID(%s) to new_series_list" % series['id'])
            new_series_list.append(series)
        else:
            logger.debug("Update SID(%s) to new state Queued(13)")
            pw_set_series_patch_state(series, 13)


    for series in new_series_list:
        series_full = pw_get_series(str(series['id']))
        body += parse_series(series_full)
        body += "\n\n"

    body += BODY_FOOTER

    return (title, body)

def init_config():
    """ Read config.ini """

    global config

    config = configparser.ConfigParser()
    config.read("/config.ini")


def init_logging(verbose):
    """ Initialize logger. Default to INFO """

    global logger

    logger = logging.getLogger('')
    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s:%(levelname)-8s:%(message)s')
    ch.setFormatter(formatter)

    logger.addHandler(ch)
    logger.setLevel(logging.INFO)
    if verbose:
        logger.setLevel(logging.DEBUG)

    logger.info("Initialized the logger: level=%s",
                 logging.getLevelName(logger.getEffectiveLevel()))

def parse_args():
    parser = argparse.ArgumentParser(
        description="Check patch style in the pull request")
    parser.add_argument('task', default='status', nargs='?',
                        help='The name of the task to run. ')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Display debugging info')
    return parser.parse_args()

def main():
    args = parse_args()

    init_logging(args.verbose)
    init_config()

    title=''
    body=''

    if args.task == 'status':
        (title, body) = task_status()
    elif args.task == 'triage':
        (title, body) = task_triage()
    else:
        logger.error("Unknown task: %s" % args.task)
        return

    if title == None or body == None:
        logger.info("Nothing to send. SKip sending email...")
        return

    logger.debug("TITLE: \n%s" % title)
    logger.debug("BODY: \n%s" % body)

    # compose_email(title, body)

if __name__ == "__main__":
    main()
