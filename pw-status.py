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
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

logger = None
config = None

PW_BASE_URL = "https://patchwork.kernel.org/api/1.2"
PW_BT_PROJECT_ID= "395"

def send_email(sender, receiver, msg):
    """ Send email """

    email_cfg = config['email']

    if 'EMAIL_TOKEN' not in os.environ:
        logging.warning("missing EMAIL_TOKEN. Skip sending email")
        return

    try:
        session = smtplib.SMTP(email_cfg['server'], int(email_cfg['port']))
        session.ehlo()
        if 'starttls' not in email_cfg or email_cfg['starttls'] == 'yes':
            session.starttls()
        session.ehlo()
        session.login(sender, os.environ['EMAIL_TOKEN'])
        session.sendmail(sender, receiver, msg.as_string())
        logging.info("Successfully sent email")
    except Exception as e:
        logging.error("Exception: {}".format(e))
    finally:
        session.quit()

    logging.info("Sending email done")

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

def pw_get_series(sid):
    """ Get series detail from patchwork """

    url = PW_BASE_URL + "/series/" + sid + "/"
    req = requests_url(url)

    return req.json()

def pw_get_patches_by_state(state):
    """
    Get the array of patches with given state
    """

    patches = []

    url = '{}/patches/?project={}&state={}&archived=0'.format(PW_BASE_URL,
                                                              PW_BT_PROJECT_ID,
                                                              state)
    while True:
        resp = requests_url(url)
        patches = patches + resp.json()

        if "next" not in resp.links:
            logger.debug("Read all patches: Total %d" % len(patches))
            break

        logger.debug("Read Next Page")
        url = resp.links["next"]["url"]

    return patches

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

    logging.info("Initialized the logger: level=%s",
                 logging.getLevelName(logger.getEffectiveLevel()))

def parse_args():
    parser = argparse.ArgumentParser(
        description="Check patch style in the pull request")
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Display debugging info')
    return parser.parse_args()

body_header = '''
List of patch series in New state
=================================

'''

body_footer = '''

------------
Best Regards
BlueZ Team
'''

def main():
    args = parse_args()

    init_logging(args.verbose)
    init_config()

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

    body += body_footer

    logger.debug("BODY: \n%s" % body)

    compose_email(title, body)


if __name__ == "__main__":
    main()
