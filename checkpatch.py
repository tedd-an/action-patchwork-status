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
from github import Github
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

logger = None

github_repo = None
github_pr = None
github_commits = None
patchwork_sid = None
repo_base = None
checkpatch_pl = None

PATCHWORK_BASE_URL = "https://patchwork.kernel.org/api/1.1"

FAIL_MSG = '''
This is automated email and please do not replay to this email!

Dear submitter,

Thank you for submitting the patches to the linux bluetooth mailing list.
While we are preparing for reviewing the patches, we found the following
issue/warning.


Test Result:
Checkpatch Failed

Patch Title:
{}

Output:
{}


For more details about BlueZ coding style guide, please find it
in doc/coding-style.txt

---
Regards,
Linux Bluetooth
'''

def err_exit(msg):
    sys.exit("ERROR: " + msg)

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

def init_github(args):
    """ Initialize github object """

    global github_repo
    global github_pr
    global github_commits
    global patchwork_sid

    github_repo = Github(os.environ['GITHUB_TOKEN']).get_repo(args.repo)
    github_pr = github_repo.get_pull(args.pull_request)
    github_commits = github_pr.get_commits()
    patchwork_sid = get_pw_sid(github_pr.title)

def get_pw_sid(pr_title):
    """
    Parse PR title prefix and get PatchWork Series ID
    PR Title Prefix = "[PW_S_ID:<series_id>] XXXXX"
    """

    try:
        sid = re.search(r'^\[PW_SID:([0-9]+)\]', pr_title).group(1)
    except AttributeError:
        logging.error("Unable to find the series_id from title %s" % pr_title)
        sid = None

    return sid

def requests_url(url):
    """ Helper function to requests WEB API GET with URL """

    resp = requests.get(url)
    if resp.status_code != 200:
        raise requests.HTTPError("GET {}".format(resp.status_code))

    return resp

def post_github_comment(msg):
    """ Post message to PR comment """

    # TODO: If the comment alrady exist, edit instead of create new one

    github_pr.create_issue_comment(msg)

def checkpatch_success_msg(extra_msg=None):
    """ Generate success message """

    msg = "**Checkpatch passed.**\n\n"

    if extra_msg != None:
        msg += extra_msg

    return msg

def checkpatch_fail_msg(outputs):
    """ Generate fail message with checkpatch output """

    msg = "**Checkpatch failed.**\n\n"
    msg += "```\n"
    for output in outputs:
        msg += output
    msg += "```\n"

    return msg

def check_patch(sha):
    """ Run checkpatch script with commit """

    output = None

    logging.info("Commit SHA: %s" % sha)

    diff = subprocess.Popen(('git', 'show', '--format=email', sha),
                            stdout=subprocess.PIPE)
    try:
        subprocess.check_output((checkpatch_pl, '--no-tree', '-'),
                                stdin=diff.stdout,
                                stderr=subprocess.STDOUT,
                                shell=True)
    except subprocess.CalledProcessError as ex:
        output = ex.output.decode("utf-8")
        logging.error("checkpatch returned error/warning")
        logging.error("output: %s" % output)

    return output

def send_email(sender, receiver, msg):
    """ Send email """

    if 'EMAIL_TOKEN' not in os.environ:
        logging.warning("missing EMAIL_TOKEN. Skip sending email")
        return

    try:
        session = smtplib.SMTP('smtp.gmail.com', 587)
        session.ehlo()
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

def patchwork_get_series(sid):
    """ Get series detail from patchwork """

    url = PATCHWORK_BASE_URL + "/series/" + sid
    req = requests_url(url)

    return req.json()

def get_patch_details(commit):
    """
    Use the patch title from github commit to get the patch details from
    the PatchWork
    """

    # Patch title from github commit
    title = commit.commit.message.splitlines()[0]
    logging.debug("Commit Title: {}".format(title))

    # Get Patchwork series
    series = patchwork_get_series(patchwork_sid)
    logging.debug("Got Patchwork Series: {}".format(series))

    # Go throuhg each patch in the series to find the patch contains title
    for patch in series["patches"]:
        # Need to add a space in the front for some corner case.
        if (patch['name'].find(title) != -1):
            logging.debug("Found matching patch title")
            req = requests_url(patch['url'])
            return req.json()
        else:
            logging.debug("Title not match.")

    logging.error("Cannot find matching patch from Patchwork")

    return None

def notify_failure(commit, output):
    """ Send checkpatch failure to mailing list """

    sender = 'bluez.test.bot@gmail.com'

    receivers = []

    receivers.append('Tedd An <tedd.an@linux.intel.com>')
    receivers.append('Tedd Ho-Jeong An <tedd.an@intel.com>')

    # Get patch details from Patchwork with github commit
    patch = get_patch_details(commit)

    # Create message
    msg = MIMEMultipart()
    msg['From'] = sender
    msg['To'] = ", ".join(receivers)
    msg['Subject'] = "RE: " + patch['name']

    # Message Header
    msg.add_header('In-Reply-To', patch['msgid'])
    msg.add_header('References', patch['msgid'])

    body = FAIL_MSG.format(patch['name'], output)
    logging.debug("Message Body: {}".format(body))
    msg.attach(MIMEText(body, 'plain'))

    logging.debug("Mail Message: {}".format(msg))

    # Send email
    send_email(sender, receivers, msg)

def check_args(args):
    """ Check input arguments and environment variables """

    global checkpatch_pl

    if 'GITHUB_TOKEN' not in os.environ:
        err_exit("Cannot find GITHUB_TOKEN from environment variable")

    if args.checkpatch != None:
        if not os.path.exists(args.checkpatch):
            err_exit("Cannot find checkpatch.pl from %s" % args.checkpatch)
        checkpatch_pl = args.checkpatch
        logging.debug("Reading checkpatch.pl from input parameter")
    else:
        if 'CHECKPATCH_PATH' not in os.environ:
            err_exit("Cannot find CHECKPATCH_PATH from environment variable")
        checkpatch_pl = os.environ['CHECKPATCH_PATH']
        logging.debug("Reading checkpatch.pl from environmebt variable")
    logging.info("checkpatch.pl path: %s" % checkpatch_pl)

def parse_args():
    parser = argparse.ArgumentParser(
        description="Check patch style in the pull request")
    parser.add_argument('-p', '--pull-request', required=True, type=int,
                        help='Pull request number')
    parser.add_argument('-r', '--repo', required=True,
                        help='Github repo in :owner/:repo')

    parser.add_argument('-c', '--checkpatch', default=None,
                        help='Absolute path of checkpatch.pl')

    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Display debugging info')
    return parser.parse_args()

def main():
    args = parse_args()
    check_args(args)

    init_logging(args.verbose)

    init_github(args)

    outputs = []

    for commit in github_commits:
        output = check_patch(commit.sha)
        if output != None:
            outputs.append(output)
            # Send email to mailing list for failure
            notify_failure(commit, output)

    logging.debug("outputs length = %d" % len(outputs))

    if len(outputs) != 0:
        logging.debug("Post fail message to PR")
        post_github_comment(checkpatch_fail_msg(outputs))
        logging.info("Script terminate with non-zero(1)")
        sys.exit(1)

    logging.debug("Post success message to PR")
    post_github_comment(checkpatch_success_msg())
    logging.info("Script terminate with zero(0)")
    sys.exit(0)


if __name__ == "__main__":
    main()
