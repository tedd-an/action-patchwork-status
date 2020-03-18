#!/usr/bin/env python3
import os
import sys
import logging
import argparse
import subprocess
import re
from github import Github

logger = None

github_repo = None
github_pr = None
github_commits = None
repo_base = None
checkpatch_pl = None

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

    github_repo = Github(os.environ['GITHUB_TOKEN']).get_repo(args.repo)
    github_pr = github_repo.get_pull(args.pull_request)
    github_commits = github_pr.get_commits()

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
