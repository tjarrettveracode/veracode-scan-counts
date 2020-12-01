import sys
import requests
import argparse
import logging
import json
import datetime

import anticrlf
from veracode_api_py import VeracodeAPI as vapi

log = logging.getLogger(__name__)

def setup_logger():
    handler = logging.FileHandler('vcscancounts.log', encoding='utf8')
    handler.setFormatter(anticrlf.LogFormatter('%(asctime)s - %(levelname)s - %(funcName)s - %(message)s'))
    logger = logging.getLogger(__name__)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)

def creds_expire_days_warning():
    creds = vapi().get_creds()
    exp = datetime.datetime.strptime(creds['expiration_ts'], "%Y-%m-%dT%H:%M:%S.%f%z")
    delta = exp - datetime.datetime.now().astimezone() #we get a datetime with timezone...
    if (delta.days < 7):
        print('These API credentials expire ', creds['expiration_ts'])

def get_all_apps():
    applist = vapi().get_apps()
    return applist

def get_incomplete_scans(app_info):
    appscancount = 0
    #first check state of policy scan
    this_app_guid = app_info.get('guid')
    log.debug('Checking application guid {} named {} for scan status'.format(this_app_guid, app_info.get('profile').get('name')))
    scans = app_info["scans"]

    try:
        static_scan = next(scan for scan in scans if scan["scan_type"] == "STATIC")
        if static_scan != None and static_scan["status"] != 'PUBLISHED':
            log.info('Status for static policy scan with url {} was {}'.format(static_scan["scan_url"],static_scan["status"]))
            appscancount = 1
    except StopIteration:
        log.debug('Application guid {} named {} has no static scans'.format(this_app_guid, app_info.get('profile').get('name')))
        static_scan = None

    #then check for sandboxes
    appscancount += get_incomplete_sandbox_scans(this_app_guid)
    return appscancount

def get_incomplete_sandbox_scans(this_app_guid):
    sandboxes = vapi().get_sandbox_list(this_app_guid)

    sandboxscancount = 0

    for sandbox in sandboxes:
        #check sandbox scan list, need to fall back to XML APIs for this part
        sandboxscancount = 0

    return sandboxscancount

def main():
    parser = argparse.ArgumentParser(
        description='This script identifies applications with one or more static scans in an incomplete state.')
    parser.add_argument('-a', '--application', required=False, help='Application guid to check for incomplete static scans.')
    parser.add_argument('--all', '-l',action='store_true')
    args = parser.parse_args()

    appguid = args.application
    checkall = args.all

    # CHECK FOR CREDENTIALS EXPIRATION
    creds_expire_days_warning()

    count=0

    if checkall:
        applist = get_all_apps()
        log.info("Checking {} applications for incomplete scans".format(len(applist)))
        for app in applist:
            count += get_incomplete_scans(app)
    elif appguid != None:
        count += get_incomplete_scans(appguid)
    else:
        print('You must provide either an application guid or check all applications.')
        return
    
    print("Identified {} applications with incomplete scans. See vcscancounts.log for details.".format(count))
    log.info("Identified {} applications with incomplete scans."format(count))
    
if __name__ == '__main__':
    setup_logger()
    main()