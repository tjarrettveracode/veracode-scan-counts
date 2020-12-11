import sys
import requests
import argparse
import logging
import json
import datetime
from lxml import etree

import anticrlf
from veracode_api_py import VeracodeAPI as vapi

log = logging.getLogger(__name__)

def setup_logger():
    handler = logging.FileHandler('vcscancounts.log', encoding='utf8')
    handler.setFormatter(anticrlf.LogFormatter('%(asctime)s - %(levelname)s - %(funcName)s - %(message)s'))
    logger = logging.getLogger(__name__)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

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
    this_app_id = app_info.get('id')
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
        appscancount += get_incomplete_sandbox_scans(this_app_guid, this_app_id)
    return appscancount

def get_incomplete_sandbox_scans(this_app_guid, this_app_id):
    sandboxes = vapi().get_app_sandboxes(this_app_guid)

    sandboxscancount = 0

    for sandbox in sandboxes:
        log.debug("Checking sandboxes for application guid {}".format(this_app_guid))
        #check sandbox scan list, need to fall back to XML APIs for this part
        sandboxscancount = 0
        sandboxid = sandbox.get('id')
        data = vapi().get_build_info(app_id=this_app_id, sandbox_id=sandboxid) #returns most recent build for sandbox

        builds = etree.fromstring(data)
        buildid = builds[0].get('build_id')
        log.debug("Checking application guid {}, sandbox {}, build {}".format(this_app_guid, sandboxid, buildid))
        status = builds[0].get('results_ready')

        if status == 'false':
            log.info("Status for sandbox scan {} in sandbox id {} for application {} was {}".format(buildid, sandboxid, this_app_guid, status))
            sandboxscancount += 1

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

    appcount=0
    scancount=0

    if checkall:
        applist = get_all_apps()
        status = "Checking {} applications for incomplete scans".format(len(applist))
        log.info(status)
        print(status)
        for app in applist:
            this_app_scans = get_incomplete_scans(app)
            if this_app_scans > 0:
                appcount +=1
                scancount += this_app_scans
    elif appguid != None:
        scancount += get_incomplete_scans(appguid)
        if scancount > 0:
            appcount = 1
    else:
        print('You must provide either an application guid or check all applications.')
        return
    
    print("Identified {} applications with {} incomplete scans. See vcscancounts.log for details.".format(appcount,scancount))
    log.info("Identified {} applications with {} incomplete scans.".format(appcount,scancount))
    
if __name__ == '__main__':
    setup_logger()
    main()