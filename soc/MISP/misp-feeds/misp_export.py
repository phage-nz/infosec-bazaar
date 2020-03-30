#!/usr/bin/python3

from datetime import datetime, timedelta
from pymisp import PyMISP

import coloredlogs
import logging
import os
import sys
import time
import urllib3

LOGGER = logging.getLogger('mispexport')
logging.basicConfig(filename='misp_feeds.log', format='%(asctime)s %(name)s %(levelname)s: %(message)s', level=logging.INFO)
coloredlogs.install(level='INFO')

MISP_URL = 'https://misp.domain.com'
MISP_API_KEY = 'YOUR KEY'
MISP_VALIDATE_SSL = False

EXPORT_DAYS = 90
EXPORT_PAGE_SIZE = 5000
EXPORT_TAGS = ['tlp:white','tlp:green','osint:source-type="block-or-filter-list"']
EXPORT_TYPES = ['domain','hostname','url','ip-dst','ip-src']
EXPORT_MERGE_HOSTNAME = True
EXPORT_PATH = '/var/www/MISP/app/webroot/export'
EXPORT_KEY = 'RANDOM STRING'

def disable_ssl_warnings():
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_api():
    auth = tweepy.auth.OAuthHandler(CONSUMER_KEY, CONSUMER_SECRET)
    auth.set_access_token(ACCESS_TOKEN, ACCESS_TOKEN_SECRET)

    return tweepy.API(auth, wait_on_rate_limit=THROTTLE_REQUESTS)

def export_run(misp, start_fresh=False):
    for attr_type in EXPORT_TYPES:
        if EXPORT_MERGE_HOSTNAME:
            if all(t in EXPORT_TYPES for t in ['domain', 'hostname']) and attr_type == 'domain':
                LOGGER.info('Collecting attribute types: domain, hostname')
                attr_type = ['domain', 'hostname']
                out_path = os.path.join(EXPORT_PATH, 'domain_{0}.txt'.format(EXPORT_KEY))

            if all(t in EXPORT_TYPES for t in ['domain', 'hostname']) and attr_type == 'hostname':
                continue

        if attr_type != ['domain', 'hostname']:
            LOGGER.info('Collecting attribute type: {0}'.format(attr_type))
            file_name = '{0}_{1}.txt'.format(attr_type, EXPORT_KEY)
            out_path = os.path.join(EXPORT_PATH, file_name)

        if not os.path.exists(out_path):
            LOGGER.info('Making new file: {0}'.format(out_path))
            open(out_path, mode='a').close()

        LOGGER.info('Writing to: {0}'.format(out_path))

        attr_page = 0

        if start_fresh:
            LOGGER.info('Performing full update.')
            date_from = (datetime.utcnow() - timedelta(days=EXPORT_DAYS)).strftime('%Y-%m-%d')

        else:
            LOGGER.info('Performing partial update.')
            date_from = (datetime.utcnow() - timedelta(days=1)).strftime('%Y-%m-%d')

        attr_list = []

        while True:
            attr_search = misp.search(controller='attributes', type_attribute=attr_type, tags=EXPORT_TAGS, date_from=date_from, limit=EXPORT_PAGE_SIZE, page=attr_page, return_format='csv', requested_attributes=['value'], headerless=True, metadata=False)
            attr_lines = attr_search.splitlines()

            if len(attr_lines) > 1:
                LOGGER.info('Fetched page: {0}'.format(attr_page))
                page_list = [attr[1:-1] for attr in attr_lines]
                attr_list.extend(page_list)
                attr_page += 1

            else:
                break

        if attr_list:
            if start_fresh:
                LOGGER.info('Saving all attributes...')
                attr_set = set(attr_list)

            else:
                LOGGER.info('Saving new attributes...')

                with open(out_path, mode='rt', encoding='utf-8') as in_file:
                    current_list = [line.rstrip('\n') for line in in_file]

                if current_list:
                    LOGGER.info('Merging with current list...')
                    attr_set = set(current_list + attr_list)

                else:
                    LOGGER.info('File is currently empty.')
                    attr_set = set(attr_list)

            with open(out_path, mode='wt', encoding='utf-8') as out_file:
                sorted_list = sorted(list(attr_set))
                out_file.write('\n'.join(sorted_list))

        else:
            LOGGER.warning('No attributes returned.')

    LOGGER.info('Run complete!')

if __name__ == '__main__':
    LOGGER.info('Setting up MISP connector...')

    if MISP_VALIDATE_SSL == False:
        disable_ssl_warnings()

    try:
        misp = PyMISP(MISP_URL, MISP_API_KEY, ssl=MISP_VALIDATE_SSL)

    except Exception as ex:
        LOGGER.error('Failed to connect to MISP: {0}'.format(str(ex)))
        sys.exit(1)

    export_run(misp)