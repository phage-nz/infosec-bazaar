#!/usr/bin/python3

# References:
# https://buildmedia.readthedocs.org/media/pdf/pymisp/latest/pymisp.pdf

from otx_misp import otx_run
from pymisp import PyMISP

import coloredlogs
import logging
import time
import urllib3

MISP_TIMES = ['08:00', '20:00']
TEXT_TIMES = ['06:00', '14:00', '22:00']
OTX_TIMES = ['06:00', '18:00']
HOURLY_FEEDS = ['16', '33', '42']

MISP_URL = 'https://misp.yourdomain.com'
MISP_ADMIN_KEY = 'YOUR ADMIN KEY'
MISP_USER_KEY = 'YOUR USER KEY'
MISP_VALIDATE_SSL = False

TEST_RUN = False

LOGGER = logging.getLogger('mispfeedmanager')
logging.basicConfig(filename='misp_feeds.log', format='%(asctime)s %(name)s %(levelname)s: %(message)s', level=logging.INFO)
coloredlogs.install(level='INFO')

def disable_ssl_warnings():
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def cache_feed(misp, feed):
    LOGGER.info('Caching feed: {0}'.format(feed.name))
    misp.cache_feed(feed.id)

def fetch_feed(misp, feed):
    LOGGER.info('Fetching feed: {0}'.format(feed.name))
    fetch = misp.fetch_feed(feed.id)

    if 'result' in fetch:
        if 'Pull queued' in fetch['result']:
            LOGGER.info('Feed queued OK!')

            if feed.caching_enabled:
                cache_feed(misp, feed)

    else:
        LOGGER.error('Failed to queue feed.')

def start_worker():
    LOGGER.info('Setting up MISP connector...')
    if MISP_VALIDATE_SSL == False:
        disable_ssl_warnings()

    try:
        misp_admin = PyMISP(MISP_URL, MISP_ADMIN_KEY, ssl=MISP_VALIDATE_SSL)
        LOGGER.info('Admin connector OK!')

        misp_user = PyMISP(MISP_URL, MISP_USER_KEY, ssl=MISP_VALIDATE_SSL)
        LOGGER.info('User connector OK!')

    except Exception as ex:
        LOGGER.error('Failed to connect to MISP: {0}'.format(str(ex)))
        sys.exit(1)

    LOGGER.info('Starting MISP feeds worker...')

    while True:
        run_start = time.strftime('%H:%M')

        if run_start.split(':')[1] == '00' or TEST_RUN:
            LOGGER.info('Beginning hourly feed run...')

            for feed in misp_admin.feeds(pythonify=True):
                if feed.id in HOURLY_FEEDS:
                    fetch_feed(misp_admin, feed)
                    LOGGER.info('Waiting a moment...')
                    time.sleep(2)

            LOGGER.info('Hourly feed run complete!')

        if run_start in MISP_TIMES or TEST_RUN:
            LOGGER.info('Beginning MISP feed run...')

            for feed in misp_admin.feeds(pythonify=True):
                if (feed.source_format == 'misp' and
                  feed.enabled and
                  feed.id not in HOURLY_FEEDS):
                    fetch_feed(misp_admin, feed)
                    LOGGER.info('Waiting a moment...')
                    time.sleep(2)

            LOGGER.info('MISP feed run complete!')

        if run_start in TEXT_TIMES or TEST_RUN:
            LOGGER.info('Beginning text feed run...')

            for feed in misp_admin.feeds(pythonify=True):
                if (feed.source_format in ['text', 'csv'] and
                  feed.enabled and
                  feed.id not in HOURLY_FEEDS):
                    fetch_feed(misp_admin, feed)
                    LOGGER.info('Waiting a moment...')
                    time.sleep(2)

            LOGGER.info('Text feed run complete!')

        if run_start in OTX_TIMES or TEST_RUN:
            LOGGER.info('Beginning OTX run...')
            otx_run(misp_user)
            LOGGER.info('OTX run complete!')

        time.sleep(60)

    LOGGER.info('Worker finished!')

if __name__ == '__main__':
    start_worker()
