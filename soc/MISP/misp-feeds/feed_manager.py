#!/usr/bin/python3

# Requirements:
# pip3 install coloredlogs pymisp

# References:
# https://buildmedia.readthedocs.org/media/pdf/pymisp/latest/pymisp.pdf

from abusech_misp import abusech_run
from misp_export import export_run
from otx_misp import otx_run
from pymisp import PyMISP
from twitter_misp import twitter_run
from xforce_misp import xforce_run

import coloredlogs
import logging
import time
import urllib3

MISP_TIMES = ['06:00', '18:00']
TEXT_TIMES = ['06:00', '12:00', '18:00', '00:00']
OTX_TIMES = ['06:00', '12:00', '18:00', '00:00']
TWITTER_TIMES = ['06:00', '12:00', '18:00', '00:00']
XFORCE_TIMES = ['06:00', '14:00', '22:00']
HOURLY_FEEDS = []

ENABLE_EXPORT = True
ENABLE ABUSECH = True
ENABLE_OTX = True
ENABLE_TWITTER = True
ENABLE_XFORCE = True

MISP_URL = 'MISP BASE URL'
MISP_ADMIN_KEY = 'MISP ADMIN KEY'
MISP_USER_KEY = 'MISP USER KEY'
MISP_VALIDATE_SSL = False

LOGGER = logging.getLogger('mispfeedmanager')
logging.basicConfig(filename='misp_feeds.log', format='%(asctime)s %(name)s %(levelname)s: %(message)s', level=logging.INFO)
coloredlogs.install(level='INFO')

def disable_ssl_warnings():
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def cache_feed(misp, feed):
    LOGGER.info('Caching feed: {0}'.format(feed.name))
    
    try:
        misp.cache_feed(feed.id)
        
    except Exception as ex:
        LOGGER.error('Failed to cache MISP feed: {0}'.format(str(ex)))

def fetch_feed(misp, feed):
    LOGGER.info('Fetching feed: {0}'.format(feed.name))
    
    try:
        fetch = misp.fetch_feed(feed.id)
        
    except Exception as ex:
        LOGGER.error('Failed to fetch MISP feed: {0}'.format(str(ex)))
        return

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
        current_time = time.strftime('%H:%M')

        if current_time.split(':')[1] == '00':
            LOGGER.info('Beginning hourly feed run...')

            for feed in misp_admin.feeds(pythonify=True):
                if feed.id in HOURLY_FEEDS:
                    fetch_feed(misp_admin, feed)
                    LOGGER.info('Waiting a moment...')
                    time.sleep(2)

            if ENABLE_ABUSECH:
                abusech_run(misp_user)

            LOGGER.info('Hourly feed run complete!')

        if current_time in MISP_TIMES:
            LOGGER.info('Beginning MISP feed run...')

            for feed in misp_admin.feeds(pythonify=True):
                if (feed.source_format == 'misp' and
                  feed.enabled and
                  feed.id not in HOURLY_FEEDS):
                    fetch_feed(misp_admin, feed)
                    LOGGER.info('Waiting a moment...')
                    time.sleep(2)

            LOGGER.info('MISP feed run complete!')

        if current_time in TEXT_TIMES:
            LOGGER.info('Beginning text feed run...')

            for feed in misp_admin.feeds(pythonify=True):
                if (feed.source_format in ['text', 'csv'] and
                  feed.enabled and
                  feed.id not in HOURLY_FEEDS):
                    fetch_feed(misp_admin, feed)
                    LOGGER.info('Waiting a moment...')
                    time.sleep(2)

            LOGGER.info('Text feed run complete!')

        if current_time in OTX_TIMES and ENABLE_OTX:
            LOGGER.info('Beginning OTX run...')
            otx_run(misp_user)
            LOGGER.info('OTX run complete!')

        if current_time in TWITTER_TIMES and ENABLE_TWITTER:
            LOGGER.info('Beginning Twitter run...')
            twitter_run(misp_user)
            LOGGER.info('Twitter run complete!')

        if current_time in XFORCE_TIMES and ENABLE_XFORCE:
            LOGGER.info('Beginning X-Force run...')
            xforce_run(misp_user)
            LOGGER.info('X-Force run completge!')

        if ENABLE_EXPORT:
            if current_time.split(':')[1] == '00':
                LOGGER.info('Beginning full export run...')
                export_run(misp_user, start_fresh=True)
                LOGGER.info('Full export run complete!')

            elif current_time.split(':')[1] in ['10','20','30','40','50']:
                LOGGER.info('Beginning partial export run...')
                export_run(misp_user)
                LOGGER.info('Partial export run complete!')

        time.sleep(60)

    LOGGER.info('Worker finished!')

if __name__ == '__main__':
    start_worker()
