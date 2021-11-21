#!/usr/bin/python3

# Requirements:
# pip3 install coloredlogs pymisp

# References:
# https://buildmedia.readthedocs.org/media/pdf/pymisp/latest/pymisp.pdf

from config import *
from export import export_run
from helpers import disable_ssl_warnings, load_plugins, misp_admin_connection, misp_user_connection

import coloredlogs
import logging
import sys
import time

LOGGER = logging.getLogger('mispfeedmanager')
logging.basicConfig(filename='misp_feeds.log', format='%(asctime)s %(name)s %(levelname)s: %(message)s', level=logging.INFO)
coloredlogs.install(level='INFO')

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
    misp_admin = misp_admin_connection()
    misp_user = misp_user_connection()

    feed_plugins = load_plugins()

    if feed_plugins:
        enabled_plugins = [x for x in feed_plugins if x.PLUGIN_ENABLED == True]

        LOGGER.info('Plugins enabled:')

        for plugin in enabled_plugins:
            LOGGER.info(plugin.PLUGIN_NAME)

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

            hourly_plugins = [x for x in enabled_plugins if 'hourly' in x.PLUGIN_TIMES]

            if hourly_plugins:
                for plugin in hourly_plugins:
                    LOGGER.info('Beginning {0} plugin run...'.format(plugin.PLUGIN_NAME))
                    plugin.plugin_run(misp_user)

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

        due_plugins = [x for x in enabled_plugins if current_time in x.PLUGIN_TIMES]

        if due_plugins:
            for plugin in due_plugins:
                LOGGER.info('Beginning {0} plugin run...'.format(plugin.PLUGIN_NAME))
                plugin.plugin_run(misp_user)

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
