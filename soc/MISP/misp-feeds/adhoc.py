#!/usr/bin/python3

from config import *
from helpers import misp_user_connection, load_plugins
from pymisp import PyMISP

import coloredlogs
import logging
import sys

LOGGER = logging.getLogger('adhoc')
logging.basicConfig(filename='misp_feeds.log', format='%(asctime)s %(name)s %(levelname)s: %(message)s', level=logging.INFO)
coloredlogs.install(level='INFO')

def run_adhoc(plugin_name):
    misp_user = misp_user_connection()
    feed_plugins = load_plugins()

    if feed_plugins:
        valid_plugin = [x for x in feed_plugins if x.PLUGIN_NAME.lower() == plugin_name.lower()]

        if valid_plugin:
            selected_plugin = valid_plugin[0]
            LOGGER.info('Starting ad-hoc {0} plugin run...'.format(selected_plugin.PLUGIN_NAME))
            selected_plugin.plugin_run(misp_user)

        else:
            LOGGER.warning('No matching plugin found.')

    else:
        LOGGER.error('There are no plugins to load.')
        sys.exit(1)

plugin_name = input('[?] Plugin name: ')
run_adhoc(plugin_name)
