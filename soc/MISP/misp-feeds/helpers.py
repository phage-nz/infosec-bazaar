#!/usr/bin/python3

from collections import Counter
from config import *
from pymisp import PyMISP
from urllib.parse import urlparse

import coloredlogs
import config
import importlib
import logging
import os
import re
import sys
import urllib3
import validators

LOGGER = logging.getLogger('helpers')
logging.basicConfig(filename='misp_feeds.log', format='%(asctime)s %(name)s %(levelname)s: %(message)s', level=logging.INFO)
coloredlogs.install(level='INFO')

def disable_ssl_warnings():
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def is_valid_domain(domain):
    return validators.domain(domain)

def is_valid_url(url):
    if any(s in url for s in config.URL_BLACKLIST):
        return False

    if any(s in url for s in config.IP_BLACKLIST):
        return False

    if url.endswith('\u2026'):
        return False

    # iocextract can incorrectly match on http://123.123:123
    if re.search(r'http://[0-9]{1,3}\.[0-9]{1,3}:[0-9]{1,5}', url):
        return False

    try:
        result = urlparse(url)
        url_valid = all([result.scheme, result.netloc])
        return url_valid

    except Exception as ex:
        LOGGER.warning('Error validating URL: {0}'.format(str(ex)))

    return False

def is_valid_ip(ip):
    if any(s in ip for s in config.IP_BLACKLIST):
        return False

    return validators.ipv4(ip)

def get_tags(misp, term, mode='contains'):
    tags = [x.name for x in misp.tags(pythonify=True) if 'misp-galaxy' in x.name]

    if mode == 'endswith':
        return [t for t in tags if t.lower().endswith(term.lower())]

    return [t for t in tags if term.lower() in t.lower()]

def get_textblock_tags(misp, input):
    tags = [x.name for x in misp.tags(pythonify=True) if 'misp-galaxy' in x.name]

    event_tags = []

    for tag in tags:
        if tag.lower() in TAG_BLACKLIST:
            continue

        if '"' in tag:
            keyword = re.findall(r'"(.*?)"', tag)[0]

        else:
            keyword = tag

        if ' - ' in keyword:
            keyword = keyword.split(' - ')[0]

        if keyword:
            if keyword in input:
                event_tags.append(tag)

    return event_tags

def apply_url_fixes(url):
    # Handle unconventional defanging:
    if url.startswith('p://'):
        url = url.replace('p://', 'http://')

    if url.startswith('s://'):
        url = url.replace('s://', 'https://')

    return url

def get_hash_type(hash):
    repeat_threshold = int(len(hash)/2)

    if [i for i,j in Counter(hash).items() if j>repeat_threshold]:
        LOGGER.warning('High number of repeat characters detected in string. Potential binary or script segment.')
        return False

    if re.search(r'[A-Fa-f0-9]{64}$', hash):
        return 'FileHash-SHA256'

    if re.search(r'[A-Fa-f0-9]{40}$', hash):
        return 'FileHash-SHA1'

    if re.search(r'[A-Fa-f0-9]{32}$', hash):
        return 'FileHash-MD5'

    return False

def load_plugins():
    LOGGER.info('Loading plugins...')

    try:
        modules = []

        py_re = re.compile('.py$', re.IGNORECASE)
        plugin_files = filter(py_re.search, os.listdir(os.path.join(os.path.dirname(__file__), 'plugins')))
        form_module = lambda fp: '.' + os.path.splitext(fp)[0]
        plugins = map(form_module, plugin_files)
        importlib.import_module('plugins')

        for plugin in plugins:
            if not plugin.startswith('.__'):
                modules.append(importlib.import_module(plugin, package='plugins'))

        return modules

    except Exception as e:
        LOGGER.error('Problem loading plugins. Exception: {0}'.format(str(e)))

    sys.exit(1)

def misp_admin_connection():
    LOGGER.info('Setting up MISP admin connector...')
    if MISP_VALIDATE_SSL == False:
        disable_ssl_warnings()

    try:
        misp_admin = PyMISP(MISP_URL, MISP_ADMIN_KEY, ssl=MISP_VALIDATE_SSL)
        LOGGER.info('Admin connector OK!')

        return misp_admin

    except Exception as ex:
        LOGGER.error('Failed to connect to MISP: {0}'.format(str(ex)))
        sys.exit(1)

def misp_user_connection():
    LOGGER.info('Setting up MISP user connector...')
    if MISP_VALIDATE_SSL == False:
        disable_ssl_warnings()

    try:
        misp_user = PyMISP(MISP_URL, MISP_USER_KEY, ssl=MISP_VALIDATE_SSL)
        LOGGER.info('User connector OK!')

        return misp_user

    except Exception as ex:
        LOGGER.error('Failed to connect to MISP: {0}'.format(str(ex)))
        sys.exit(1)
