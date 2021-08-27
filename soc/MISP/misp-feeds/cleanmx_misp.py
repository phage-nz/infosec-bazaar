#!/usr/bin/python3
from collections import Counter
from datetime import datetime, timedelta
from pymisp import PyMISP, MISPEvent, MISPAttribute, ThreatLevel, Distribution, Analysis

import coloredlogs
import json
import logging
import re
import requests
import sys
import time
import urllib.parse
import urllib3
import validators

LOGGER = logging.getLogger('cleanmxmisp')
logging.basicConfig(filename='misp_feeds.log', format='%(asctime)s %(name)s %(levelname)s: %(message)s', level=logging.INFO)
coloredlogs.install(level='INFO')

MISP_URL = 'MISP BASE URL'
MISP_API_KEY = 'MISP USER KEY'
MISP_EVENT_TITLE = 'CleanMX indicator feed'
MISP_VALIDATE_SSL = False
MISP_TO_IDS = False
MISP_PUBLISH_EVENTS = False

CLEANMX_AGENT = 'CLEANMX USER AGENT'

PHISHING_URL = 'http://support.clean-mx.de/clean-mx/xmlphishing?response=alive&format=json&domain='
VIRUS_URL = 'http://support.clean-mx.de/clean-mx/xmlviruses?response=alive&format=json&domain='

ATTRIBUTE_PROGRESS = True
SAMPLE_MAX_MINUTES = 300
SKIP_PHISHTANK = True

IP_BLACKLIST = []
URL_BLACKLIST = []

headers = {'User-Agent': CLEANMX_AGENT}

class FeedIndicator:
  def __init__(self, ref_comment, o_type, o_value):
    self.ref_comment = ref_comment
    self.o_type = o_type
    self.o_value = o_value

def disable_ssl_warnings():
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def is_valid_url(url):
    if any(s in url for s in URL_BLACKLIST):
        return False

    if any(s in url for s in IP_BLACKLIST):
        return False

    if url.endswith('\u2026'):
        return False

    # iocextract can incorrectly match on http://123.123:123
    if re.search(r'http://[0-9]{1,3}\.[0-9]{1,3}:[0-9]{1,5}', url):
        return False

    try:
        result = urllib.parse.urlparse(url)
        url_valid = all([result.scheme, result.netloc])
        return url_valid

    except Exception as ex:
        LOGGER.warning('Error validating URL: {0}'.format(str(ex)))

    return False

def make_new_event(misp):
    LOGGER.info('Creating new fixed event...')
    event = MISPEvent()
    event_date = datetime.now().strftime('%Y-%m-%d')
    event_title = '{0} {1}'.format(MISP_EVENT_TITLE, event_date)

    event.info = event_title
    event.analysis = Analysis.completed
    event.distribution = Distribution.your_organisation_only
    event.threat_level_id = ThreatLevel.low

    event.add_tag('type:OSINT')
    event.add_tag('tlp:amber')

    LOGGER.info('Saving event...')
    time.sleep(1)

    try:
        new_event = misp.add_event(event, pythonify=True)
        return new_event

    except Exception as ex:
        LOGGER.error('Failed to make MISP event: {0}'.format(str(ex)))
        return False

def get_phish_list():
    LOGGER.info('Fetching latest phishing URLs from CleanMX...')
    indicator_list = []

    try:
        headers = {'User-Agent': CLEANMX_AGENT}
        response = requests.get(PHISHING_URL, headers=headers)

        if response.status_code == 200:
            date_threshold = datetime.utcnow() - timedelta(minutes=SAMPLE_MAX_MINUTES)
            entries = json.loads(response.text)['entries']

            if not 'entry' in entries:
                LOGGER.warning('CleanMX did not return any items.')
                return []

            for entry in entries['entry']:
                entry_timestamp = datetime.utcfromtimestamp(int(entry['first']))

                if not entry_timestamp > date_threshold:
                    continue

                if SKIP_PHISHTANK and entry['phishtank'] != {}:
                    continue

                url_value = entry['url']

                if not is_valid_url(url_value):
                    continue

                indicator_list.append(FeedIndicator('cleanmx_phish', 'url', url_value))

    except Exception as e:
        LOGGER.error('CleanMX request error: {0}'.format(str(e)))

    return indicator_list

def get_virus_list():
    LOGGER.info('Fetching latest virus URLs from CleanMX...')
    indicator_list = []

    try:
        headers = {'User-Agent': CLEANMX_AGENT}
        response = requests.get(VIRUS_URL, headers=headers)

        if response.status_code == 200:
            date_threshold = datetime.utcnow() - timedelta(minutes=SAMPLE_MAX_MINUTES)
            entries = json.loads(response.text)['entries']

            if not 'entry' in entries:
                LOGGER.warning('CleanMX did not return any items.')
                return []

            for entry in entries['entry']:
                entry_timestamp = datetime.utcfromtimestamp(int(entry['first']))

                if not entry_timestamp > date_threshold:
                    continue

                if entry['virustotal'] != {}:
                    comment = entry['virusname']

                else:
                    comment = 'cleanmx_virus'

                url_value = entry['url']

                if not is_valid_url(url_value):
                    continue

                indicator_list.append(FeedIndicator(comment, 'url', url_value))

                hash_value = entry['md5']

                if hash_value == {}:
                    continue

                if re.search(r'\w{32}', hash_value):
                    indicator_list.append(FeedIndicator(comment, 'md5', hash_value))

    except Exception as e:
        LOGGER.error('CleanMX request error: {0}'.format(str(e)))

    return indicator_list

def process_indicators(misp, indicator_list):
    event = False
    event_date = datetime.now().strftime('%Y-%m-%d')
    event_title = '{0} {1}'.format(MISP_EVENT_TITLE, event_date)

    try:
        event_search = misp.search_index(eventinfo=event_title)

    except Exception as ex:
        LOGGER.error('Failed to search for MISP event: {0}'.format(str(ex)))
        return

    if not event_search == []:
        for result in event_search:
            if result['info'] == event_title:
                event = event_search[0]

    if event:
        LOGGER.warning('Event already exists!')

    else:
        event = make_new_event(misp)

    if not event:
        LOGGER.warning('Failed to make or retrieve event.')
        return

    indicator_count = len(indicator_list)
    LOGGER.info('Processing {0} indicators...'.format(indicator_count))

    for i, indicator in enumerate(indicator_list):
        if ATTRIBUTE_PROGRESS and i % 100 == 0:
            progress_value = int(round(100 * (i / float(indicator_count))))
            LOGGER.info('Event completion: {0}%'.format(progress_value))

        #LOGGER.info('Found {0} "{1}" in: {2}'.format(indicator.o_type, indicator.o_value, indicator.ref_url))

        attribute_type = indicator.o_type
        indicator_value = indicator.o_value
        indicator_comment = indicator.ref_comment

        attribute_exists = False

        try:
            attribute_search = misp.search(controller='attributes', value=indicator_value, type=attribute_type)

        except Exception as ex:
            LOGGER.error('Failed to search for MISP attribute: {0}'.format(str(ex)))
            continue

        if not attribute_search['Attribute'] == []:
            for attribute_result in attribute_search['Attribute']:
                if attribute_result['value'] == indicator_value:
                    if int(attribute_result['event_id']) == int(event['id']):
                        attribute_exists = True

        if attribute_exists:
            continue

        if attribute_type == 'md5':
            attribute_category = 'Payload delivery'

        elif attribute_type == 'url':
            attribute_category = 'Network activity'

        else:
            LOGGER.warning('Unsupported indicator type: {0}'.format(attribute_type))
            continue

        attribute_json = {'category': attribute_category, 'type': attribute_type, 'value': indicator_value, 'comment': indicator_comment, 'to_ids': MISP_TO_IDS}

        try:
            new_attr = misp.add_attribute(event, attribute_json, pythonify=True)

        except Exception as ex:
            LOGGER.error('Failed to add MISP attribute: {0}'.format(str(ex)))
            continue

    if MISP_PUBLISH_EVENTS:
        LOGGER.info('Publishing event...')

        try:
            misp.publish(event)

        except Exception as ex:
            LOGGER.error('Failed to publish MISP event: {0}'.format(str(ex)))

def cleanmx_run(misp):
    phishing_list = get_phish_list()

    if len(phishing_list) > 0:
        process_indicators(misp, phishing_list)

    else:
        LOGGER.warning('CleanMX phishing list is empty.')

    virus_list = get_virus_list()

    if len(virus_list) > 0:
        process_indicators(misp, virus_list)

    else:
        LOGGER.warning('CleanMX phishing list is empty.')

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

    cleanmx_run(misp)
