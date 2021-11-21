#!/usr/bin/python3

from collections import Counter
from config import *
from datetime import datetime, timedelta
from helpers import disable_ssl_warnings, is_valid_domain, is_valid_url, is_valid_ip, get_tags
from pymisp import MISPEvent, MISPAttribute, ThreatLevel, Distribution, Analysis

from pprint import pprint

import coloredlogs
import csv
import json
import logging
import re
import sys
import requests
import time

LOGGER = logging.getLogger('abusechmisp')
logging.basicConfig(filename='misp_feeds.log', format='%(asctime)s %(name)s %(levelname)s: %(message)s', level=logging.INFO)
coloredlogs.install(level='INFO')

PLUGIN_NAME = 'Abuse.CH'
PLUGIN_ENABLED = True
PLUGIN_TIMES = ['hourly']

MISP_EVENT_TITLE = 'Abuse.ch indicator feed'
MISP_TO_IDS = False
MISP_PUBLISH_EVENTS = False

FEODOTRACKER_URL = 'https://feodotracker.abuse.ch/downloads/ipblocklist.csv'
MALWAREBAZAAR_URL = 'https://bazaar.abuse.ch/export/csv/recent/'
THREATFOX_URL = 'https://threatfox.abuse.ch/export/json/recent/'
URLHAUS_URL = 'https://urlhaus.abuse.ch/downloads/csv_recent/'

ATTRIBUTE_PROGRESS = True
SAMPLE_MAX_MINUTES = 70
SHA256_ONLY = True

class FeedIndicator:
  def __init__(self, ref_comment, ref_tags, o_type, o_value):
    self.ref_comment = ref_comment
    self.ref_tags = ref_tags
    self.o_type = o_type
    self.o_value = o_value

def is_valid_sample(tags):
    if tags:
        if any(x.lower() in SAMPLE_BLACKLIST for x in tags):
            return False

    return True

def make_new_event(misp):
    LOGGER.info('Creating new fixed event...')
    event = MISPEvent()
    event_date = datetime.now().strftime('%Y-%m-%d')
    event_title = '{0} {1}'.format(MISP_EVENT_TITLE, event_date)

    event.info = event_title
    event.analysis = Analysis.completed
    event.distribution = Distribution.your_organisation_only
    event.threat_level_id = ThreatLevel.low

    event.add_tag('abuse.ch')
    event.add_tag('type:OSINT')
    event.add_tag('tlp:white')

    LOGGER.info('Saving event...')
    time.sleep(1)

    try:
        new_event = misp.add_event(event, pythonify=True)
        return new_event

    except Exception as ex:
        LOGGER.error('Failed to make MISP event: {0}'.format(str(ex)))
        return False

def get_urlhaus_list():
    LOGGER.info('Fetching latest URLs from URLhaus...')
    indicator_list = []

    try:
        response = requests.get(URLHAUS_URL)

        if response.status_code == 200:
            content = response.text
            reader = csv.reader(content.splitlines(), delimiter=',')
            valid_lines = [line for line in list(reader) if len(line) == 8]
            date_threshold = datetime.utcnow() - timedelta(minutes=SAMPLE_MAX_MINUTES)

            for line in valid_lines:
                if line[0].startswith('#'):
                    continue

                line_timestamp = datetime.strptime(line[1], '%Y-%m-%d %H:%M:%S')

                if not line_timestamp > date_threshold:
                    continue

                url = line[2]
                tags = line[5]

                if tags:
                    tags = tags.split(',')

                    if not is_valid_sample(tags):
                        continue

                comment = line[6]

                if not is_valid_sample(tags):
                    continue

                if not is_valid_url(url):
                    continue

                indicator_list.append(FeedIndicator(comment, tags, 'url', url))

    except Exception as e:
        LOGGER.error('URLhaus request error: {0}'.format(str(e)))

    return indicator_list

def get_feodo_list():
    LOGGER.info('Fetching latest IPs from FeodoTracker...')
    indicator_list = []

    try:
        response = requests.get(FEODOTRACKER_URL)

        if response.status_code == 200:
            content = response.text
            reader = csv.reader(content.splitlines(), delimiter=',')
            valid_lines = [line for line in list(reader) if len(line) == 6]
            date_threshold = datetime.utcnow() - timedelta(minutes=SAMPLE_MAX_MINUTES)

            for line in valid_lines:
                if line[0].startswith('#') or 'first_seen' in line[0]:
                    continue

                line_timestamp = datetime.strptime(line[0], '%Y-%m-%d %H:%M:%S')

                if not line_timestamp > date_threshold:
                    continue

                ip = line[1]
                port = line[2]
                tags = line[5]

                if tags:
                    tags = tags.split(',')

                    if not is_valid_sample(tags):
                        continue

                comment = 'https://feodotracker.abuse.ch/browse/host/{0}/'.format(ip)

                if not is_valid_ip(ip):
                    continue

                indicator_list.append(FeedIndicator(comment, tags, 'ip-dst|port', '{0}|{1}'.format(ip,port)))

    except Exception as e:
        LOGGER.error('FeodoTracker request error: {0}'.format(str(e)))

    return indicator_list

def get_threatfox_list():
    LOGGER.info('Fetching latest IOCs from ThreatFox...')
    indicator_list = []

    try:
        response = requests.get(THREATFOX_URL)

        if response.status_code == 200:
            content = response.text
            entries = json.loads(response.text)
            date_threshold = datetime.utcnow() - timedelta(minutes=SAMPLE_MAX_MINUTES)

            for entry_id in entries:
                entry = entries[entry_id][0]
                entry_timestamp = datetime.strptime(entry['first_seen_utc'], '%Y-%m-%d %H:%M:%S')

                if not entry_timestamp > date_threshold:
                    continue

                ioc_value = entry['ioc_value']
                ioc_type = entry['ioc_type']
                tags = []

                if entry['malware']:
                    tags.append(entry['malware'])

                if entry['malware_printable']:
                    tags.append(entry['malware_printable'])

                if not is_valid_sample(tags):
                    continue

                comment = 'https://threatfox.abuse.ch/ioc/{0}/'.format(entry_id)

                if ioc_type == 'url':
                    if not is_valid_url(ioc_value):
                        continue

                elif ioc_type == 'ip:port':
                    if not is_valid_ip(ioc_value.split(':')[0]):
                        continue

                    ioc_type = 'ip-dst|port'
                    ioc_value = ioc_value.replace(':','|')

                elif '_hash' in ioc_type:
                    if SHA256_ONLY and not re.search(r'\w{64}', ioc_value):
                        continue

                    elif not re.search(r'\w{32,64}', ioc_value):
                        continue

                    ioc_type = ioc_type.replace('_hash','')

                else:
                    continue

                indicator_list.append(FeedIndicator(comment, tags, ioc_type, ioc_value))

    except Exception as e:
        LOGGER.error('ThreatFox request error: {0}'.format(str(e)))

    return indicator_list

def get_bazaar_list():
    LOGGER.info('Fetching latest hashes from MalwareBazaar...')
    indicator_list = []

    try:
        response = requests.get(MALWAREBAZAAR_URL)

        if response.status_code == 200:
            content = response.text
            content = content.replace(', ',',')
            reader = csv.reader(content.splitlines(), delimiter=',')
            valid_lines = [line for line in list(reader) if len(line) == 14]
            date_threshold = datetime.utcnow() - timedelta(minutes=SAMPLE_MAX_MINUTES)

            for line in valid_lines:
                if line[0].startswith('#'):
                    continue

                line_timestamp = datetime.strptime(line[0], '%Y-%m-%d %H:%M:%S')

                if line_timestamp > date_threshold:
                    continue

                sha256 = line[1]
                md5 = line[2]
                sha1 = line[3]
                filename = line[5]
                filetype = line[6]
                tags = line[8]

                if tags:
                    tags = tags.split(',')

                    if not is_valid_sample(tags):
                        continue

                comment = 'File: {0} ({1})'.format(filename, filetype)

                indicator_list.append(FeedIndicator(comment, tags, 'sha256', sha256))

                if not SHA256_ONLY:
                    indicator_list.append(FeedIndicator(comment, tags, 'md5', md5))
                    indicator_list.append(FeedIndicator(comment, tags, 'sha1', sha1))

    except Exception as e:
        LOGGER.error('MalwareBazaar request error: {0}'.format(str(e)))

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
        indicator_tags = indicator.ref_tags
        indicator_comment = indicator.ref_comment

        attribute_exists = False

        try:
            if attribute_type == 'ip-dst|port':
                search_value = indicator_value.split('|')[0]

            else:
                search_value = indicator_value

            attribute_search = misp.search(controller='attributes', value=search_value, type=attribute_type)

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

        if attribute_type == 'sha256':
            attribute_category = 'Payload delivery'

        elif attribute_type == 'sha1':
            attribute_category = 'Payload delivery'

        elif attribute_type == 'md5':
            attribute_category = 'Payload delivery'

        elif attribute_type == 'ip-dst':
            attribute_category = 'Network activity'

        elif attribute_type == 'ip-dst|port':
            attribute_category = 'Network activity'

        elif attribute_type == 'url':
            attribute_category = 'Network activity'

        else:
            LOGGER.warning('Unsupported indicator type: {0}'.format(attribute_type))
            continue

        attribute_json = {'category': attribute_category, 'type': attribute_type, 'value': indicator_value, 'comment': indicator_comment, 'to_ids': MISP_TO_IDS}

        try:
            new_attr = misp.add_attribute(event, attribute_json, pythonify=True)

            if indicator_tags:
                for tag in indicator_tags:
                    if tag:
                        if tag.lower() in TAG_BLACKLIST:
                            continue

                        galaxy_tags = get_tags(misp, tag, 'contains')

                        if galaxy_tags:
                            for galaxy_tag in galaxy_tags:
                                misp.tag(new_attr, galaxy_tag)

                        else:
                            misp.tag(new_attr, tag)

        except Exception as ex:
            LOGGER.error('Failed to add MISP attribute: {0}'.format(str(ex)))
            continue

    if MISP_PUBLISH_EVENTS:
        LOGGER.info('Publishing event...')

        try:
            misp.publish(event)

        except Exception as ex:
            LOGGER.error('Failed to publish MISP event: {0}'.format(str(ex)))

def plugin_run(misp):
    urlhaus_list = get_urlhaus_list()

    if len(urlhaus_list) > 0:
        process_indicators(misp, urlhaus_list)

    else:
        LOGGER.warning('URLhaus list is empty.')

    feodo_list = get_feodo_list()

    if len(feodo_list) > 0:
        process_indicators(misp, feodo_list)

    else:
        LOGGER.warning('FeodoTracker list is empty.')

    bazaar_list = get_bazaar_list()

    if len(bazaar_list) > 0:
        process_indicators(misp, bazaar_list)

    else:
        LOGGER.warning('MalwareBazaar list is empty.')

    threatfox_list = get_threatfox_list()

    if len(threatfox_list) > 0:
        process_indicators(misp, threatfox_list)

    else:
        LOGGER.warning('ThreatFox list is empty.')

    LOGGER.info('Run complete!')
