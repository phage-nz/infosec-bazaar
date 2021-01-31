#!/usr/bin/python3
from collections import Counter
from datetime import datetime, timedelta
from pymisp import PyMISP, MISPEvent, MISPAttribute, ThreatLevel, Distribution, Analysis

import coloredlogs
import csv
import logging
import re
import sys
import requests
import time
import urllib.parse
import urllib3
import validators

LOGGER = logging.getLogger('abusechmisp')
logging.basicConfig(filename='misp_feeds.log', format='%(asctime)s %(name)s %(levelname)s: %(message)s', level=logging.INFO)
coloredlogs.install(level='INFO')

MISP_URL = 'MISP BASE URL'
MISP_API_KEY = 'MISP USER KEY'
MISP_EVENT_TITLE = 'Abuse.ch indicator feed'
MISP_VALIDATE_SSL = False
MISP_TO_IDS = False
MISP_PUBLISH_EVENTS = False

FEODOTRACKER_URL = 'https://feodotracker.abuse.ch/downloads/ipblocklist.csv'
MALWAREBAZAAR_URL = 'https://bazaar.abuse.ch/export/csv/recent/'
URLHAUS_URL = 'https://urlhaus.abuse.ch/downloads/csv_recent/'

ATTRIBUTE_PROGRESS = True
SAMPLE_MAX_MINUTES = 70

IP_BLACKLIST = []
URL_BLACKLIST = []
TAG_BLACKLIST = ['arm','bashlite','elf','gafgyt','mirai','mozi','script']
TAG_IGNORE = ['exe','dll','doc','encrypted','excel','hta','iso','msi','ransomware','rtf','script','xls']

class FeedIndicator:
  def __init__(self, ref_comment, ref_tags, o_type, o_value):
    self.ref_comment = ref_comment
    self.ref_tags = ref_tags
    self.o_type = o_type
    self.o_value = o_value

def disable_ssl_warnings():
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_tags(misp, term):
    tags = [x for x in misp.tags(pythonify=True)]
    return [t.to_dict() for t in tags if term.lower() in t.name.lower()]

def is_valid_domain(domain):
    return validators.domain(domain)

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

def is_valid_ip(ip):
    if any(s in ip for s in IP_BLACKLIST):
        return False

    return validators.ipv4(ip)

def is_valid_sample(tags):
    if any(x.lower() in TAG_BLACKLIST for x in tags.split(',')):
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

                if line_timestamp > date_threshold:
                    url = line[2]
                    tags = line[5]
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
                if line[0].startswith('#'):
                    continue

                line_timestamp = datetime.strptime(line[0], '%Y-%m-%d %H:%M:%S')

                if line_timestamp > date_threshold:
                    ip = line[1]
                    tag = line[5]
                    comment = 'Port {0}'.format(line[2])

                    if not is_valid_sample(tag):
                        continue

                    if not is_valid_ip(ip):
                        continue

                    indicator_list.append(FeedIndicator(comment, tag, 'ip-dst', ip))

    except Exception as e:
        LOGGER.error('FeodoTracker request error: {0}'.format(str(e)))

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
                    sha256 = line[1]
                    md5 = line[2]
                    sha1 = line[3]
                    filename = line[5]
                    filetype = line[6]
                    tag = line[8]
                    comment = 'File: {0} ({1})'.format(filename, filetype)

                    if not is_valid_sample(tag):
                        continue

                    indicator_list.append(FeedIndicator(comment, tag, 'sha256', sha256))
                    indicator_list.append(FeedIndicator(comment, tag, 'md5', md5))
                    indicator_list.append(FeedIndicator(comment, tag, 'sha1', sha1))

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
            attribute_search = misp.search(controller='attributes', value=indicator_value)

        except Exception as ex:
            LOGGER.error('Failed to search for MISP attribute: {0}'.format(str(ex)))
            continue

        if not attribute_search['Attribute'] == []:
            for attribute_result in attribute_search['Attribute']:
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

        elif attribute_type == 'url':
            attribute_category = 'Network activity'

        else:
            LOGGER.warning('Unsupported indicator type: {0}'.format(attribute_type))
            continue

        attribute_tags = []

        if indicator_tags:
            for tag in indicator_tags.split(','):
                if tag:
                    if tag.lower() in TAG_IGNORE:
                        continue

                    galaxy_tags = get_tags(misp, tag)

                    if galaxy_tags:
                        #LOGGER.info('Adding tags for: {0}'.format(tag))
                        attribute_tags.extend(galaxy_tags)

        attribute_json = {'category': attribute_category, 'type': attribute_type, 'value': indicator_value, 'comment': indicator_comment, 'to_ids': MISP_TO_IDS, 'Tag': attribute_tags}

        try:
            print(attribute_json)
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

def abusech_run(misp):
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

    abusech_run(misp)
