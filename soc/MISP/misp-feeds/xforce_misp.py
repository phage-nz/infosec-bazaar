#!/usr/bin/python3

# References:
# https://buildmedia.readthedocs.org/media/pdf/pymisp/latest/pymisp.pdf
# https://api.xforce.ibmcloud.com/doc

from datetime import datetime, timedelta, timezone
from dateutil import parser as dateparser
from pymisp import PyMISP, MISPEvent, MISPAttribute, ThreatLevel, Distribution, Analysis

import base64
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

LOGGER = logging.getLogger('xforcemisp')
logging.basicConfig(filename='misp_feeds.log', format='%(asctime)s %(name)s %(levelname)s: %(message)s', level=logging.INFO)
coloredlogs.install(level='INFO')

XFORCE_API_KEY = 'YOUR KEY'
XFORCE_API_PASSWORD = 'YOUR PASSWORD'
XFORCE_LINK_IGNORE = ['ibm.com', 'ibmcloud.com', 'xforce-security.com']

MISP_URL = 'https://misp.domain.com'
MISP_API_KEY = 'YOUR KEY'
MISP_VALIDATE_SSL = False
MISP_TO_IDS = False
MISP_PUBLISH_EVENTS = False

HOURS_TO_CHECK = 12

def disable_ssl_warnings():
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def is_valid_md5(hash):
    return bool(re.match(r'^[a-fA-F\d]{32}$', hash))

def is_valid_sha1(hash):
    return bool(re.match(r'^[a-fA-F\d]{40}$', hash))

def is_valid_sha256(hash):
    return bool(re.match(r'^[a-fA-F\d]{64}$', hash))

def is_valid_domain(domain):
    return validators.domain(domain)

def is_valid_url(url):
    try:
        result = urllib.parse.urlparse(url)
        url_valid = all([result.scheme, result.netloc])
        return url_valid

    except Exception as ex:
        LOGGER.warning('Error validating URL: {0}'.format(str(ex)))

    return False

def is_valid_ip(ip):
    return validators.ipv4(ip)

def get_tags(misp, term):
    tags = [x.name for x in misp.tags(pythonify=True)]
    return [t for t in tags if term in t]

def get_tags(misp, input):
    tags = [x.name for x in misp.tags(pythonify=True) if 'misp-galaxy' in x.name]

    event_tags = []

    for tag in tags:
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

def get_api_headers():
    keypair = '{0}:{1}'.format(XFORCE_API_KEY, XFORCE_API_PASSWORD)
    token = str(base64.b64encode(keypair.encode('utf-8')), 'utf-8')
    return {'Accept': 'application/json', 'Authorization': 'Basic {0}'.format(token)}

def get_cases():
    LOGGER.info('Getting new cases...')
    case_url = 'https://api.xforce.ibmcloud.com/casefiles/public'
    response = requests.get(case_url, headers=get_api_headers())

    if not response.status_code == 200:
        LOGGER.info('Failed to get cases. Status code: {0}'.format(response.status_code))
        return []

    LOGGER.info('Case request OK! Building list of new cases...')

    case_data = json.loads(response.text)
    case_list = []

    for case in case_data['casefiles']:
        try:
            timestamp = dateparser.parse(case['created'])

        except Exception as ex:
            LOGGER.error('Cannot parse case creation date: {0}'.format(str(ex)))
            continue

        time_threshold = datetime.now(tz=timezone.utc) - timedelta(hours=HOURS_TO_CHECK)

        if 'advisory' in case['tags'] and timestamp > time_threshold:
            case_list.append(case['caseFileID'])

    LOGGER.info('Assembled case list.')

    return case_list

def make_new_event(misp, case_data, references):
    LOGGER.info('Creating new event...')
    event = MISPEvent()

    title = case_data['title']
    author = case_data['owner']['name']
    tlp = case_data['tlpColor']['tlpColorCode']

    try:
        timestamp = dateparser.parse(case_data['created'])

    except Exception as ex:
        LOGGER.error('Cannot parse case creation date: {0}'.format(str(ex)))
        timestamp = datetime.utcnow()

    event_date = timestamp.strftime('%Y-%m-%d')
    event.info = title
    event.analysis = Analysis.completed
    event.distribution = Distribution.your_organisation_only
    event.threat_level_id = ThreatLevel.low
    event.add_tag('xforce-author:{0}'.format(author))

    block_parts = case_data['contents']['rawContentState']['blocks']
    body_parts = [b['text'].strip() for b in block_parts if b['type'] == 'unstyled']

    if body_parts:
        summary = body_parts[0]
        LOGGER.info('Adding external analysis attribute.')
        event.add_attribute('comment', summary, category='External analysis')

    tag_list = get_tags(misp, title)

    for tag in tag_list:
        LOGGER.info('Adding galaxy tag: "{0}"'.format(tag))
        event.add_tag(tag)

    if references:
        event.add_tag('type:OSINT')

        for reference in references:
            if is_valid_domain(reference):
                reference = 'https://{0}'.format(reference)

            if is_valid_url(reference):
                LOGGER.info('Adding attribute for reference: {0}'.format(reference))
                event.add_attribute('link', reference, category='External analysis')

    if tlp:
        LOGGER.info('Adding TLP tag: tlp:{0}'.format(tlp))
        event.add_tag('tlp:{0}'.format(tlp))

    LOGGER.info('Saving event...')
    time.sleep(1)
    return misp.add_event(event, pythonify=True)

def process_cases(case_list):
    for case_id in case_list:
        LOGGER.info('Fetching case: {0}'.format(case_id))

        case_url = 'https://api.xforce.ibmcloud.com/casefiles/{0}'.format(case_id)
        response = requests.get(case_url, headers=get_api_headers())

        if not response.status_code == 200:
            LOGGER.info('Failed to get case. Status code: {0}'.format(response.status_code))
            continue

        LOGGER.info('Case request OK!')
        case_data = json.loads(response.text)

        title = case_data['title']
        author = case_data['owner']['name']

        LOGGER.info('New case from {0}: {1}'.format(author, title))

        observables = []
        references = []

        entities = case_data['contents']['rawContentState']['entityMap']

        for id, entity in entities.items():
            if entity['type'].upper() == 'OBSERVABLE':
                observables.append(entity['data']['id'])

            elif entity['type'].upper() == 'HYPERLINK':
                target = entity['data']['target']

                if not any(s in target for s in XFORCE_LINK_IGNORE):
                    references.append(target)

            else:
                continue

        if len(observables) == 0:
            LOGGER.warning('Case has no observables to add.')
            continue

        event = False
        event_search = misp.search_index(eventinfo=title)

        if not event_search == []:
            for result in event_search:
                if result['info'] == title:
                    event = event_search[0]

        if event:
            LOGGER.warning('Event already exists. Will only update attributes.')

        else:
            event = make_new_event(misp, case_data, references)

        if not event:
            LOGGER.warning('Failed to make or retrieve event.')
            continue

        LOGGER.info('Processing {0} observables...'.format(len(observables)))

        for observable in observables:
            attribute_exists = False
            attribute_search = misp.search(controller='attributes', value=observable)

            if not attribute_search['Attribute'] == []:
                for attribute_result in attribute_search['Attribute']:
                    if attribute_result['event_id'] == event['id']:
                        attribute_exists = True

            if attribute_exists:
                continue

            if is_valid_md5(observable):
                attribute_category = 'Payload delivery'
                attribute_type = 'md5'

            elif is_valid_sha1(observable):
                attribute_category = 'Payload delivery'
                attribute_type = 'sha1'

            elif is_valid_sha256(observable):
                attribute_category = 'Payload delivery'
                attribute_type = 'sha256'

            elif is_valid_ip(observable):
                attribute_category = 'Network activity'

                if 'scan' in title.lower():
                    attribute_type = 'ip-src'

                else:
                    attribute_type = 'ip-dst'

            elif is_valid_domain(observable):
                attribute_category = 'Network activity'

                if observable.count('.') == 1:
                    attribute_type = 'domain'

                else:
                    attribute_type = 'hostname'

            elif is_valid_url(observable):
                attribute_category = 'Network activity'
                attribute_type = 'url'

            elif is_valid_url('https://{0}'.format(observable)):
                attribute_category = 'Network activity'
                attribute_type = 'url'
                observable = 'https://{0}'.format(observable)

            else:
                LOGGER.warning('Unable to determine observable type: {0}'.format(observable))
                continue

            attribute_json = {'category': attribute_category, 'type': attribute_type, 'value': observable, 'to_ids': MISP_TO_IDS}
            new_attr = misp.add_attribute(event, attribute_json, pythonify=True)

        if MISP_PUBLISH_EVENTS:
            LOGGER.info('Publishing event...')
            misp.publish(event)

        LOGGER.info('Case complete!')

def xforce_run(misp):
    cases = get_cases()

    if cases:
        process_cases(cases)

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

    xforce_run(misp)