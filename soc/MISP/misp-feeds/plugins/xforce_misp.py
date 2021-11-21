#!/usr/bin/python3

# References:
# https://buildmedia.readthedocs.org/media/pdf/pymisp/latest/pymisp.pdf
# https://api.xforce.ibmcloud.com/doc

from config import *
from datetime import datetime, timedelta, timezone
from dateutil import parser as dateparser
from helpers import disable_ssl_warnings, is_valid_domain, is_valid_url, is_valid_ip, get_textblock_tags
from io import StringIO
from pymisp import MISPEvent, MISPAttribute, ThreatLevel, Distribution, Analysis
from stix.core import STIXPackage

import base64
import coloredlogs
import json
import logging
import requests
import sys
import time

LOGGER = logging.getLogger('xforcemisp')
logging.basicConfig(filename='misp_feeds.log', format='%(asctime)s %(name)s %(levelname)s: %(message)s', level=logging.INFO)
coloredlogs.install(level='INFO')

PLUGIN_NAME = 'X-Force'
PLUGIN_ENABLED = True
PLUGIN_TIMES = ['06:00', '14:00', '22:00']

XFORCE_API_KEY = 'YOUR XFORCE API KEY'
XFORCE_API_PASSWORD = 'YOUR XFORCE API PASSWORD'
XFORCE_LINK_IGNORE = ['ibm.com', 'ibmcloud.com', 'xforce-security.com']

MISP_TO_IDS = False
MISP_PUBLISH_EVENTS = False

HOURS_TO_CHECK = 9
ATTRIBUTE_PROGRESS = True

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

    print(case_list)
    return case_list

def make_new_event(misp, stix_package):
    LOGGER.info('Creating new event...')
    event = MISPEvent()

    title = stix_package.stix_header.title
    author = stix_package.stix_header.information_source.contributing_sources[0].identity.name

    timestamp = stix_package.stix_header.information_source.time.produced_time.value
    event_date = timestamp.strftime('%Y-%m-%d')

    event.info = title
    event.analysis = Analysis.completed
    event.distribution = Distribution.your_organisation_only
    event.threat_level_id = ThreatLevel.low
    event.add_tag('xforce-author:{0}'.format(author))

    tlp = stix_package.stix_header.handling[0].marking_structures[0].color.lower()
    LOGGER.info('Adding TLP tag: tlp:{0}'.format(tlp))
    event.add_tag('tlp:{0}'.format(tlp))

    text_parts = stix_package.stix_header.description.value.split('\n')

    while '' in text_parts:
        text_parts.remove('')

    if 'Summary' in text_parts:
        summary_index = text_parts.index('Summary') + 1
        summary = text_parts[summary_index]
        LOGGER.info('Adding external analysis attribute.')
        event.add_attribute('comment', summary, category='External analysis')

    reference_links = []

    if 'References' in text_parts:
        ref_index = text_parts.index('References') + 1
        references = [r.replace('\xa0', '') for r in text_parts[ref_index:]]

    if 'Reference' in text_parts:
        ref_index = text_parts.index('Reference') + 1
        reference_links = [r.replace('\xa0', '') for r in text_parts[ref_index:]]

    if reference_links:
        references = []

        for link in reference_links:
            if is_valid_domain(link):
                link = 'https://{0}'.format(link)

            if not any(d in link for d in XFORCE_LINK_IGNORE) and is_valid_url(link):
                references.append(link)

        if references:
            event.add_tag('type:OSINT')

            for reference in references:
                LOGGER.info('Adding attribute for reference: {0}'.format(reference))
                event.add_attribute('link', reference, category='External analysis')

    tag_list = get_textblock_tags(misp, title)

    for tag in tag_list:
        LOGGER.info('Adding galaxy tag: "{0}"'.format(tag))
        event.add_tag(tag)

    LOGGER.info('Saving event...')
    time.sleep(1)

    try:
        new_event = misp.add_event(event, pythonify=True)
        return new_event

    except Exception as ex:
        LOGGER.error('Failed to make MISP event: {0}'.format(str(ex)))
        return False

def process_cases(misp, case_list):
    for case_id in case_list:
        LOGGER.info('Fetching case: {0}'.format(case_id))

        case_url = 'https://api.xforce.ibmcloud.com/casefiles/{0}/stix'.format(case_id)
        response = requests.get(case_url, headers=get_api_headers())

        if not response.status_code == 200:
            LOGGER.info('Failed to get case. Status code: {0}'.format(response.status_code))
            continue

        LOGGER.info('Case request OK!')

        stix_xml = StringIO(response.text)
        stix_package = STIXPackage.from_xml(stix_xml)
        stix_xml.close()

        title = stix_package.stix_header.title
        author = stix_package.stix_header.information_source.contributing_sources[0].identity.name

        LOGGER.info('New case from {0}: {1}'.format(author, title))

        if not stix_package.observables:
            LOGGER.warning('Case does not have any recorded observables. Skipping...')
            continue

        event = False

        try:
            event_search = misp.search_index(eventinfo=title)

        except Exception as ex:
            LOGGER.error('Failed to search for MISP event: {0}'.format(str(ex)))
            continue

        if not event_search == []:
            for result in event_search:
                if result['info'] == title:
                    event = event_search[0]

        if event:
            LOGGER.warning('Event already exists. Will only update attributes.')

        else:
            event = make_new_event(misp, stix_package)

        if not event:
            LOGGER.warning('Failed to make or retrieve event.')
            continue

        observables = stix_package.observables.observables
        observable_count = len(observables)
        LOGGER.info('Processing {0} observables...'.format(observable_count))

        for i, observable in enumerate(observables):
            if ATTRIBUTE_PROGRESS and i % 100 == 0:
                progress_value = int(round(100 * (i / float(observable_count))))
                LOGGER.info('Event completion: {0}%'.format(progress_value))

            attribute_value = None

            if hasattr(observable.object_.properties, 'hashes'):
                if observable.object_.properties.hashes.sha256:
                    attribute_value = str(observable.object_.properties.hashes.sha256.value).lower()
                    attribute_category = 'Payload delivery'
                    attribute_type = 'sha256'

                elif observable.object_.properties.hashes.sha1:
                    attribute_value = str(observable.object_.properties.hashes.sha1.value).lower()
                    attribute_category = 'Payload delivery'
                    attribute_type = 'sha1'

                elif observable.object_.properties.hashes.md5:
                    attribute_value = str(observable.object_.properties.hashes.md5.value).lower()
                    attribute_category = 'Payload delivery'
                    attribute_type = 'md5'

            elif hasattr(observable.object_.properties, 'type_'):
                if observable.object_.properties.type_ == 'URL':
                    observable_value = str(observable.object_.properties.value)
                    attribute_category = 'Network activity'

                    if is_valid_domain(observable_value):
                        attribute_value = observable_value

                        if attribute_value.count('.') == 1:
                            attribute_type = 'domain'

                        else:
                            attribute_type = 'hostname'

                    elif is_valid_url(observable_value):
                        attribute_value = observable_value
                        attribute_category = 'Network activity'
                        attribute_type = 'url'

                    elif is_valid_url('https://{0}'.format(observable_value)):
                        attribute_value = 'https://{0}'.format(observable_value)
                        attribute_category = 'Network activity'
                        attribute_type = 'url'

            elif hasattr(observable.object_.properties, 'address_value'):
                attribute_value = str(observable.object_.properties.address_value)
                attribute_category = 'Network activity'

                if 'scan' in title.lower():
                    attribute_type = 'ip-src'

                else:
                    attribute_type = 'ip-dst'

            if not attribute_value:
                LOGGER.warning('Unable to determine observable type: {0}'.format(str(type(observable.object_.properties))))
                continue

            attribute_exists = False

            try:
                attribute_search = misp.search(controller='attributes', value=attribute_value)

            except Exception as ex:
                LOGGER.error('Failed to search for MISP attribute: {0}'.format(str(ex)))
                continue

            if not attribute_search['Attribute'] == []:
                for attribute_result in attribute_search['Attribute']:
                    if int(attribute_result['event_id']) == int(event['id']):
                        attribute_exists = True

            if attribute_exists:
                continue

            attribute_json = {'category': attribute_category, 'type': attribute_type, 'value': attribute_value, 'to_ids': MISP_TO_IDS}

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
                continue

        LOGGER.info('Case complete!')

def plugin_run(misp):
    cases = get_cases()

    if cases:
        process_cases(misp, cases)

    LOGGER.info('Run complete!')
