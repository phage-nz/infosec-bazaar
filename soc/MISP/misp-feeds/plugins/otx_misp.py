#!/usr/bin/python3

# Requirements:
# pip3 install coloredlogs OTXv2 pymisp validators

# References:
# https://buildmedia.readthedocs.org/media/pdf/pymisp/latest/pymisp.pdf
# https://github.com/AlienVault-OTX/OTX-Python-SDK

from config import *
from datetime import datetime, timedelta
from dateutil import parser as dateparser
from helpers import disable_ssl_warnings, is_valid_domain, is_valid_url, is_valid_ip, get_tags
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
from pymisp import MISPEvent, MISPAttribute, ThreatLevel, Distribution, Analysis

import coloredlogs
import logging
import sys
import time

PLUGIN_NAME = 'OTX'
PLUGIN_ENABLED = True
PLUGIN_TIMES = ['08:00', '14:00', '20:00', '02:00']

LOGGER = logging.getLogger('otxmisp')
logging.basicConfig(filename='misp_feeds.log', format='%(asctime)s %(name)s %(levelname)s: %(message)s', level=logging.INFO)
coloredlogs.install(level='INFO')

OTX_API_KEY = 'YOUR OTX KEY'
OTX_USER_BLACKLIST = []
OTX_USER_WHITELIST = []
OTX_PULSE_BLACKLIST = []

MISP_TO_IDS = False
MISP_PUBLISH_EVENTS = False

HOURS_TO_CHECK = 7
ATTRIBUTE_PROGRESS = True

def get_pulses(otx, date_since):
    LOGGER.info('Getting recent pulses...')

    try:
        pulses = otx.getsince(date_since, limit=None)

    except Exception as ex:
        LOGGER.error('Cannot connect to OTX: {0}'.format(str(ex)))
        return False

    if pulses:
        LOGGER.info('OTX request OK! Returning pulses...')
        return pulses

    else:
        LOGGER.error('OTX request failed.')

    return False

def make_new_event(misp, pulse):
    LOGGER.info('Creating new event...')
    event = MISPEvent()

    title = pulse['name']
    author = pulse['author_name']
    adversary = pulse['adversary']
    description = pulse['description']
    attack_ids = pulse['attack_ids']
    malware_families = pulse['malware_families']
    references = pulse['references']
    tlp = pulse['tlp']

    try:
        timestamp = dateparser.parse(pulse['created'])

    except Exception as ex:
        LOGGER.error('Cannot parse pulse creation date: {0}'.format(str(ex)))
        timestamp = datetime.utcnow()

    event_date = timestamp.strftime('%Y-%m-%d')
    event.info = title
    event.analysis = Analysis.completed
    event.distribution = Distribution.your_organisation_only
    event.threat_level_id = ThreatLevel.low
    event.add_tag('otx-author:{0}'.format(author))

    if adversary:
        adversary_list = []

        if ',' in adversary:
            adversary_list = [s.strip() for s in adversary.split(',') if s.strip() != '']

        else:
            adversary_list.append(adversary)

        for adversary in adversary_list:
            galaxy_tags = get_tags(misp, adversary, 'contains')

            if galaxy_tags:
                for galaxy_tag in galaxy_tags:
                    LOGGER.info('Adding threat actor galaxy tag: "{0}"'.format(galaxy_tag))
                    event.add_tag(galaxy_tab)

            else:
                event.add_tag(adversary)

    if description:
        LOGGER.info('Adding external analysis attribute.')
        event.add_attribute('comment', description, category='External analysis')

    if attack_ids:
        for attack_id in attack_ids:
            if attack_id:
                galaxy_tags = get_tags(misp, '{0}"'.format(attack_id), 'endswith')

                if galaxy_tags:
                    for galaxy_tag in galaxy_tags:
                        LOGGER.info('Adding MITRE ATT&CK galaxy tag: "{0}"'.format(galaxy_tag))
                        event.add_tag(galaxy_tag)

    if malware_families:
        for malware_family in malware_families:
            if malware_family:
                galaxy_tags = get_tags(misp, malware_family, 'contains')

                if galaxy_tags:
                    for tag in galaxy_tags:
                        LOGGER.info('Adding malware galaxy tag: {0}'.format(tag))
                        event.add_tag(tag)

                else:
                    event.add_tag(malware_family)

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

    try:
        new_event = misp.add_event(event, pythonify=True)
        return new_event

    except Exception as ex:
        LOGGER.error('Failed to make MISP event: {0}'.format(str(ex)))
        return False

def process_pulses(misp, pulses):
    LOGGER.info('Processing pulses...')

    for pulse in pulses:
        title = pulse['name']
        author = pulse['author_name']

        if OTX_USER_BLACKLIST:
            if author in OTX_USER_BLACKLIST:
                continue

        if OTX_USER_WHITELIST:
            if not author in OTX_USER_WHITELIST:
                continue

        if OTX_PULSE_BLACKLIST:
            if pulse['id'] in OTX_PULSE_BLACKLIST:
                continue

        LOGGER.info('New pulse from {0}: {1}'.format(author, title))

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
            event = make_new_event(misp, pulse)

        if not event:
            continue

        indicators = pulse['indicators']
        indicator_count = len(indicators)
        LOGGER.info('Processing {0} indicators...'.format(indicator_count))

        for i, indicator in enumerate(indicators):
            if ATTRIBUTE_PROGRESS and i % 100 == 0:
                progress_value = int(round(100 * (i / float(indicator_count))))
                LOGGER.info('Event completion: {0}%'.format(progress_value))

            indicator_type = indicator['type']
            indicator_value = indicator['indicator']

            attribute_exists = False

            try:
                attribute_search = misp.search(controller='attributes', value=indicator_value)

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

            if indicator_type == 'FileHash-SHA256':
                attribute_category = 'Payload delivery'
                attribute_type = 'sha256'

            elif indicator_type == 'FileHash-SHA1':
                attribute_category = 'Payload delivery'
                attribute_type = 'sha1'

            elif indicator_type == 'FileHash-MD5':
                attribute_category = 'Payload delivery'
                attribute_type = 'md5'

            elif indicator_type == 'FileHash-IMPHASH':
                attribute_category = 'Payload delivery'
                attribute_type = 'imphash'

            elif indicator_type == 'FileHash-PEHASH':
                attribute_category = 'Payload delivery'
                attribute_type = 'pehash'

            elif indicator_type == 'URL' or indicator_type == 'URI':
                attribute_category = 'Network activity'
                attribute_type = 'url'

            elif indicator_type == 'domain':
                attribute_category = 'Network activity'
                attribute_type = 'domain'

            elif indicator_type == 'hostname':
                attribute_category = 'Network activity'
                attribute_type = 'hostname'

            elif indicator_type == 'IPv4' or indicator_type == 'IPv6':
                attribute_category = 'Network activity'

                if 'scan' in title.lower():
                    attribute_type = 'ip-src'

                else:
                    attribute_type = 'ip-dst'

            elif indicator_type == 'email':
                attribute_category = 'Payload delivery'
                attribute_type = 'email-src'

            elif indicator_type == 'CVE':
                attribute_category = 'Payload delivery'
                attribute_type = 'vulnerability'

            elif indicator_type == 'Mutex':
                attribute_category = 'Artifacts dropped'
                attribute_type = 'mutex'

            elif indicator_type == 'FilePath':
                attribute_category = 'Artifacts dropped'
                attribute_type = 'filename'

            elif indicator_type == 'YARA':
                attribute_category = 'Artifacts dropped'
                attribute_type = 'yara'

            else:
                LOGGER.warning('Unsupported indicator type: {0}'.format(indicator_type))
                continue

            attribute_json = {'category': attribute_category, 'type': attribute_type, 'value': indicator_value, 'to_ids': MISP_TO_IDS}

            if indicator['description']:
                attribute_json['comment'] = indicator['description']

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

        LOGGER.info('Pulse complete!')

def plugin_run(misp):
    LOGGER.info('Setting up OTX connector...')
    try:
        otx = OTXv2(OTX_API_KEY)

    except Exception as ex:
        LOGGER.error('Failed to connect to OTX: {0}'.format(str(ex)))
        sys.exit(1)

    date_since = (datetime.utcnow() - timedelta(hours=HOURS_TO_CHECK)).isoformat()
    pulses = get_pulses(otx, date_since)

    if pulses:
        process_pulses(misp, pulses)

    LOGGER.info('Run complete!')
