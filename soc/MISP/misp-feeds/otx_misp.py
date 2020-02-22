#!/usr/bin/python3

# References:
# https://buildmedia.readthedocs.org/media/pdf/pymisp/latest/pymisp.pdf
# https://github.com/AlienVault-OTX/OTX-Python-SDK

from datetime import datetime, timedelta
from dateutil import parser as dateparser
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
from pymisp import PyMISP, MISPEvent, MISPAttribute, ThreatLevel, Distribution, Analysis

import coloredlogs
import logging
import sys
import time
import urllib.parse
import urllib3
import validators

LOGGER = logging.getLogger('otxmisp')
logging.basicConfig(filename='misp_feeds.log', format='%(asctime)s %(name)s %(levelname)s: %(message)s', level=logging.INFO)
coloredlogs.install(level='INFO')

OTX_API_KEY = 'YOUR KEY'
OTX_USER_BLACKLIST = []
OTX_USER_WHITELIST = []

MISP_URL = 'https://misp.yourdomain.com'
MISP_API_KEY = 'YOUR KEY'
MISP_VALIDATE_SSL = False
MISP_TO_IDS = False
MISP_PUBLISH_EVENTS = False

HOURS_TO_CHECK = 12

def disable_ssl_warnings():
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

def get_tags(misp, term):
    tags = [x.name for x in misp.tags(pythonify=True)]
    return [t for t in tags if term in t]

def get_pulses(otx, date_since):
    LOGGER.info('Getting recent pulses...')
    pulses = otx.getsince(date_since, limit=None)

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
        tag_list = []

        if ',' in adversary:
            adversary_list = [s.strip() for s in adversary.split(',')]

        else:
            adversary_list.append(adversary)

        print(adversary_list)

        for adversary in adversary_list:
            galaxy_tags = get_tags(misp, adversary)

            if galaxy_tags:
                for galaxy_tag in galaxy_tags:
                    LOGGER.info('Adding threat actor galaxy tag: "{0}"'.format(galaxy_tag))
                    tag_list.append(galaxy_tag)

            else:
                LOGGER.info('Adding default threat actor galaxy tag: misp-galaxy:threat-actor="{0}"'.format(adversary))
                tag_list.append('misp-galaxy:threat-actor="{0}"'.format(adversary))

        for tag in tag_list:
            event.add_tag(tag)

    if description:
        LOGGER.info('Adding external analysis attribute.')
        event.add_attribute('comment', description, category='External analysis')

    if malware_families:
        for malware_family in malware_families:
            if malware_family:
                galaxy_tags = get_tags(misp, malware_family)

                if galaxy_tags:
                    for tag in galaxy_tags:
                        LOGGER.info('Adding malware galaxy tag: {0}'.format(tag))
                        event.add_tag(tag)

                else:
                    LOGGER.info('Adding default malware galaxy tag: misp-galaxy:tool="{0}"'.format(malware_family))
                    event.add_tag('misp-galaxy:tool="{0}"'.format(malware_family))

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

        LOGGER.info('New pulse from {0}: {1}'.format(author, title))

        event = False
        event_search = misp.search_index(eventinfo=title)

        if not event_search == []:
            for result in event_search:
                if result['info'] == title:
                    event = event_search[0]

        if event:
            LOGGER.warning('Event already exists. Will only update attributes.')

        else:
            event = make_new_event(misp, pulse)

        if not event:
            LOGGER.warning('Failed to make or retrieve event.')
            continue

        indicators = pulse['indicators']
        LOGGER.info('Processing {0} indicators...'.format(len(indicators)))

        for indicator in indicators:
            indicator_type = indicator['type']
            indicator_value = indicator['indicator']

            attribute_exists = False
            attribute_search = misp.search(controller='attributes', value=indicator_value)

            if not attribute_search['Attribute'] == []:
                for attribute_result in attribute_search['Attribute']:
                    if attribute_result['event_id'] == event['id']:
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

            new_attr = misp.add_attribute(event, attribute_json, pythonify=True)

        if MISP_PUBLISH_EVENTS:
            LOGGER.info('Publishing event...')
            misp.publish(event)

        LOGGER.info('Pulse complete!')

def otx_run(misp):
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

if __name__ == '__main__':
    LOGGER.info('Setting up MISP connector...')
    if MISP_VALIDATE_SSL == False:
        disable_ssl_warnings()

    try:
        misp = PyMISP(MISP_URL, MISP_API_KEY, ssl=MISP_VALIDATE_SSL)

    except Exception as ex:
        LOGGER.error('Failed to connect to MISP: {0}'.format(str(ex)))
        sys.exit(1)

    otx_run(misp)
