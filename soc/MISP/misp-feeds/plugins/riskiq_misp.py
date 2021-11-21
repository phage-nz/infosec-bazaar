#!/usr/bin/python3

from config import *
from datetime import datetime, timedelta
from dateutil import parser as dateparser
from helpers import disable_ssl_warnings, is_valid_domain, is_valid_url, is_valid_ip, get_tags
from pymisp import MISPEvent, MISPAttribute, ThreatLevel, Distribution, Analysis
from urllib.parse import urljoin

import coloredlogs
import json
import logging
import requests
import sys
import time
import urllib3

LOGGER = logging.getLogger('riskiqmisp')
logging.basicConfig(filename='misp_feeds.log', format='%(asctime)s %(name)s %(levelname)s: %(message)s', level=logging.INFO)
coloredlogs.install(level='INFO')

PLUGIN_NAME = 'RiskIQ'
PLUGIN_ENABLED = True
PLUGIN_TIMES = ['06:00','14:00','22:00']

RISKIQ_URL = 'https://api.riskiq.net/pt/v2/'
RISKIQ_USER = 'YOUR RISKIQ USER'
RISKIQ_KEY = 'YOUR RISKIQ KEY'
RISKIQ_TLP = 'white'

MISP_TO_IDS = False
MISP_PUBLISH_EVENTS = False

HOURS_TO_CHECK = 9
ATTRIBUTE_PROGRESS = True

def get_articles():
    try:
        date_since = (datetime.utcnow() - timedelta(hours=HOURS_TO_CHECK)).strftime('%Y-%m-%d')
        article_url = urljoin(RISKIQ_URL, 'articles/')
        params = {'createdAfter': date_since, 'sort': 'created', 'order': 'asc'}
        response = requests.get(article_url, params=params, auth=(RISKIQ_USER, RISKIQ_KEY))

        if response.status_code == 200:
            return json.loads(response.text)['articles']

    except Exception as e:
        LOGGER.error('RiskIQ request error: {0}'.format(str(e)))

    return False

def make_new_event(misp, article):
    LOGGER.info('Creating new event...')
    event = MISPEvent()

    title = article['title']
    description = article['summary']
    tags = article['tags']
    tlp = RISKIQ_TLP.lower()
    reference = article['link']

    try:
        timestamp = dateparser.parse(article['publishedDate'])

    except Exception as ex:
        LOGGER.error('Cannot parse article creation date: {0}'.format(str(ex)))
        timestamp = datetime.utcnow()

    event_date = timestamp.strftime('%Y-%m-%d')
    event.info = title
    event.analysis = Analysis.completed
    event.distribution = Distribution.your_organisation_only
    event.threat_level_id = ThreatLevel.low

    if tags:
        for tag in tags:
            if tag.lower() in TAG_BLACKLIST:
               continue

            galaxy_tags = get_tags(misp, tag, 'contains')

            if galaxy_tags:
                for galaxy_tag in galaxy_tags:
                    LOGGER.info('Adding galaxy tag: "{0}"'.format(galaxy_tag))
                    event.add_tag(galaxy_tag)

            else:
                event.add_tag(tag)

    if description:
        LOGGER.info('Adding external analysis attribute.')
        event.add_attribute('comment', description, category='External analysis')

    if reference:
        event.add_tag('type:OSINT')

        if is_valid_url(reference):
            LOGGER.info('Adding attribute for reference: {0}'.format(reference))
            event.add_attribute('link', reference, category='External analysis')

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

def process_articles(misp, articles):
    LOGGER.info('Processing articles...')

    for article in articles:
        title = article['title']
        author = 'RiskIQ'

        LOGGER.info('New article from {0}: {1}'.format(author, title))

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
            event = make_new_event(misp, article)

        if not event:
            continue

        indicators = article['indicators']
        indicator_count = len(indicators)

        for indicator_category in indicators:
            indicator_type = indicator_category['type']
            indicator_list = indicator_category['values']
            indicator_count = len(indicator_list)

            LOGGER.info('Processing {0} indicators...'.format(indicator_count))

            for i, indicator_value in enumerate(indicator_list):
                if ATTRIBUTE_PROGRESS and i % 100 == 0:
                    progress_value = int(round(100 * (i / float(indicator_count))))
                    LOGGER.info('Event completion: {0}%'.format(progress_value))

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

                if indicator_type in ['hash_sha256', 'sha256']:
                    attribute_category = 'Payload delivery'
                    attribute_type = 'sha256'

                elif indicator_type in ['hash_sha1', 'sha1']:
                    attribute_category = 'Payload delivery'
                    attribute_type = 'sha1'

                elif indicator_type == 'hash_md5':
                    attribute_category = 'Payload delivery'
                    attribute_type = 'md5'

                elif indicator_type == 'url':
                    attribute_category = 'Network activity'
                    attribute_type = 'url'

                elif indicator_type == 'domain':
                    attribute_category = 'Network activity'
                    attribute_type = 'domain'

                elif indicator_type == 'ip':
                    attribute_category = 'Network activity'

                    if 'scan' in title.lower():
                        attribute_type = 'ip-src'

                    else:
                        attribute_type = 'ip-dst'

                elif indicator_type in ['email', 'emails']:
                    attribute_category = 'Payload delivery'
                    attribute_type = 'email-src'

                elif indicator_type in ['proces_mutex', 'process_mutex', 'mutex']:
                    attribute_category = 'Artifacts dropped'
                    attribute_type = 'mutex'

                elif indicator_type in ['filename', 'filepath']:
                    attribute_category = 'Artifacts dropped'
                    attribute_type = 'filename'

                elif indicator_type == 'certificate_sha1':
                    attribute_category = 'Network activity'
                    attribute_type = 'x509-fingerprint-sha1'

                else:
                    LOGGER.warning('Unsupported indicator type: {0}'.format(indicator_type))
                    continue

                attribute_json = {'category': attribute_category, 'type': attribute_type, 'value': indicator_value, 'to_ids': MISP_TO_IDS}

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

            LOGGER.info('Article complete!')



def plugin_run(misp):
    LOGGER.info('Collecting articles from RiskIQ...')

    articles = get_articles()

    if articles:
        process_articles(misp, articles)

    LOGGER.info('Run complete!')
