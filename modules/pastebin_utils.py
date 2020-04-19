#!/usr/bin/python3

from .cache_utils import get_paste_strings, is_cached_paste, add_to_paste_cache, get_keyword_organisation
from .log_utils import get_module_logger
from django.utils import timezone
from web.models import Paste

import json
import jsonpickle
import os
import re
import requests
import sys
import time

logger = get_module_logger(__name__)

PASTE_BATCH_SIZE = 150

class RecentPaste(object):
    def __init__(self, title, key, scrape_url, full_url):
        self.title = title
        self.key = key
        self.scrape_url = scrape_url
        self.full_url = full_url


class KeywordMatches(object):
    def __init__(self, organisation, matches):
        self.organisation = organisation
        self.matches = matches


def process_paste_data(paste_data):
    matches = []

    monitored_strings = get_paste_strings()

    for monitored_string in monitored_strings:
        if monitored_string in paste_data:
            organisation = get_keyword_organisation(monitored_string)

            if organisation:
                logger.info('Hit for keyword: {0} ({1})'.format(monitored_string, organisation.name))

                existing_object = [x for x in matches if x.organisation == organisation]

                if len(existing_object) > 0:
                    existing_object[0].matches.append(monitored_string)

                else:
                    matches.append(KeywordMatches(organisation, [monitored_string]))

    if len(matches) > 0:
        return matches

    return []


def get_recent_pastebin_list():
    try:
        return_list = []

        logger.info('Getting recent PasteBin pastes...')

        paste_url = 'https://scrape.pastebin.com/api_scraping.php?limit={0}'.format(PASTE_BATCH_SIZE)

        request = requests.get(paste_url)

        if request.status_code == 200:
            paste_data = request.text
            paste_list = []

            try:
                paste_list = json.loads(paste_data)

            except ValueError as e:
                logger.error('Invalid PasteBin response: {0}'.format(paste_data))

            for paste_item in paste_list:
                if not is_cached_paste(paste_item['key']):
                    title = paste_item['title']

                    if not title:
                        title = 'Untitled'

                    return_list.append(RecentPaste(title, paste_item['key'], paste_item['scrape_url'], paste_item['full_url']))

                else:
                    logger.warning('PasteBin paste with key "{0}" has already been processed.'.format(paste_item['key']))

        elif request.status_code == 522:
            logger.error('Pastebin API did not respond. Potentially overloaded.')
            return []

        if len(return_list) > 0:
            return return_list

    except requests.exceptions.ConnectionError as e:
        logger.error('Problem connecting to PasteBin. Error: {0}'.format(e))

    except Exception as e:
        logger.error('Problem connecting to PasteBin. Aborting task.')
        logger.error(sys.exc_info())
        logger.error(type(e))
        logger.error(e.args)
        logger.error(e)

    return []


def process_pastebin_list(paste_list):
    return_list = []

    logger.info('Processing recent PasteBin pastes...')

    for paste_item in paste_list:
        try:
            request = requests.get(paste_item.scrape_url)

            if request.status_code == 200:
                paste_body = request.text
                paste_matches = process_paste_data(paste_body)

                if len(paste_matches) > 0:
                    for paste_match in paste_matches:
                        logger.info('Found matches for PasteBin paste with key "{0}": ({1})'.format(paste_item.key, paste_match.organisation.name))

                        return_list.append(Paste(added=timezone.now(), title=paste_item.title, body=paste_body, key=paste_item.key, matches=paste_match.matches, url=paste_item.full_url, organisation=paste_match.organisation))

            elif request.status_code == 522:
                logger.error('Pastebin API did not respond. Potentially overloaded.')
                return []

        except requests.exceptions.ConnectionError as e:
            logger.error('Problem connecting to PasteBin. Error: {0}'.format(e))

        except Exception as e:
            logger.error('Problem connecting to PasteBin. Aborting task.')
            logger.error(sys.exc_info())
            logger.error(type(e))
            logger.error(e.args)
            logger.error(e)

        add_to_paste_cache(paste_item.key)

        time.sleep(1)

    if len(return_list) > 0:
        return return_list

    return []


def pastebin_listen():
    logger.info('Starting PasteBin listener...')

    while True:
        recent_pastes = get_recent_pastebin_list()

        if len(recent_pastes) > 0:
            relevant_pastes = process_pastebin_list(recent_pastes)

            if len(relevant_pastes) > 0:
                try:
                    logger.info('Saving items...')

                    Paste.objects.bulk_create(relevant_pastes)

                except Exception as e:
                    logger.error('Problem saving PasteBin data.')
                    logger.error(sys.exc_info())
                    logger.error(type(e))
                    logger.error(e.args)
                    logger.error(e)

        logger.info('Finished PasteBin run.')

        if len(recent_pastes) >= (PASTE_BATCH_SIZE / 2):
            logger.info('Waiting a moment...')
            time.sleep(30)

        elif len(recent_pastes) == 0:
            logger.warning('Empty PasteBin paste list. Waiting a minute...')
            time.sleep(60)

        else:
            logger.info('Waiting a minute...')
            time.sleep(60)
