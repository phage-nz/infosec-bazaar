#!/usr/bin/python3

from .feed_utils import process_feed
from .geo_utils import get_home_isocode
from .log_utils import get_module_logger
from .string_utils import clean_url, get_host_from_url
from datetime import datetime, timedelta
from django.utils import timezone
from web.models import Compromise, Setting

import json
import logging
import requests
import time

logger = get_module_logger(__name__)

SEARCH_URL = 'https://urlscan.io/api/v1/search/'
REPORT_URL = 'https://urlscan.io/api/v1/result/'
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.89 Safari/537.36'
DAYS_TO_CHECK = 1

class UrlscanObservable:
  def __init__(self, ref_name, ref_url, o_type, o_value):
    self.ref_name = ref_name
    self.ref_url = ref_url
    self.o_type = o_type
    self.o_value = o_value


def find_bad_refs(domain):
    try:
        query_list = []
        entry_list = []

        user_agent = {'User-agent': USER_AGENT}

        today = datetime.utcnow()
        threshold = today - timedelta(days=1)

        logger.info('Fetching urlscan bad reference data...')

        url_query = 'page.url:{0} AND date:[{1} TO {2}]'.format(domain.domain.split('.')[0], threshold.strftime('%Y-%m-%d'), today.strftime('%Y-%m-%d'))
        query_list.append(url_query)

        domain_query = '{0} AND !page.domain:{0} AND date:[{1} TO {2}]'.format(domain.domain, threshold.strftime('%Y-%m-%d'), today.strftime('%Y-%m-%d'))
        query_list.append(domain_query)

        for query in query_list:
            logger.info('Performing query: {0}'.format(query))

            payload = {'q': query}

            request = requests.get(SEARCH_URL, params=payload, headers=user_agent)

            if request.status_code == 200:
                logger.info('Request successful!')

                response = json.loads(request.text)

                if 'results' in response:
                    for result in response['results']:
                        if 'task' in result:
                            host_name = get_host_from_url(url)
                            url = defang_url(result['task']['url'])
                            url_description = 'Phishing URL: {0}'.format(url)

                            if not host_name.endswith(domain.domain):
                                if not Compromise.objects.filter(organisation=domain.organisation, description=url_description).exists():
                                    if 'url:' in query:
                                        logger.info('Found {0} string in URL: {1}'.format(domain.organisation.name, url))

                                    elif 'domain:' in query:
                                        logger.info('Found link to {0} domain in page: {1}'.format(domain.organisation.name, url))

                                    new_entry = Compromise(added=timezone.now(), category='MalwareHosting', domain=domain, description=url_description, sourcename='urlscan', sourceurl=SEARCH_URL, organisation=domain.organisation)
                                    entry_list.append(new_entry)

                            else:
                                logger.warning('Possible false positive for {0}: {1}'.format(domain.domain, url))

            else:
                logger.warning('Problem connecting to urlscan. Error: {0}'.format(e))
                return False

            time.sleep(2)

        if len(entry_list) > 0:
            logger.info('Deduping URL list...')

            entry_list = list(set(url_list))

            logger.info('Saving items...')
            Compromise.objects.bulk_create(entry_list)

        else:
            logger.info('There are no new items to save.')

        return True

    except requests.exceptions.ConnectionError as e:
        logger.warning('Problem connecting to urlscan. Error: {0}'.format(e))

    except Exception as e:
        logger.warning('Problem connecting to urlscan: {0}'.format(str(e)))

    return False


def get_urlscan_list():
    try:
        query_list = []
        url_list = []

        user_agent = {'User-agent': USER_AGENT}

        today = datetime.utcnow()
        threshold = today - timedelta(days=DAYS_TO_CHECK)

        logger.info('Fetching urlscan phishing data...')

        country_query = 'country:{0} AND date:[{1} TO {2}]'.format(get_home_isocode(), threshold.strftime('%Y-%m-%d'), today.strftime('%Y-%m-%d'))
        query_list.append(country_query)

        domain_query = 'page.domain:{0} AND date:[{1} TO {2}]'.format(get_home_isocode().lower(), threshold.strftime('%Y-%m-%d'), today.strftime('%Y-%m-%d'))
        query_list.append(domain_query)

        for query in query_list:
            payload = {'q': query}
            logger.info('Performing query: {0}'.format(query))

            request = requests.get(SEARCH_URL, params=payload, headers=user_agent)

            logger.info('Waiting a moment...')
            time.sleep(2)

            if request.status_code == 200:
                logger.info('Request successful!')

                report_list = []
                response = json.loads(request.text)

                if 'results' in response:
                    for result in response['results']:
                        report_list.append(result['_id'])

                    for report in report_list:
                        logger.info('Requesting report: {0}'.format(report))
                        report_url = '{0}{1}'.format(REPORT_URL, report)

                        request = requests.get(report_url, headers=user_agent)

                        logger.info('Waiting a moment...')
                        time.sleep(2)

                        if request.status_code == 200:
                            logger.info('Request successful!')

                            response = json.loads(request.text)

                            if 'stats' in result and 'task' in response:
                                if bool(response['stats']['malicious']):
                                    url = clean_url(response['task']['url'])
                                    logger.info('URL marked as malicious: {0}'.format(url))
                                    url_list.append(UrlscanObservable('urlscan', report_url, 'MalwareHosting', url))

        return url_list

    except requests.exceptions.ConnectionError as e:
        logger.warning('Problem connecting to urlscan. Error: {0}'.format(e))

    except Exception as e:
        logger.warning('Problem connecting to urlscan: {0}'.format(str(e)))

    return []


def check_urlscan():
    observable_list = get_urlscan_list()

    logger.info('Processing collected observables...')

    if len(observable_list) > 0:
        process_feed(observable_list)

    else:
        logger.warning('urlscan observable list is empty.')
