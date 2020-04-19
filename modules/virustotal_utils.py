#!/usr/bin/python3

from .geo_utils import get_home_name, resolve_asn
from .log_utils import get_module_logger
from .string_utils import double_url_encode, defang_url
from web.models import Compromise, CountryHit, Host, Domain, Setting
from datetime import datetime, timedelta
from django.utils import timezone

import dateutil.parser
import iptools
import json
import os
import requests
import sys
import time
import validators

logger = get_module_logger(__name__)

VT_KEY = Setting.objects.get(name='VirusTotal API Key').value1
VT_USER = Setting.objects.get(name='VirusTotal User').value1
VT_REQ_MIN = int(Setting.objects.get(name='VirusTotal Requests Per Minute').value1)
VT_WAIT = int(float(60) / VT_REQ_MIN)
VT_SEARCH_BASE = 'https://www.virustotal.com/gui/search/'
VT_PREFERRED_ENGINES = ['Malwarebytes','BitDefender','ESET-NOD32','Kaspersky','Sophos AV','GData','Emsisoft','Avira']
VT_SCORE_MIN = 3
VT_MAX_AGE = 60

class GenericReport(object):
    def __init__(self, observable, sourcename, sourceurl):
        self.observable = observable
        self.sourcename = sourcename
        self.sourceurl = sourceurl

# Sample: 185.7.78.31
def update_vt_ip_activity(host):
    ip_addr = host.address

    params = {'apikey': VT_KEY, 'ip': ip_addr}
    headers = {
        'Accept-Encoding': 'gzip, deflate',
        'User-Agent': VT_USER}

    logger.info('Querying VirusTotal for data associated with: {0}'.format(ip_addr))
    try:
        response = requests.get('https://www.virustotal.com/vtapi/v2/ip-address/report', params=params, headers=headers)

        logger.info('Waiting for a moment...')
        time.sleep(VT_WAIT)

        if response.status_code == 200:
            process_vt_response(host, json.loads(response.text))

        else:
            logger.error('Bad response code returned by VirusTotal.')
            logger.error(response.text)
            return False

        return True

    except requests.exceptions.ConnectionError as e:
        logger.error('Error querying VirusTotal: {0}'.format(str(e)))
        logger.info('Waiting for a minute...')
        time.sleep(90)

    except Exception as e:
        logger.error('Error querying VirusTotal: {0}'.format(str(e)))

    return False

# Sample: megapolis-trade.ru
def update_vt_domain_activity(domain):
    hostname = domain.domain

    params = {'apikey': VT_KEY, 'domain': hostname}
    headers = {
        'Accept-Encoding': 'gzip, deflate',
        'User-Agent': VT_USER}

    try:
        logger.info('Querying VirusTotal for data associated with: {0}'.format(hostname))
        response = requests.get('https://www.virustotal.com/vtapi/v2/domain/report', params=params, headers=headers)

        logger.info('Waiting for a moment...')
        time.sleep(VT_WAIT)

        if response.status_code == 200:
            process_vt_response(domain, json.loads(response.text))

        else:
            logger.error('Bad response code returned by VirusTotal.')
            logger.error(response.text)
            return False

        return True

    except requests.exceptions.ConnectionError as e:
        logger.error('Error querying VirusTotal: {0}'.format(str(e)))
        logger.info('Waiting for a minute...')
        time.sleep(90)

    except Exception as e:
        logger.error('Error querying VirusTotal: {0}'.format(str(e)))

    return False

def process_vt_response(entity, vt_report):
    if vt_report['response_code'] == 0:
        logger.info('Host not found.')

    if vt_report['response_code'] == 1:
        if isinstance(entity, Host) or isinstance(entity, Domain):
            entry_list = []
            generic_list = False

        else:
            entry_list = False
            generic_list = []

        if 'detected_downloaded_samples' in vt_report:
            for sample in vt_report['detected_downloaded_samples']:
                vt_positives = sample['positives']
                vt_added = sample['date']
                vt_total = sample['total']
                vt_sha256 = sample['sha256']

                if dateutil.parser.parse(vt_added) < (datetime.utcnow() - timedelta(days=VT_MAX_AGE)):
                    logger.warning('Sample exceeds age limit: {0}'.format(vt_sha256))
                    continue

                if vt_positives < VT_SCORE_MIN:
                    logger.warning('Potential false positive for sample: {0}'.format(vt_sha256))
                    continue

                vt_url = '{0}{1}'.format(VT_SEARCH_BASE, vt_sha256)

                if isinstance(entity, Host) or isinstance(entity, Domain):
                    if not Compromise.objects.filter(organisation=entity.organisation, sourceurl=vt_url).exists():
                        sample_class = get_class_for_hash(vt_sha256)

                        if sample_class:
                            logger.info('Discovered downloaded malware sample: {0} ({1})'.format(vt_sha256, sample_class))

                            sample_description = 'Malware Download: {0} ({1})'.format(vt_sha256, sample_class)

                            if isinstance(entity, Host):
                                new_entry = Compromise(added=timezone.now(), category='MalwareHosting', host=entity, description=sample_description, sourcename='VirusTotal', sourceurl=vt_url, organisation=entity.organisation)
                                entry_list.append(new_entry)

                            if isinstance(entity, Domain):
                                new_entry = Compromise(added=timezone.now(), category='MalwareHosting', domain=entity, description=sample_description, sourcename='VirusTotal', sourceurl=vt_url, organisation=entity.organisation)
                                entry_list.append(new_entry)

                else:
                    if not CountryHit.objects.filter(entity=entity, sourceurl=vt_url):
                        sample_class = get_class_for_hash(vt_sha256)

                        if sample_class:
                            logger.info('Discovered downloaded malware sample: {0} ({1})'.format(vt_sha256, sample_class))

                            sample_description = 'Malware Download: {0} ({1})'.format(vt_sha256, sample_class)

                            new_entry = GenericReport(sample_description, 'VirusTotal', vt_url)
                            generic_list.append(new_entry)

        if 'detected_referrer_samples' in vt_report:
            for sample in vt_report['detected_referrer_samples']:
                vt_positives = sample['positives']
                vt_total = sample['total']
                vt_sha256 = sample['sha256']

                if vt_positives < VT_SCORE_MIN:
                    logger.warning('Potential false positive for sample: {0}'.format(vt_sha256))
                    continue

                vt_url = '{0}{1}'.format(VT_SEARCH_BASE, vt_sha256)

                if isinstance(entity, Host) or isinstance(entity, Domain):
                    if not Compromise.objects.filter(organisation=entity.organisation, sourceurl=vt_url).exists():
                        sample_class = get_class_for_hash(vt_sha256)

                        if sample_class:
                            logger.info('Discovered referring malware sample: {0} ({1})'.format(vt_sha256, sample_class))

                            sample_description = 'Referring Malware: {0} ({1})'.format(vt_sha256, sample_class)

                            if isinstance(entity, Host):
                                new_entry = Compromise(added=timezone.now(), category='MalwareCommunication', host=entity, description=sample_description, sourcename='VirusTotal', sourceurl=vt_url, organisation=entity.organisation)
                                entry_list.append(new_entry)

                            if isinstance(entity, Domain):
                                new_entry = Compromise(added=timezone.now(), category='MalwareCommunication', domain=entity, description=sample_description, sourcename='VirusTotal', sourceurl=vt_url, organisation=entity.organisation)
                                entry_list.append(new_entry)

                else:
                    if not CountryHit.objects.filter(entity=entity, sourceurl=vt_url):
                        sample_class = get_class_for_hash(vt_sha256)

                        if sample_class:
                            logger.info('Discovered referring malware sample: {0} ({1})'.format(vt_sha256, sample_class))

                            sample_description = 'Referring Malware: {0} ({1})'.format(vt_sha256, sample_class)

                            new_entry = GenericReport(sample_description, 'VirusTotal', vt_url)
                            generic_list.append(new_entry)

        if 'detected_urls' in vt_report:
            for url in vt_report['detected_urls']:
                vt_positives = url['positives']
                vt_added = url['scan_date']
                vt_total = url['total']
                vt_url = defang_url(url['url'])

                if dateutil.parser.parse(vt_added) < (datetime.utcnow() - timedelta(days=VT_MAX_AGE)):
                    logger.warning('URL exceeds age limit: {0}'.format(vt_url))
                    continue

                if vt_positives < VT_SCORE_MIN:
                    logger.warning('Potential false positive for URL: {0}'.format(vt_url))
                    continue

                vt_search_url = '{0}{1}'.format(VT_SEARCH_BASE, double_url_encode(url['url']))

                if isinstance(entity, Host) or isinstance(entity, Domain):
                    if not Compromise.objects.filter(organisation=entity.organisation, sourceurl=vt_search_url).exists():
                        logger.info('Discovered malicious URL: {0}'.format(vt_url))

                        url_description = 'Malware URL: {0}'.format(vt_url)

                        if isinstance(entity, Host):
                            new_entry = Compromise(added=timezone.now(), category='MalwareHosting', host=entity, description=url_description, sourcename='VirusTotal', sourceurl=vt_search_url, organisation=entity.organisation)
                            entry_list.append(new_entry)

                        if isinstance(entity, Domain):
                            new_entry = Compromise(added=timezone.now(), category='MalwareHosting', domain=entity, description=url_description, sourcename='VirusTotal', sourceurl=vt_search_url, organisation=entity.organisation)
                            entry_list.append(new_entry)


                else:
                    if not CountryHit.objects.filter(entity=entity, sourceurl=vt_search_url):
                        logger.info('Discovered malicious URL: {0}'.format(vt_url))

                        url_description = 'Malware URL: {0}'.format(vt_url)

                        new_entry = GenericReport(url_description, 'VirusTotal', vt_search_url)
                        generic_list.append(new_entry)

        if entry_list != False:
            if len(entry_list) > 0:
                logger.info('Saving items...')
                Compromise.objects.bulk_create(entry_list)

            else:
                logger.info('There are no new items to save.')

            return True

        if generic_list != False:
            if len(generic_list) > 0:
                logger.info('Returning generic list...')
                return generic_list

            else:
                logger.info('There are no new items to return.')

            return []

        logger.warning('Unhandled return type encountered.')
        return False


def get_class_from_scans(scans):
    for engine in VT_PREFERRED_ENGINES:
        if engine in scans:
            if scans[engine]['detected']:
                return scans[engine]['result']

    logger.warning('Unable to determine sample classification. Returning generic response.')

    return 'Malware.Generic'


def get_class_for_hash(sha256):
    params = {'apikey': VT_KEY, 'resource': sha256}
    headers = {
        'Accept-Encoding': 'gzip, deflate',
        'User-Agent': VT_USER}

    try:
        logger.info('Querying VirusTotal for classification associated with: {0}'.format(sha256))
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)

        logger.info('Waiting for a moment...')
        time.sleep(VT_WAIT)

        if response.status_code == 200:
            vt_report = json.loads(response.text)

            if vt_report['response_code'] == 0:
                logger.warning('File not found.')

            if vt_report['response_code'] == 1:
                if dateutil.parser.parse(vt_report['scan_date']) < (datetime.utcnow() - timedelta(days=VT_MAX_AGE)):
                    logger.warning('Sample exceeds age limit: {0}'.format(sha256))
                    return False

                if vt_report['positives'] < VT_SCORE_MIN:
                    logger.warning('Potential false positive for sample: {0}'.format(sha256))
                    return False

                if 'scans' in vt_report:
                    scans = vt_report['scans']
                    return get_class_from_scans(scans)

                else:
                    logger.warning('No scans for file.')

        else:
            logger.error('Bad response code returned by VirusTotal.')
            logger.error(response.text)

    except requests.exceptions.ConnectionError as e:
        logger.error('Error querying VirusTotal: {0}'.format(str(e)))
        logger.info('Waiting for a minute...')
        time.sleep(90)

    except Exception as e:
        logger.error('Error querying VirusTotal: {0}'.format(str(e)))

    return False


def enrich_country_hosts():
    logger.info('Beginning {0} host enrichment...'.format(get_home_name()))

    host_list = list(CountryHit.objects.filter(category='MalwareCommunication').values_list('entity', flat=True).distinct())

    entry_list = []

    for host in host_list:
        if iptools.ipv4.validate_cidr(host):
            logger.warning('Cannot search VirusTotal for CIDR ranges: {0}'.format(host))
            continue

        params = {'apikey': VT_KEY, 'ip': host}
        headers = {
            'Accept-Encoding': 'gzip, deflate',
            'User-Agent': VT_USER}

        try:
            logger.info('Querying VirusTotal for data associated with: {0}'.format(host))
            response = requests.get('https://www.virustotal.com/vtapi/v2/ip-address/report', params=params, headers=headers)

            logger.info('Waiting for a moment...')
            time.sleep(VT_WAIT)

            if response.status_code == 200:
                observable_list = process_vt_response(host, json.loads(response.text))

                if observable_list:
                    if len(observable_list) > 0:
                        for observable in observable_list:
                            host_asn = resolve_asn(host)

                            new_item = CountryHit(added=timezone.now(), category='MalwareCommunication', entity=host, asn=host_asn, observable=observable.observable, sourcename=observable.sourcename, sourceurl=observable.sourceurl, country=get_home_name())
                            entry_list.append(new_item)

                    else:
                        logger.info('No observables returned.')

            else:
                logger.error('Failed to query VirusTotal.')
                logger.error(response.text)
                return False

        except requests.exceptions.ConnectionError as e:
            logger.error('Failed to connect to VirusTotal: {0}'.format(str(e)))
            logger.info('Waiting for a minute...')
            time.sleep(90)

        except Exception as e:
            logger.error('Error querying VirusTotal: {0}'.format(str(e)))
            return False

    if len(entry_list) > 0:
        logger.info('Saving items...')
        CountryHit.objects.bulk_create(entry_list)

    else:
        logger.info('There are no new items to save.')

    return True


def get_report_for_hash(sha256):
    params = {'apikey': VT_KEY, 'resource': sha256}
    headers = {
        'Accept-Encoding': 'gzip, deflate',
        'User-Agent': VT_USER}

    try:
        logger.info('Querying VirusTotal for classification associated with: {0}'.format(sha256))
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)

        logger.info('Waiting for a moment...')
        time.sleep(VT_WAIT)

        if response.status_code == 200:
            vt_report = json.loads(response.text)

            logger.info('Report: {0}'.format(vt_report))

        else:
            logger.error('Bad response code returned by VirusTotal.')
            logger.error(response.text)

    except requests.exceptions.ConnectionError as e:
        logger.error('Error querying VirusTotal: {0}'.format(str(e)))
        logger.info('Waiting for a minute...')
        time.sleep(90)

    except Exception as e:
        logger.error('Error querying VirusTotal: {0}'.format(str(e)))

    return False

