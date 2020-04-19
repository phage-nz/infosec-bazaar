#!/usr/bin/python3

from .geo_utils import get_home_isocode, get_home_name, resolve_asn
from .log_utils import get_module_logger
from .string_utils import defang_url
from django.utils import timezone
from web.models import Host, Compromise, SensorHit, OpenPort, PortCVE, Setting, CountryHit

import json
import requests

logger = get_module_logger(__name__)

BE_API_KEY = Setting.objects.get(name='BinaryEdge API Key').value1

#curl 'https://api.binaryedge.io/v2/query/ip/xxx.xxx.xxx.xxx' -H 'X-Key:API_KEY'
#curl 'https://api.binaryedge.io/v2/query/torrent/ip/xxx.xxx.xxx.xxx' -H 'X-Key:API_KEY'
#curl 'https://api.binaryedge.io/v2/query/dataleaks/organization/example.com' -H 'X-Key:API_KEY'
#curl 'https://api.binaryedge.io/v2/query/dataleaks/email/user@example.com' -H 'X-Key:API_KEY'
#curl 'https://api.binaryedge.io/v2/query/domains/subdomain/example.com' -H 'X-Key:API_KEY'
#curl 'https://api.binaryedge.io/v2/query/sensors/ip/xxx.xxx.xxx.xxx' -H 'X-Key:API_KEY'

def update_host_ports(host):
    api_url = 'https://api.binaryedge.io/v2/query/ip/{0}'.format(host.address)
    headers = {'X-Key': BE_API_KEY}

    response = requests.get(api_url, headers=headers)

    if response.status_code == 200:
        be_report = json.loads(response.text)

        if not be_report['targets_found'] > 0:
            logger.warning('Empty report returned by API.')
            return False

        entry_list = []

        for event in be_report['events']:
            event_data = None

            for result_set in event['results']:
                if 'service' in result_set['result']['data']:
                    event_data = result_set

            if event_data is None:
                continue

            event_port = event['port']
            service_data = event_data['result']['data']['service']

            service_name = None
            service_banner = None

            if 'product' in service_data:
                service_name = service_data['product']

            elif 'name' in service_data:
                service_name = service_data['name']

            if 'banner' in service_data:
                service_banner = service_data['banner']

            if 'version' in service_data and service_name is not None:
                service_version = service_data['version']
                service_name = '{0} ({1})'.format(service_name, service_version)

            logger.info('Found open port {0}:{1}!'.format(host.address, event_port))

            new_entry = OpenPort(host=host, port=event_port, service=service_name, banner=service_banner, organisation=host.organisation)
            entry_list.append(new_entry)

        if len(entry_list) > 0:
            logger.info('Saving items...')
            OpenPort.objects.bulk_create(entry_list)

        else:
            logger.info('There are no new items to save.')

        logger.info('Querying vulnerabilities for exposed host...')
        vuln_update = update_host_vulns(host)

        return vuln_update

    elif response.status_code == 404:
        logger.info('No port data available for address.')
        return True

    else:
        logger.error('Failed to query BinaryEdge.')
        logger.error(response.text)
        return False


# Sample: 125.237.31.55
def update_host_vulns(host):
    api_url = 'https://api.binaryedge.io/v2/query/cve/ip/{0}'.format(host.address)
    headers = {'X-Key': BE_API_KEY}

    response = requests.get(api_url, headers=headers)

    if response.status_code == 200:
        be_report = json.loads(response.text)

        query_results = be_report['events']['results']

        if not len(query_results) > 0:
            logger.warning('Empty result set returned by API.')
            return False

        for vuln_result in query_results:
            port = vuln_result['port']
            cve_list = vuln_result['cves']

            if len(cve_list) > 0:
                entry_list = []

                open_port = OpenPort.objects.get(host=host,port=port)

                for cve in cve_list:
                    logger.info('{0}:{1} marked with {2}'.format(host.address, port, cve['cve']))

                    new_entry = PortCVE(cve=cve['cve'],cvss=cve['cvss'],host=host,port=open_port,organisation=open_port.organisation)
                    entry_list.append(new_entry)

                if len(entry_list) > 0:
                    logger.info('Saving items...')
                    PortCVE.objects.bulk_create(entry_list)

                else:
                    logger.info('There are no new items to save.')

        else:
            logger.info('No ports marked as vulnerable.')

    elif response.status_code == 404:
        logger.info('No vulnerability data available for host.')

    else:
        logger.error('Failed to query BinaryEdge.')
        logger.error(response.text)
        return False

    return True


# Sample: 121.98.178.19
def update_torrent_status(host):
    api_url = 'https://api.binaryedge.io/v2/query/torrent/ip/{0}'.format(host.address)
    headers = {'X-Key': BE_API_KEY}

    response = requests.get(api_url, headers=headers)

    if response.status_code == 200:
        logger.info('Torrent activity discovered for host.')

        Host.objects.filter(pk=host.pk).update(torrentdetected=True)

    elif response.status_code == 404:
        logger.info('No torrent activity found for host.')

    else:
        logger.error('Failed to query BinaryEdge.')
        logger.error(response.text)
        return False

    return True


# Sample: 27.252.178.31
# Sample: 134.209.14.237 
def update_honeypot_activity(host):
    api_url = 'https://api.binaryedge.io/v2/query/sensors/ip/{0}'.format(host.address)
    headers = {'X-Key': BE_API_KEY}

    response = requests.get(api_url, headers=headers)

    if response.status_code == 200:
        be_report = json.loads(response.text)

        if not be_report['total'] > 0:
            logger.warning('Empty result set returned by API.')
            return False

        logger.info('Found honeypot sensor hits for host...')

        entry_list = []

        for honey_event in be_report['events']:
            honey_data = honey_event['results'][0]

            target_protocol = honey_data['target']['protocol'].upper()
            target_port = honey_data['target']['port']
            payload = honey_data['data']['payload']
            tags = []
            notes = ''

            if 'tags' in honey_data['data']:
                tags = [x.lower() for x in honey_data['data']['tags']]

            if 'extra' in honey_data['data']:
                notes = honey_data['data']['extra']

            if not SensorHit.objects.filter(host=host, targetprotocol=target_protocol, targetport=target_port, payload=payload).exists():
                new_entry = SensorHit(added=timezone.now(), host=host, targetprotocol=target_protocol, targetport=target_port, payload=payload, tags=tags, organisation=host.organisation, notes=notes)
                entry_list.append(new_entry)

        if len(entry_list) > 0:
            logger.info('Saving items...')
            SensorHit.objects.bulk_create(entry_list)

        else:
            logger.info('There are no new items to save.')

    elif response.status_code == 404:
        logger.info('No honeypot data available for address.')

    else:
        logger.error('Failed to query BinaryEdge.')
        logger.error(response.text)
        return False

    return True


def update_domain_leaks(domain):
    api_url = 'https://api.binaryedge.io/v2/query/dataleaks/organization/{0}'.format(domain.domain)
    headers = {'X-Key': BE_API_KEY}

    response = requests.get(api_url, headers=headers)

    if response.status_code == 200:
        be_report = json.loads(response.text)

        if not be_report['total'] > 0:
            logger.warning('Empty result set returned by API.')
            return False

        logger.info('Found compromises for domain: {0}'.format(domain.domain))

        entry_list = []

        for leak in be_report['groups']:
            leak_name = leak['leak']
            leak_count = leak['count']
            compromise_string = 'Leak: {0} ({1} hits)'.format(leak_name, leak_count)

            if not Compromise.objects.filter(domain=domain, description=compromise_string).exists():
                new_entry = Compromise(added=timezone.now(), category='AccountCompromise', domain=domain, description=compromise_string, sourcename='BinaryEdge', sourceurl='https://app.binaryedge.io/services/dataleaks', organisation=domain.organisation)
                entry_list.append(new_entry)

        if len(entry_list) > 0:
            logger.info('Saving items...')
            Compromise.objects.bulk_create(entry_list)

        else:
            logger.info('There are no new items to save.')

    elif response.status_code == 404:
        logger.info('No leak data available for domain.')

    else:
        logger.error('Failed to query BinaryEdge.')
        logger.error(response.text)
        return False

    return True


def update_email_leaks(email):
    api_url = 'https://api.binaryedge.io/v2/query/dataleaks/email/{0}'.format(email.email)
    headers = {'X-Key': BE_API_KEY}

    response = requests.get(api_url, headers=headers)

    if response.status_code == 200:
        be_report = json.loads(response.text)

        if not be_report['total'] > 0:
            logger.warning('Empty result set returned by API.')
            return False

        logger.info('Found compromises for email: {0}'.format(email.email))

        entry_list = []

        for leak_name in be_report['events']:
            compromise_string = 'Leak: {0}'.format(leak_name)

            if not Compromise.objects.filter(email=email, description=compromise_string).exists():
                new_entry = Compromise(added=timezone.now(), category='AccountCompromise', email=email, description=compromise_string, sourcename='BinaryEdge', sourceurl='https://app.binaryedge.io/services/dataleaks', organisation=email.organisation)
                entry_list.append(new_entry)

        if len(entry_list) > 0:
            logger.info('Saving items...')
            Compromise.objects.bulk_create(entry_list)

        else:
            logger.info('There are no new items to save.')

    elif response.status_code == 404:
        logger.info('No leak data available for email.')

    else:
        logger.error('Failed to query BinaryEdge.')
        logger.error(response.text)
        return False

    return True


def find_c2_hosts():
    country = get_home_name()
    category = 'MalwareCommunication'

    logger.info('Checking for {0} C2 items...'.format(country))

    api_url = 'https://api.binaryedge.io/v2/query/search?query=country:{0}%20AND%20tag:MALWARE'.format(get_home_isocode())
    headers = {'X-Key': BE_API_KEY}

    response = requests.get(api_url, headers=headers)

    if response.status_code == 200:
        be_report = json.loads(response.text)

        if not be_report['total'] > 0:
            logger.warning('Empty result set returned by API.')
            return False

        logger.info('C2 activity discovered for {0}.'.format(country))

        entry_list = []

        for malware_event in be_report['events']:
            result_data = malware_event['result']['data']
            host_data = malware_event['target']

            if not 'service' in result_data:
                continue

            event_host = host_data['ip']
            event_port = host_data['port']
            event_family = result_data['service']['name']
            event_observable = '{0}:{1} ({2})'.format(defang_url(event_host), event_port, event_family)

            logger.info('Found C2 host: {0}'.format(event_observable))

            if not CountryHit.objects.filter(observable=event_observable).exists():
                host_asn = resolve_asn(event_host)

                new_entry = CountryHit(added=timezone.now(), category=category, entity=event_host, asn=host_asn, observable=event_observable, sourcename='BinaryEdge', sourceurl=api_url, country=country)
                entry_list.append(new_entry)

        if len(entry_list) > 0:
            logger.info('Saving items...')
            CountryHit.objects.bulk_create(entry_list)

        else:
            logger.info('There are no new items to save.')

    elif response.status_code == 404:
        logger.info('No C2 activity found for {0}.'.format(country))

    else:
        logger.error('Failed to query BinaryEdge.')
        logger.error(response.text)
        return False

    return True


def find_malicious_hosts():
    country = get_home_name()
    category = 'MalwareCommunication'

    logger.info('Checking for malicious {0} items...'.format(country))

    api_url = 'https://api.binaryedge.io/v2/query/sensors/search?query=country:{0}%20AND%20tags:MALICIOUS'.format(get_home_isocode())
    headers = {'X-Key': BE_API_KEY}

    response = requests.get(api_url, headers=headers)

    if response.status_code == 200:
        be_report = json.loads(response.text)

        if not be_report['total'] > 0:
            logger.warning('Empty result set returned by API.')
            return False

        logger.info('Malicious activity discovered for {0}.'.format(country))

        entry_list = []

        for malware_event in be_report['events']:
            result_data = malware_event['data']
            origin_data = malware_event['origin']
            target_data = malware_event['target']

            event_host = origin_data['ip']
            event_port = target_data['port']
            event_protocol = target_data['protocol']
            event_tags = result_data['tags']

            if 'MALIGN' in event_tags:
                event_tags.remove('MALIGN')

            if 'MALICIOUS' in event_tags:
                event_tags.remove('MALICIOUS')

            event_family = ', '.join(event_tags).lower()
            event_payload = result_data['payload']
            event_observable = '{0} ({1}/{2}) ({3})'.format(defang_url(event_host), event_protocol, event_port, event_family)

            logger.info('Found malicious host: {0}'.format(event_observable))

            if not CountryHit.objects.filter(observable=event_observable).exists():
                host_asn = resolve_asn(event_host)

                new_entry = CountryHit(added=timezone.now(), category=category, entity=event_host, asn=host_asn, observable=event_observable, sourcename='BinaryEdge', sourceurl=api_url, country=country, notes=event_payload)
                entry_list.append(new_entry)

        if len(entry_list) > 0:
            logger.info('Saving items...')
            CountryHit.objects.bulk_create(entry_list)

        else:
            logger.info('There are no new items to save.')

    elif response.status_code == 404:
        logger.info('No malicious activity found for {0}.'.format(country))

    else:
        logger.error('Failed to query BinaryEdge.')
        logger.error(response.text)
        return False

    return True
