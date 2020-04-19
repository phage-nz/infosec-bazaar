#!/usr/bin/python3

from .dns_utils import resolve_dns
from .log_utils import get_module_logger
from .string_utils import get_host_from_url, is_valid_url, get_path_from_url
from web.models import Setting

import geoip2.database
import iptools
import netaddr
import random
import validators

MAXMIND_CITY_DB_PATH = Setting.objects.get(name='MaxMind City Database Path').value1
MAXMIND_ASN_DB_PATH = Setting.objects.get(name='MaxMind ASN Database Path').value1

logger = get_module_logger(__name__)
city_reader = geoip2.database.Reader(MAXMIND_CITY_DB_PATH)
asn_reader = geoip2.database.Reader(MAXMIND_ASN_DB_PATH)

def get_home_isocode():
    return Setting.objects.get(name='Home Country').value2.upper()

def get_home_name():
    return Setting.objects.get(name='Home Country').value1

def ip_is_of_interest(host):
    try:
        response = city_reader.city(host)

        if response is not None:
            if response.country.iso_code is not None:
                return response.country.iso_code == get_home_isocode()

            if response.continent.code is not None:
                return response.continent.code == get_home_isocode()
        else:
            logger.error('Failed to perform GeoLookup for address: {0}'.format(host))

    except Exception as e:
        logger.error('Error performing GeoLookup for {0}: {1}'.format(host, str(e)))

    return False

def tld_is_of_interest(host):
    if host.split('.')[-1].upper() == get_home_isocode():
        return True

    return False

def url_is_of_interest(url):
    host_name = get_host_from_url(url)
    url_path = get_path_from_url(url)

    if tld_is_of_interest(url):
        return True

    if '.{0}'.format(get_home_isocode().lower()) in url_path:
        return True

    return False

def is_of_interest(observable):
    interest = False

    try:
        if iptools.ipv4.validate_ip(observable):
            interest = ip_is_of_interest(observable)

        elif iptools.ipv4.validate_cidr(observable):
            first_ip = iptools.ipv4.cidr2block(observable)[0]
            interest = ip_is_of_interest(first_ip)

        elif validators.domain(observable.lower()):
            interest = tld_is_of_interest(observable)

        elif is_valid_url(observable):
            interest = url_is_of_interest(observable)

        else:
            logger.error('Unable to determine observable type: {0}'.format(observable))

    except Exception as e:
        logger.error('Failed to valudate observable: {0} ({1})'.format(observable, str(e)))

    if interest:
        return(observable)

    return False


def resolve_asn(host):
    if iptools.ipv4.validate_cidr(host):
        host = str(random.choice(netaddr.IPNetwork(host)))

    if validators.ipv4(host):
        return asn_lookup(host)

    if validators.domain(host.lower()):
        ip_addr = resolve_dns(host)

        if ip_addr:
            return asn_lookup(ip_addr)

    return 'AS0000 Unknown'


def asn_lookup(ip_addr):
    if validators.ipv4(ip_addr):
        try:
            response = asn_reader.asn(ip_addr)

            if response is not None:
                asn_number = response.autonomous_system_number
                asn_org = response.autonomous_system_organization
                return 'AS{0} {1}'.format(asn_number, asn_org)

        except Exception as e:
            logger.warning('Failed to perform ASN lookup for address {0}: {1}'.format(ip_addr, str(e)))

    else:
        logger.warning('Invalid IP address: {0}'.format(ip_addr))

    return 'AS0000 Unknown'
