#!/usr/bin/python3
from pathlib import Path
from urllib.parse import urlparse

import argparse
import coloredlogs
import logging
import os
import re
import sys

LOGGER = logging.getLogger('beacon2empire')
coloredlogs.install(level='INFO', logger=LOGGER)

CLIENT_HEADER_BLACKLIST = ['connection', 'host']

def get_contents(filename):
    with open(filename) as f:
        lines = f.readlines()
        return '\t'.join([line.strip() for line in lines])

def get_profiles(directory):
    return (path for path in Path(directory).rglob('*.profile'))

def convert_profile(profile):
    LOGGER.info('Converting: {0}'.format(profile))

    profile_name = profile.name.split('.')[0]

    if '_' in profile_name:
        profile_name = profile_name.split('_')[0]

    profile_contents = get_contents(profile)

    jitter = re.findall(r'set\sjitter\s+\"([0-9]+)\";', profile_contents)
    sleeptime = re.findall(r'set\ssleeptime\s+\"([0-9]+)\";', profile_contents)
    useragent = re.findall(r'set\suseragent\s+\"([^\"]+)\";', profile_contents)

    if not useragent:
        LOGGER.error('A user agent must be defined.')
        return

    uri_list = re.findall(r'set\suri\s+\"([^\"]{2,})\";', profile_contents)

    if not uri_list:
        LOGGER.error('At least one URI must be defined.')
        return

    client_headers = []
    client_config = re.findall(r'http-[a-z]+\s\{.*?client\s\{(.*?)\}\s+\}', profile_contents)
    server_headers = []
    server_config = re.findall(r'http-[a-z]+\s\{.*?server\s\{(.*?)\}\s+\}', profile_contents)

    if client_config:
        for config_element in client_config:
            config_headers = re.findall(r'header\s\"([^\"]+)\"\s\"([^\"]+)', config_element)

            if config_headers:
                for config_header in config_headers:
                    if config_header[0].lower() in CLIENT_HEADER_BLACKLIST:
                        continue

                    joined_header = ':'.join(config_header)

                    if joined_header not in client_headers:
                        client_headers.append(joined_header)

    else:
        LOGGER.warning('No client configuration found.')

    if server_config:
        for config_element in server_config:
            config_headers = re.findall(r'header\s\"([^\"]+)\"\s\"([^\"]+)', config_element)

            if config_headers:
                for config_header in config_headers:
                    joined_header = ':'.join(config_header)

                    if joined_header not in server_headers:
                        server_headers.append(joined_header)

    else:
        LOGGER.warning('No server configuration found.')

    empire_config = 'listeners\r\n'
    empire_config += 'uselistener http\r\n'
    empire_config += 'set Name {0}\r\n'.format(profile_name)
    empire_config += 'set BindIP 0.0.0.0\r\n'
    empire_port = urlparse(EMPIRE_URL).port
    empire_config += 'set Port {0}\r\n'.format(empire_port)
    empire_config += 'set Host {0}\r\n'.format(PROXY_URL)

    if jitter:
        empire_config += 'set DefaultJitter {0}\r\n'.format(jitter[0])

    else:
        LOGGER.warning('Using default jitter: 0')
        empire_config += 'set DefaultJitter 0\r\n'

    if sleeptime:
        delay = int(sleeptime[0]) // 1000
        empire_config += 'set DefaultDelay {0}\r\n'.format(delay)

    else:
        LOGGER.warning('Using default delay: 5')
        empire_config += 'set DefaultDelay 5\r\n'

    default_profile = 'set DefaultProfile '
    default_profile += ','.join(uri_list).replace(' ', ',')
    default_profile += '|'
    default_profile += useragent[0]

    if client_headers:
        default_profile += '|'
        default_profile += '|'.join(client_headers)

    default_profile += '\r\n'
    empire_config += default_profile

    if server_headers:
        header_profile = 'set Headers '
        header_profile += '|'.join(server_headers)
        empire_config += header_profile

    apache_config = 'RewriteEngine On\r\n'
    apache_urilist = (uri.strip('/') for uri in uri_list)
    apache_uristring = '|'.join(apache_urilist).replace(' ', '|').replace('|/','|')
    apache_config += 'RewriteCond %{{REQUEST_URI}} ^/({0})/?$\r\n'.format(apache_uristring)
    apache_useragent = useragent[0].replace(' ','\ ').replace('.','\.').replace('(','\(').replace(')','\)')
    apache_useragent = apache_useragent.rstrip('\"')
    apache_config += 'RewriteCond %{{HTTP_USER_AGENT}} ^{0}?$\r\n'.format(apache_useragent)
    apache_config += 'RewriteRule ^.*$ {0}%{{REQUEST_URI}} [P]\r\n'.format(EMPIRE_URL)
    apache_config += 'RewriteRule ^.*$ {0}/? [L,R=302]'.format(REDIRECT_URL)
    
    LOGGER.info('Empire configuration:')
    print(empire_config)
    LOGGER.info('Apache rewrite configuration:')
    print(apache_config)
    
if __name__ == '__main__':
    parser_description = 'Convert Cobalt Strike Malleable C2 profiles to Empire listener and Apache mod_rewrite configurations.'
    parser = argparse.ArgumentParser(description=parser_description)
    parser.add_argument('-b', dest='beaconpath', help='Beacon Profile Path')
    parser.add_argument('-e', dest='empireurl', help='Empire URL (must include port). Format: http://12.34.56.78:80 or https://domain.goes.here:443')
    parser.add_argument('-p', dest='proxyurl', help='Proxy URL (must include port). Format: http://12.34.56.78:80 or https://domain.goes.here:443')
    parser.add_argument('-r', dest='redirecturl', help='Redirect URL. Format: http://12.34.56.78 or https://domain.goes.here')

    args = parser.parse_args()

    if not args.beaconpath:
        LOGGER.error('Missing Beacon profile path!')
        parser.print_help()
        sys.exit(1)

    if not args.empireurl:
        LOGGER.error('Missing Empire URL!')
        parser.print_help()
        sys.exit(1)
        
    if not args.proxyurl:
        LOGGER.error('Missing proxy URL!')
        parser.print_help()
        sys.exit(1)

    if not args.redirecturl:
        LOGGER.error('Missing redirect URL!')
        parser.print_help()
        sys.exit(1)

    PROFILE_PATH = args.beaconpath
    EMPIRE_URL = args.empireurl
    PROXY_URL = args.proxyurl
    REDIRECT_URL = args.redirecturl
    
    for profile in get_profiles(PROFILE_PATH):
        convert_profile(profile)