#!/usr/bin/python3

MISP_URL = 'https://misp.yourdomain.here/'
MISP_ADMIN_KEY = 'YOUR MISP ADMIN KEY'
MISP_USER_KEY = 'YOUR MISP USER KEY'
MISP_VALIDATE_SSL = True

MISP_TIMES = ['06:00', '18:00']
TEXT_TIMES = ['06:00', '12:00', '18:00', '00:00']
HOURLY_FEEDS = []

ENABLE_EXPORT = True
EXPORT_DAYS = 90
EXPORT_PAGE_SIZE = 5000
EXPORT_TAGS = ['tlp:white','tlp:green','tlp:amber','osint:source-type="block-or-filter-list"']
EXPORT_TYPES = ['domain','email-src','email-subject','hostname','url','ip-dst','ip-src','sha256']
EXPORT_MERGE_HOSTNAME = True
EXPORT_PATH = '/var/www/MISP/app/webroot/export'
EXPORT_KEY = 'RANDOM ALPHANUMERIC STRING'

WHITELIST_FILE = 'whitelist.txt'

IP_BLACKLIST = ['0.0.0.0', '127.0.0.1', '127.0.1.1', '192.168.1.']
URL_BLACKLIST = ['//t.co/', 'abuse.ch', 'app.any.run', 'capesandbox.com', 'otx.alienvault.com', 'proofpoint.com', 'tria.ge', 'twitter.com', 'virustotal.com', 'www.cloudflare.com']
SAMPLE_BLACKLIST = ['arm','bashlite','elf','gafgyt','mirai','mozi','script']
TAG_BLACKLIST = ['32','exe','dll','dfir','doc','encrypted','excel','hta','isc','iso','malware','msi','microsoft','n/a','none','pe','phishing','ransomware','rtf','script','threat','trojan','xls']
