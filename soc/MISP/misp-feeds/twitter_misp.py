#!/usr/bin/python3

# cfscrape requires NodeJS for JS challenge bypass:
# apt install nodejs
from cfscrape import create_scraper
from collections import Counter
from datetime import datetime, timedelta
from pymisp import PyMISP, MISPEvent, MISPAttribute, ThreatLevel, Distribution, Analysis

import coloredlogs
import iocextract
import logging
import re
import sys
import requests
import time
import tweepy
import urllib.parse
import urllib3
import validators

LOGGER = logging.getLogger('twittermisp')
logging.basicConfig(filename='misp_feeds.log', format='%(asctime)s %(name)s %(levelname)s: %(message)s', level=logging.INFO)
coloredlogs.install(level='INFO')

MISP_URL = 'https://misp.domain.com'
MISP_API_KEY = 'YOUR KEY'
MISP_EVENT_TITLE = 'Twitter indicator feed'
MISP_VALIDATE_SSL = False
MISP_TO_IDS = False
MISP_PUBLISH_EVENTS = False

CONSUMER_KEY = 'YOUR KEY'
CONSUMER_SECRET = 'YOUR SECRET'
ACCESS_TOKEN = 'YOUR TOKEN'
ACCESS_TOKEN_SECRET = 'YOUR SECRET'

HOURS_BACK = 7
MAX_SEARCH_ITEMS = 40
MAX_USER_ITEMS = 20
WAIT_SECONDS = 10
THROTTLE_REQUESTS = True
INCLUDE_DOMAINS = False

USERNAME_LIST = ['abuse_ch','avman1995','bad_packets','Bank_Security','Cryptolaemus1','CNMF_VirusAlert','executemalware','FewAtoms','James_inthe_box','JAMESWT_MHT','Jan0fficial','JRoosen','pollo290987','ps66uk','malwrhunterteam','mesa_matt','Mesiagh','nao_sec','Racco42','reecdeep','shotgunner101','thlnk3r','TrackerEmotet','VK_Intel']
SEARCH_LIST = ['#agenttesla','#azorult','#banload','#brushaloader','#dridex','#emotet','#fin7','#formbook','#gandcrab','#gozi','#hancitor','#hawkeye','#icedid','#lokibot','#malspam','#nanocore','#njrat','#nymaim','#pyrogenic','#ramnit','#remcos','#ryuk','#revil','#smokeloader','#sodinokibi','#trickbot','#troldesh','#ursnif']

URL_BLACKLIST = ['//t.co/', 'abuse.ch', 'app.any.run', 'otx.alienvault.com', 'proofpoint.com', 'twitter.com', 'virustotal.com', 'www.cloudflare.com']
IP_BLACKLIST = ['0.0.0.0', '127.0.0.1', '127.0.1.1', '192.168.1.']

SCRAPER_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.89 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Content-Type': 'application/x-www-form-urlencoded'
}

CF_SCRAPER = create_scraper()

class TwitterIndicator:
  def __init__(self, ref_name, ref_url, o_type, o_value):
    self.ref_name = ref_name
    self.ref_url = ref_url
    self.o_type = o_type
    self.o_value = o_value

def disable_ssl_warnings():
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def is_valid_domain(domain):
    return validators.domain(domain)

def apply_url_fixes(url):
    # Handle unconventional defanging:
    if url.startswith('p://'):
        url = url.replace('p://', 'http://')

    if url.startswith('s://'):
        url = url.replace('s://', 'https://')

    return url

def is_valid_url(url):
    if any(s in url for s in URL_BLACKLIST):
        return False

    if any(s in url for s in IP_BLACKLIST):
        return False

    if url.endswith('\u2026'):
        return False

    # iocextract can incorrectly match on http://123.123:123
    if re.search(r'http://[0-9]{1,3}\.[0-9]{1,3}:[0-9]{1,5}', url):
        return False

    try:
        result = urllib.parse.urlparse(url)
        url_valid = all([result.scheme, result.netloc])
        return url_valid

    except Exception as ex:
        LOGGER.warning('Error validating URL: {0}'.format(str(ex)))

    return False

def is_valid_ip(ip):
    if any(s in ip for s in IP_BLACKLIST):
        return False

    return validators.ipv4(ip)

def get_hash_type(hash):
    repeat_threshold = int(len(hash)/2)

    if [i for i,j in Counter(hash).items() if j>repeat_threshold]:
        LOGGER.warning('High number of repeat characters detected in string. Potential binary or script segment.')
        return False

    if re.search(r'[A-Fa-f0-9]{64}$', hash):
        return 'FileHash-SHA256'

    if re.search(r'[A-Fa-f0-9]{40}$', hash):
        return 'FileHash-SHA1'

    if re.search(r'[A-Fa-f0-9]{32}$', hash):
        return 'FileHash-MD5'

    return False

def make_new_event(misp):
    LOGGER.info('Creating new fixed event...')
    event = MISPEvent()

    timestamp = datetime.utcnow()
    event_date = timestamp.strftime('%Y-%m-%d')
    event.info = MISP_EVENT_TITLE
    event.analysis = Analysis.completed
    event.distribution = Distribution.your_organisation_only
    event.threat_level_id = ThreatLevel.low

    event.add_tag('type:OSINT')
    event.add_tag('tlp:white')

    LOGGER.info('Saving event...')
    time.sleep(1)
    return misp.add_event(event, pythonify=True)

def get_api():
    auth = tweepy.auth.OAuthHandler(CONSUMER_KEY, CONSUMER_SECRET)
    auth.set_access_token(ACCESS_TOKEN, ACCESS_TOKEN_SECRET)

    return tweepy.API(auth, wait_on_rate_limit=THROTTLE_REQUESTS)

def get_pastebin_paste(url):
    try:
        paste_search = re.search(r'https://pastebin.com/([a-zA-Z0-9]{8})', url)
        raw_search = re.search(r'https://pastebin.com/raw/([a-zA-Z0-9]{8})', url)

        if paste_search:
            paste_id = paste_search.group(1)
            raw_url = 'https://pastebin.com/raw/{0}'.format(paste_id)

        elif raw_search:
            paste_id = raw_search.group(1)
            raw_url = url

        else:
            LOGGER.warning('Failed to construct raw PasteBin URL from: {0}'.format(url))
            return None

        LOGGER.info('Requesting PasteBin paste with ID: {0}'.format(paste_id))

        paste_request = requests.get(raw_url)

        if paste_request.status_code == 200:
            return paste_request.content

        else:
            LOGGER.warning('Failed to request PasteBin. Status: {0}'.format(paste_request.status_code))

    except Exception as ex:
        LOGGER.error('Failed to query PasteBin: {0}'.format(ex))

    return None

def get_ghostbin_paste(url):
    try:
        paste_search = re.search(r'https://ghostbin.com/paste/([a-zA-Z0-9]{5})', url)

        if paste_search:
            paste_id = paste_search.group(1)
            raw_url = 'https://ghostbin.com/paste/{0}/raw'.format(paste_id)

            # Delay enforced by CloudFlare.
            LOGGER.info('Requesting GhostBin paste with ID: {0} (this will take a moment)'.format(paste_id))

            paste_request = CF_SCRAPER.get(raw_url, headers=SCRAPER_HEADERS)

            if paste_request.status_code == 200:
                return paste_request.content

            else:
                LOGGER.warning('Failed to request GhostBin. Status: {0}'.format(paste_request.status_code))

        else:
            LOGGER.warning('Failed to construct raw GhostBin URL from: {0}'.format(url))

    except Exception as ex:
        LOGGER.error('Failed to query GhostBin: {0}'.format(ex))

    return None

def extract_paste_indicators(username, tweet_id, url):
    if 'pastebin.com' in url:
        paste_text = get_pastebin_paste(url)

        LOGGER.info('Waiting a moment...')
        time.sleep(1)

        if paste_text != None:
            paste_indicators = extract_text_indicators(username, tweet_id, paste_text.decode('utf-8'))

            if len(paste_indicators) > 0:
                return paste_indicators

    elif 'ghostbin.com' in url:
        paste_text = get_ghostbin_paste(url)

        LOGGER.info('Waiting a moment...')
        time.sleep(1)

        if paste_text != None:
            paste_indicators = extract_text_indicators(username, tweet_id, paste_text.decode('utf-8'))

            if len(paste_indicators) > 0:
                return paste_indicators

    return []

def extract_text_indicators(username, tweet_id, text):
    indicator_list = []

    user_id = '@{0}'.format(username)
    tweet_url = 'https://twitter.com/{0}/status/{1}'.format(username, tweet_id)

    try:
        for ip in iocextract.extract_ipv4s(text, refang=True):
            if is_valid_ip(ip):
                indicator_list.append(TwitterIndicator(user_id, tweet_url, 'IPv4', ip))

        for hash in iocextract.extract_hashes(text):
            hash_type = get_hash_type(hash)

            if hash_type:
                indicator_list.append(TwitterIndicator(user_id, tweet_url, hash_type, hash))

        for url in iocextract.extract_urls(text, refang=True):
            if 'ghostbin.com' in url or 'pastebin.com' in url:
                paste_indicators = extract_paste_indicators(username, url)

                if len(paste_indicators) > 0:
                    indicator_list.extend(paste_indicators)

            url = apply_url_fixes(url)

            if is_valid_url(url):
                indicator_list.append(TwitterIndicator(user_id, tweet_url, 'URL', url))

            elif INCLUDE_DOMAINS:
                if is_valid_domain(url):
                    indicator_list.append(TwitterIndicator(user_id, tweet_url, 'HOST', url))

    except Exception as ex:
        LOGGER.warning('Exception parsing text: {0}'.format(ex))

    return indicator_list

def parse_tweet(tweet):
    indicator_list = []

    valid_since = datetime.utcnow() - timedelta(hours=HOURS_BACK)

    try:
        if (tweet.created_at > valid_since):
            screen_name = tweet.user.screen_name
            tweet_id = tweet.id

            LOGGER.info('Parsing Tweet: {0} (user: {1})'.format(tweet_id, screen_name))
            tweet_indicators = extract_text_indicators(screen_name, tweet_id, tweet.text)

            if len(tweet_indicators) > 0:
                indicator_list.extend(tweet_indicators)

            for url in tweet.entities['urls']:
                expanded_url = url['expanded_url']

                if 'ghostbin.com' in expanded_url or 'pastebin.com' in expanded_url:
                    paste_indicators = extract_paste_indicators(screen_name, tweet_id, expanded_url)

                    if len(paste_indicators) > 0:
                        indicator_list.extend(paste_indicators)

    except Exception as ex:
        LOGGER.error('Failed to query Twitter API: {0}'.format(ex))

    return indicator_list

def process_tweets(api):
    indicator_list = []

    for username in USERNAME_LIST:
        LOGGER.info('Processing Tweets for user: {0}...'.format(username))

        try:
            recent_tweets = tweepy.Cursor(api.user_timeline, id=username).items(MAX_USER_ITEMS)

            for recent_tweet in recent_tweets:
                tweet_indicators = parse_tweet(recent_tweet)

                if len(tweet_indicators) > 0:
                    indicator_list.extend(tweet_indicators)

            if THROTTLE_REQUESTS:
                LOGGER.info('Waiting a moment...')
                time.sleep(WAIT_SECONDS)

        except tweepy.error.TweepError as ex:
            LOGGER.error('Failed to query Twitter: {0}'.format(str(ex)))

            if ex.api_code == 429:
                LOGGER.info('Waiting a moment...')
                time.sleep(WAIT_SECONDS)

            else:
                return []

        except Exception as ex:
            LOGGER.error('Failed to query Twitter: {0}'.format(str(ex)))
            return []

    for search in SEARCH_LIST:
        LOGGER.info('Processing Tweets for search: "{0}"...'.format(search))

        try:
            recent_tweets = tweepy.Cursor(api.search, q=search).items(MAX_SEARCH_ITEMS)

            for recent_tweet in recent_tweets:
                tweet_indicators = parse_tweet(recent_tweet)

                if len(tweet_indicators) > 0:
                    indicator_list.extend(tweet_indicators)

            if THROTTLE_REQUESTS:
                LOGGER.info('Waiting a moment...')
                time.sleep(WAIT_SECONDS)

        except tweepy.error.TweepError as ex:
            LOGGER.error('Failed to query Twitter: {0}'.format(str(ex)))

            if ex.api_code == 429:
                LOGGER.info('Waiting a moment...')
                time.sleep(WAIT_SECONDS)

            else:
                return []

        except Exception as ex:
            LOGGER.error('Failed to query Twitter: {0}'.format(str(ex)))
            return []

    return indicator_list

def process_indicators(misp, indicator_list):
    LOGGER.info('Processing collected indicators...')

    event = False
    event_search = misp.search_index(eventinfo=MISP_EVENT_TITLE)

    if not event_search == []:
        for result in event_search:
            if result['info'] == MISP_EVENT_TITLE:
                event = event_search[0]

    if event:
        LOGGER.warning('Event already exists!')

    else:
        event = make_new_event(misp)

    if not event:
        LOGGER.warning('Failed to make or retrieve event.')
        return

    for indicator in indicator_list:
        LOGGER.info('Found {0} "{1}" in: {2}'.format(indicator.o_type, indicator.o_value, indicator.ref_url))

        indicator_type = indicator.o_type
        indicator_value = indicator.o_value
        indicator_comment = indicator.ref_url

        attribute_exists = False
        attribute_search = misp.search(controller='attributes', value=indicator_value)

        if not attribute_search['Attribute'] == []:
            for attribute_result in attribute_search['Attribute']:
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

        elif indicator_type == 'IPv4':
            attribute_category = 'Network activity'
            attribute_type = 'ip-dst'

        elif indicator_type == 'URL':
            attribute_category = 'Network activity'
            attribute_type = 'url'

        elif indicator_type == 'HOST':
            if attribute_value.count('.') == 1:
                attribute_type = 'domain'

            else:
                attribute_type = 'hostname'

        else:
            LOGGER.warning('Unsupported indicator type: {0}'.format(indicator_type))
            continue

        attribute_json = {'category': attribute_category, 'type': attribute_type, 'value': indicator_value, 'comment': indicator_comment, 'to_ids': MISP_TO_IDS}

        new_attr = misp.add_attribute(event, attribute_json, pythonify=True)

    if MISP_PUBLISH_EVENTS:
        LOGGER.info('Publishing event...')
        misp.publish(event)

def twitter_run(misp):
    LOGGER.info('Setting up Twitter connector...')

    try:
        api = get_api()

    except Exception as ex:
        LOGGER.error('Failed to connect to Twitter: {0}'.format(str(ex)))
        sys.exit(1)

    indicator_list = process_tweets(api)

    LOGGER.info('Tweets harvested.')

    if len(indicator_list) > 0:
        process_indicators(misp, indicator_list)

    else:
        LOGGER.warning('Twitter indicator list is empty.')

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

    twitter_run(misp)
