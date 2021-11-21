#!/usr/bin/python3

# cfscrape requires NodeJS for JS challenge bypass:
# apt install nodejs

from cfscrape import create_scraper
from config import *
from datetime import datetime, timedelta
from helpers import disable_ssl_warnings, is_valid_domain, is_valid_url, is_valid_ip, get_tags, apply_url_fixes, get_hash_type
from pymisp import MISPEvent, MISPAttribute, ThreatLevel, Distribution, Analysis
from urllib.parse import urlparse

import coloredlogs
import iocextract
import logging
import pytz
import re
import sys
import requests
import time
import tweepy

LOGGER = logging.getLogger('twittermisp')
logging.basicConfig(filename='misp_feeds.log', format='%(asctime)s %(name)s %(levelname)s: %(message)s', level=logging.INFO)
coloredlogs.install(level='INFO')

PLUGIN_NAME = 'Twitter'
PLUGIN_ENABLED = True
PLUGIN_TIMES = ['06:00', '12:00', '18:00', '00:00']

MISP_EVENT_TITLE = 'Twitter indicator feed'
MISP_TO_IDS = False
MISP_PUBLISH_EVENTS = False

CONSUMER_KEY = 'YOUR TWITTER CONSUMER KEY'
CONSUMER_SECRET = 'YOUR TWITTER CONSUMER SECRET'
ACCESS_TOKEN = 'YOUR TWITTER ACCESS TOKEN'
ACCESS_TOKEN_SECRET = 'YOUR TWITTER TOKEN SECRET'

HOURS_BACK =  7
ATTRIBUTE_PROGRESS = True
MAX_SEARCH_ITEMS = 50
MAX_USER_ITEMS = 25
WAIT_SECONDS = 10
THROTTLE_REQUESTS = True
INCLUDE_DOMAINS = False

USERNAME_LIST = ['abuse_ch','avman1995','bad_packets','Bank_Security','cobaltstrikebot','Cryptolaemus1','dubstard','executemalware','FewAtoms','ffforward','James_inthe_box','JAMESWT_MHT','Jan0fficial','JCyberSec_','JRoosen','pollo290987','ps66uk','malwrhunterteam','mesa_matt','Mesiagh','nao_sec','Racco42','reecdeep','shotgunner101','thlnk3r','VK_Intel']
SEARCH_LIST = ['#dridex','#emotet','#icedid','#qakbot','#qbot','#trickbot']

SCRAPER_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.89 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Content-Type': 'application/x-www-form-urlencoded'
}

CF_SCRAPER = create_scraper()

class TwitterIndicator:
  def __init__(self, ref_name, ref_url, o_type, o_value, o_tags):
    self.ref_name = ref_name
    self.ref_url = ref_url
    self.o_type = o_type
    self.o_value = o_value
    self.o_tags = o_tags

def make_new_event(misp):
    LOGGER.info('Creating new fixed event...')
    event = MISPEvent()
    event_date = datetime.now().strftime('%Y-%m-%d')
    event_title = '{0} {1}'.format(MISP_EVENT_TITLE, event_date)

    event.info = event_title
    event.analysis = Analysis.completed
    event.distribution = Distribution.your_organisation_only
    event.threat_level_id = ThreatLevel.low

    event.add_tag('Twitter')
    event.add_tag('type:OSINT')
    event.add_tag('tlp:white')

    LOGGER.info('Saving event...')
    time.sleep(1)

    try:
        new_event = misp.add_event(event, pythonify=True)
        return new_event

    except Exception as ex:
        LOGGER.error('Failed to make MISP event: {0}'.format(str(ex)))
        return False

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

def get_github_blob(url):
    try:
        url_parts = urlparse(url)

        if url_parts.netloc == 'github.com' and 'blob/' in url:
            raw_url = 'https://raw.githubusercontent.com{0}'.format(url_parts.path).replace('/blob','')

        elif url_parts.netloc == 'gist.github.com':
            raw_url = 'https://gist.githubusercontent.com{0}/raw'.format(url_parts.path)

        elif '/raw' in url:
            raw_url = url

        else:
            LOGGER.warning('Failed to construct raw GitHub URL from: {0}'.format(url))
            return None

        LOGGER.info('Requesting GitHub blob from: {0}'.format(raw_url))

        blob_request = requests.get(raw_url)

        if blob_request.status_code == 200:
            return blob_request.content

        else:
            LOGGER.warning('Failed to request GitHub. Status: {0}'.format(blob_request.status_code))

    except Exception as ex:
        LOGGER.error('Failed to query GitHub: {0}'.format(ex))

    return None

def get_tweet_tags(tweet):
    tweet_tags = []
    tweet_hashtags = tweet.entities['hashtags']

    if tweet_hashtags:
        for hashtag in tweet_hashtags:
            tweet_tags.append(hashtag['text'])

    return tweet_tags

def extract_paste_indicators(username, tweet_id, url, tags):
    paste_text = None

    if 'pastebin.com' in url:
        paste_text = get_pastebin_paste(url)

        LOGGER.info('Waiting a moment...')
        time.sleep(1)

    elif 'ghostbin.com' in url:
        paste_text = get_ghostbin_paste(url)

        LOGGER.info('Waiting a moment...')
        time.sleep(1)

    elif any(x in url for x in ['github.com','githubusercontent.com']):
        paste_text = get_github_blob(url)

        LOGGER.info('Waiting a moment...')
        time.sleep(1)

    if paste_text != None:
        paste_indicators = extract_text_indicators(username, tweet_id, paste_text.decode('utf-8'), tags)

        if len(paste_indicators) > 0:
            return paste_indicators

    return []

def extract_text_indicators(username, tweet_id, text, tags):
    indicator_list = []

    user_id = '@{0}'.format(username)
    tweet_url = 'https://twitter.com/{0}/status/{1}'.format(username, tweet_id)

    try:
        for ip in iocextract.extract_ipv4s(text, refang=True):
            if is_valid_ip(ip):
                indicator_list.append(TwitterIndicator(user_id, tweet_url, 'IPv4', ip, tags))

        for hash in iocextract.extract_hashes(text):
            hash_type = get_hash_type(hash)

            if hash_type:
                indicator_list.append(TwitterIndicator(user_id, tweet_url, hash_type, hash, tags))

        for url in iocextract.extract_urls(text, refang=True):
            url = apply_url_fixes(url)

            if is_valid_url(url):
                indicator_list.append(TwitterIndicator(user_id, tweet_url, 'URL', url, tags))

            elif INCLUDE_DOMAINS:
                if is_valid_domain(url):
                    indicator_list.append(TwitterIndicator(user_id, tweet_url, 'HOST', url, tags))

    except Exception as ex:
        LOGGER.warning('Exception parsing text: {0}'.format(ex))

    return indicator_list

def parse_tweet(tweet):
    indicator_list = []

    valid_since = pytz.UTC.localize(datetime.utcnow() - timedelta(hours=HOURS_BACK))

    try:
        if (tweet.created_at > valid_since):
            screen_name = tweet.user.screen_name
            tweet_id = tweet.id

            LOGGER.info('Parsing Tweet: {0} (user: {1})'.format(tweet_id, screen_name))

            tweet_tags = get_tweet_tags(tweet)
            tweet_indicators = extract_text_indicators(screen_name, tweet_id, tweet.full_text, tweet_tags)

            if len(tweet_indicators) > 0:
                indicator_list.extend(tweet_indicators)

            for url in tweet.entities['urls']:
                expanded_url = url['expanded_url']

                if any(x in expanded_url for x in ['pastebin.com','ghostbin.com','github.com','githubusercontent.com']):
                    paste_indicators = extract_paste_indicators(screen_name, tweet_id, expanded_url, tweet_tags)

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
            recent_tweets =  tweepy.Cursor(api.user_timeline, screen_name=username, tweet_mode='extended').items(MAX_USER_ITEMS)

            for recent_tweet in recent_tweets:
                tweet_indicators = parse_tweet(recent_tweet)

                if len(tweet_indicators) > 0:
                    indicator_list.extend(tweet_indicators)

            if THROTTLE_REQUESTS:
                LOGGER.info('Waiting a moment...')
                time.sleep(WAIT_SECONDS)

        except tweepy.errors.TooManyRequests as ex:
            LOGGER.error('Tweepy error: 429')
            LOGGER.info('Waiting a moment...')
            time.sleep(WAIT_SECONDS)

        except tweepy.errors.NotFound as ex:
            LOGGER.error('Tweepy error: 404')
            return []

        except Exception as ex:
            LOGGER.error('Failed to query Twitter: {0}'.format(str(ex)))
            return []

    for search in SEARCH_LIST:
        LOGGER.info('Processing Tweets for search: "{0}"...'.format(search))

        try:
            recent_items = tweepy.Cursor(api.search_tweets, q=search, result_type='recent', tweet_mode='extended').items(MAX_SEARCH_ITEMS)

            for recent_tweet in recent_tweets:
                tweet_indicators = parse_tweet(recent_tweet)

                if len(tweet_indicators) > 0:
                    indicator_list.extend(tweet_indicators)

            if THROTTLE_REQUESTS:
                LOGGER.info('Waiting a moment...')
                time.sleep(WAIT_SECONDS)

        except tweepy.errors.TooManyRequests as ex:
            LOGGER.error('Tweepy error: 429')
            LOGGER.info('Waiting a moment...')
            time.sleep(WAIT_SECONDS)

        except tweepy.errors.NotFound as ex:
            LOGGER.error('Tweepy error: 404')
            return []

        except Exception as ex:
            LOGGER.error('Failed to query Twitter: {0}'.format(str(ex)))
            return []

    return indicator_list

def process_indicators(misp, indicator_list):
    event = False
    event_date = datetime.now().strftime('%Y-%m-%d')
    event_title = '{0} {1}'.format(MISP_EVENT_TITLE, event_date)

    try:
        event_search = misp.search_index(eventinfo=event_title)

    except Exception as ex:
        LOGGER.error('Failed to search for MISP event: {0}'.format(str(ex)))
        return

    if not event_search == []:
        for result in event_search:
            if result['info'] == event_title:
                event = event_search[0]

    if event:
        LOGGER.warning('Event already exists!')

    else:
        event = make_new_event(misp)

    if not event:
        LOGGER.warning('Failed to make or retrieve event.')
        return

    indicator_count = len(indicator_list)
    LOGGER.info('Processing {0} indicators...'.format(indicator_count))

    for i, indicator in enumerate(indicator_list):
        if ATTRIBUTE_PROGRESS and i % 100 == 0:
            progress_value = int(round(100 * (i / float(indicator_count))))
            LOGGER.info('Event completion: {0}%'.format(progress_value))

        indicator_type = indicator.o_type
        indicator_value = indicator.o_value
        indicator_comment = indicator.ref_url
        indicator_tags = indicator.o_tags

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
            if indicator_value.count('.') == 1:
                attribute_type = 'domain'

            else:
                attribute_type = 'hostname'

        else:
            LOGGER.warning('Unsupported indicator type: {0}'.format(indicator_type))
            continue

        attribute_tags = []

        attribute_json = {'category': attribute_category, 'type': attribute_type, 'value': indicator_value, 'comment': indicator_comment, 'to_ids': MISP_TO_IDS, 'Tag': attribute_tags}

        try:
            new_attr = misp.add_attribute(event, attribute_json, pythonify=True)

            if indicator_tags:
                for tag in indicator_tags:
                    if tag:
                        if tag.lower() in TAG_BLACKLIST:
                            continue

                        galaxy_tags = get_tags(misp, tag, 'contains')

                        if galaxy_tags:
                            for galaxy_tag in galaxy_tags:
                                misp.tag(new_attr, galaxy_tag)

                        else:
                            misp.tag(new_attr, tag)

        except Exception as ex:
            LOGGER.error('Failed to add MISP attribute: {0}'.format(str(ex)))
            continue

    if MISP_PUBLISH_EVENTS:
        LOGGER.info('Publishing event...')

        try:
            misp.publish(event)

        except Exception as ex:
            LOGGER.error('Failed to publish MISP event: {0}'.format(str(ex)))

def plugin_run(misp):
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
