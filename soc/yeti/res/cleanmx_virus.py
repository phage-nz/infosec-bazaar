import logging
import pytz
import re

from core.config.config import yeti_config
from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import Hash, Url
from datetime import datetime, timedelta
from dateutil import parser


class CleanMXVirusFeed(Feed):
    default_values = {
        "frequency": timedelta(hours=1),
        "name": "CleanMXVirusFeed",
        "source": "http://support.clean-mx.com/clean-mx/rss?scope=viruses",
        "description": "CleanMX virus feed.",
    }

    def update(self):
        user_agent = {'User-agent': yeti_config.get('cleanmx', 'user_agent')}

        for item in self.update_xml(
                'item', ["title", "category", "link", "pubDate", "description"], headers=user_agent):
            self.analyze(item)

    def analyze(self, item):
        if not item:
            return

        item_date = parser.parse(item['pubDate'])
        max_age = yeti_config.get('limits', 'max_age')
        limit_date = pytz.UTC.localize(datetime.now()) - timedelta(days=max_age)

        if item_date < limit_date:
            return

        md5_search = re.search(r'md5:\t([a-fA-F\d]{32})<br />', item['description'])

        if not bool(md5_search):
            return

        context = {}
        tags = ['malware']

        if item['category'] != '':
            context['threat'] = item['category']
            signature = item['category']\
                .replace(' ', '_')\
                .replace('/', '_')\
                .replace(':', '_')\
                .replace('.', '-')\
                .replace('!', '-')

            if signature == 'clean_site':
                return

            tags.append(signature)

        context['date_added'] = item_date
        context['source'] = self.name
        context['reference'] = item['link']

        try:
            sample = Hash.get_or_create(value=md5_search.group(1))
            sample.add_context(context)
            sample.add_source("feed")
            sample.tag(tags)

        except ObservableValidationError as e:
            logging.error(e)
            return

        except Exception as e:
            print(e)

        try:
            url = Url.get_or_create(value=item['title'])
            url.add_context(context)
            url.add_source("feed")
            url.tag(tags)
            sample.active_link_to(url, 'drops', self.name)

        except ObservableValidationError as e:
            logging.error(e)
            return
