import dateutil.parser
import logging

from core import Feed
from core.config.config import yeti_config
from core.errors import ObservableValidationError
from core.observables import Url
from datetime import datetime, timedelta


class UrlHaus(Feed):
    default_values = {
        "frequency":
            timedelta(hours=1),
        "name":
            "UrlHaus",
        "source":
            "https://urlhaus.abuse.ch/downloads/csv/",
        "description":
            "URLhaus is a project from abuse.ch with the goal of sharing malicious URLs that are being used for malware distribution.",
    }

    def update(self):
        for line in self.update_csv(delimiter=',',quotechar='"'):
            self.analyze(line)

    def analyze(self, item):
        if not item or item[0].startswith("#"):
            return

        id_feed, dateadded, url, url_status, threat, tags, urlhaus_link = item

        item_date = dateutil.parser.parse(dateadded)
        max_age = yeti_config.get('limits', 'max_age')
        limit_date = datetime.now() - timedelta(days=max_age)

        if item_date < limit_date:
            return

        if url:
            try:
                url_obs = Url.get_or_create(value=url)

                if tags != None:
                    tags = tags\
                        .replace(' ', '_')\
                        .replace('/', '_')\
                        .replace(':', '_')\
                        .replace('.', '-')\
                        .replace('!', '-')

                    tags = tags.split(',')
                    url_obs.tag(tags)

                context = {
                    "id_urlhaus": id_feed,
                    "first_seen": dateadded,
                    "status": url_status,
                    "source": self.name,
                    "report": urlhaus_link,
                    "threat": threat
                }

                url_obs.add_context(context)
                url_obs.add_source('feed')

            except ObservableValidationError as e:
                logging.error(e)
