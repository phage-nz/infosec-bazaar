import logging
from datetime import timedelta

from core import Feed
from core.errors import ObservableValidationError
from core.observables import Url


class h3xTracker(Feed):
    default_values = {
        "frequency":
            timedelta(hours=1),
        "name":
            "h3xTracker",
        "source":
            "http://tracker.h3x.eu/api/sites_1hour.php",
        "description":
            "h3x Malware Corpus Tracker is a tracker for Corpus and C&C sites of various malware families.",
    }

    def update(self):
        for line in self.update_csv(delimiter=',',quotechar='"'):
            self.analyze(line)

    def analyze(self, item):
        if not item or item[0].startswith("#"):
            return

        family, threat, url, url_status, first_seen, first_active, last_active, last_update = item

        context = {
            "first_seen": first_seen,
            "first_active": first_active,
            "last_active": last_active,
            "last_update": last_update,
            "status": url_status,
            "source": self.name,
            "threat": threat
        }

        if url:
            try:
                url_obs = Url.get_or_create(value=url)
                url_obs.tag([family, 'malware'])
                url_obs.add_context(context)
                url_obs.add_source('feed')
            except ObservableValidationError as e:
                logging.error(e)
