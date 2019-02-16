import logging
from datetime import timedelta

from core import Feed
from core.errors import ObservableValidationError
from core.observables import Hash


class FeodoTrackerPayloads(Feed):
    default_values = {
        "frequency":
            timedelta(hours=1),
        "name":
            "FeodoTrackerPayloads",
        "source":
            "https://feodotracker.abuse.ch/downloads/malware_hashes.csv",
        "description":
            "Feodo Tracker Payload Feed. This feed shows Feodo payload MD5 hashes which Feodo Tracker has identified in the past 30 days.",
    }

    def update(self):
        for line in self.update_lines():
            self.analyze(line)

    def analyze(self, line):
        if not line or line[0].startswith("#"):
            return

        tokens = line.split(',')
        
        if len(tokens) == 3:
            dateadded = tokens[0]
            md5 = tokens[1]
            variant = tokens[2]

            context = {
                "first_seen": dateadded,
                "subfamily": variant,
                "source": self.name
            }

            if md5:
                try:
                    hash_obs = Hash.get_or_create(value=md5)
                    hash_obs.tag([variant, 'malware', 'crimeware', 'banker'])
                    hash_obs.add_context(context)
                    hash_obs.add_source('feed')

                except ObservableValidationError as e:
                    logging.error(e)
