import logging
from datetime import timedelta

from core import Feed
from core.errors import ObservableValidationError
from core.observables import Ip


class FeodoTrackerC2(Feed):
    default_values = {
        "frequency":
            timedelta(hours=1),
        "name":
            "FeodoTrackerC2",
        "source":
            "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        "description":
            "Feodo Tracker Feed. This feed shows Feodo C2 servers which Feodo Tracker has identified in the past 30 days.",
    }

    def update(self):
        for line in self.update_lines():
            self.analyze(line)

    def analyze(self, line):
        if not line or line[0].startswith("#"):
            return

        tokens = line.split(',')
        
        if len(tokens) == 4:
            dateadded = tokens[0]
            c2_ip = tokens[1]
            c2_port = tokens[2]
            variant = tokens[3]

            context = {
                "first_seen": dateadded,
                "port": c2_port,
                "subfamily": variant,
                "source": self.name
            }

            if c2_ip:
                try:
                    ip_obs = Ip.get_or_create(value=c2_ip)
                    ip_obs.tag([variant, 'malware', 'crimeware', 'banker', 'c2'])
                    ip_obs.add_context(context)
                    ip_obs.add_source('feed')

                except ObservableValidationError as e:
                    logging.error(e)
