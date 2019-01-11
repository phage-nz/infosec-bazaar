from datetime import timedelta
import logging

from core.observables import Ip
from core.feed import Feed
from core.errors import ObservableValidationError


class ETCompromisedList(Feed):
    default_values = {
        'frequency': timedelta(hours=1),
        'name': 'ETCompromisedList',
        'source': 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
        'description': 'Emerging Threats compromised host list.'
    }

    def update(self):
        for line in self.update_lines():
            self.analyze(line)

    def analyze(self, data):
        try:
            host_ip = Ip.get_or_create(value=data.rstrip())
            host_ip.add_context({'source': self.name})
            host_ip.add_source('feed')
            host_ip.tag(['compromised'])
        except ObservableValidationError as e:
            logging.error(e)