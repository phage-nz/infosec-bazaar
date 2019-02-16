import dateutil.parser
import logging
import re
import validators

from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import Ip, Url, Hostname, Hash, Email
from core.config.config import yeti_config
from datetime import datetime, timedelta
from mongoengine import DictField
from OTXv2 import OTXv2

OBSERVABLE_TYPES = {
    "IPv4": Ip,
    "domain": Hostname,
    "hostname": Hostname,
    "email": Email,
    "URL": Url,
    "FileHash-MD5": Hash,
    "FileHash-SHA256": Hash,
    "FileHash-SHA1": Hash,
}

# Some observable types are not yet supported by Yeti:
# IPv6
# URI
# FileHash-PEHASH
# FileHash-IMPHASH
# CIDR
# FilePath
# Mutex
# CVE


class OtxFeed(Feed):
    last_runs = DictField()

    default_values = {
        "frequency": timedelta(hours=1),
        "name": "OtxFeed",
        "description": "Parses pulses from OTX subscriptions and groups.",
        "source": "OTX"
    }

    def __init__(self, *args, **kwargs):
        super(OtxFeed, self).__init__(*args, **kwargs)
        self.otx = OTXv2(yeti_config.get('otx', 'api_key'))

    def update(self):
        for pulse in self.otx.getsince(
            (datetime.utcnow() - timedelta(hours=1)).isoformat(),
            limit=None):
            pulse_context = {
                'source': "OTX Pulse - {}".format(pulse['name']),
                'date_added': dateutil.parser.parse(pulse['created']),
                'author_name': pulse['author_name'],
                'description': pulse['description'],
                'reference': 'https://otx.alienvault.com/pulse/{0}'.format(pulse['id']),
            }

            if pulse['adversary'] != '':
                pulse_context['threat'] = pulse['adversary']

            for indicator in pulse['indicators']:
                self.analyze(
                    indicator,
                    pulse_context,
                    pulse['tags'])

    def validate_indicator(self, indicator_type, indicator_value):
        if indicator_type == 'IPv4':
            return validators.ipv4(indicator_value)

        elif indicator_type == 'hostname' or indicator_type == 'domain':
            return validators.domain(indicator_value)

        elif indicator_type == 'email':
            return validators.email(indicator_value)

        elif indicator_type == 'URL':
            return validators.url(indicator_value)

        elif indicator_type.startswith('FileHash'):
            return re.match(r'(?=(?:.{32}|.{40}|.{64})$)[a-fA-F\d]', indicator_value)

    def analyze(self, indicator_context, pulse_context, pulse_tags):
        indicator_type = indicator_context['type']
        indicator_value = indicator_context.pop('indicator')

        if not indicator_type in OBSERVABLE_TYPES:
            return

        if not self.validate_indicator(indicator_type, indicator_value):
            return

        try:
            context = pulse_context.copy()
            context['date_dadded'] = dateutil.parser.parse(
                indicator_context.pop('created'))
            context.update(indicator_context)

            observable = OBSERVABLE_TYPES[indicator_type].get_or_create(
                value=indicator_value)
            observable.add_context(context)
            observable.tag(pulse_tags)

        except ObservableValidationError as e:
            logging.error(e)

        except Exception as e:
            logging.error(e)
