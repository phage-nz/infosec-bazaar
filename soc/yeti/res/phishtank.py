import dateutil.parser
import logging
import pytz

from core.config.config import yeti_config
from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import Url
from datetime import datetime, timedelta


class PhishTank(Feed):
    default_values = {
        'frequency':
            timedelta(hours=4),
        'name':
            'PhishTank',
        'source':
            'http://data.phishtank.com/data/online-valid.csv',
        'description':
            'PhishTank community feed. Contains a list of possible Phishing URLs.'
    }

    def update(self):
        for line in self.update_csv(delimiter=',', quotechar='"'):
            self.analyze(line)

    def analyze(self, data):
        if not data or data[0].startswith('phish_id'):
            return

        _, url, phish_detail_url, submission_time, verified, verification_time, online, target = data

        item_date = dateutil.parser.parse(submission_time)
        max_age = yeti_config.get('limits', 'max_age')
        limit_date = pytz.UTC.localize(datetime.now()) - timedelta(days=max_age)

        if item_date < limit_date:
            return

        tags = ['phishing']

        context = {
            'source': self.name,
            'phish_detail_url': phish_detail_url,
            'submission_time': submission_time,
            'verified': verified,
            'verification_time': verification_time,
            'online': online,
            'target': target
        }

        if url is not None and url != '':
            try:    
                url = Url.get_or_create(value=url)
                url.add_context(context)
                url.add_source('feed')
                url.tag(tags)

            except ObservableValidationError as e:
                logging.error(e)
