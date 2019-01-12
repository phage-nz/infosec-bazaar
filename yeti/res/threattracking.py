import hammock
import logging
import requests
import simplejson as json

from core.config.config import yeti_config
from core.entities import Actor, Campaign, Malware
from core.feed import Feed
from datetime import timedelta
from mongoengine.errors import DoesNotExist


class ThreatTracking(Feed):
    default_values = {
        "frequency": timedelta(days=30),
        "name": "ThreatTracking",
        "source": "http://apt.threattracking.com",
        "description": "This feed contains APT Actor information.",
    }

    target_sheet = {
        'China': {
            'aliases': 'A3:L79',
            'campaigns': 'M:P',
            'tools': 'Q'
        },
        'Russia': {
            'aliases': 'A3:N18',
            'campaigns': 'O:U',
            'tools': 'V'
        },
        'North Korea': {
            'aliases': 'A3:M12',
            'campaigns': 'N:V',
            'tools': 'W'
        },
        'Iran': {
            'aliases': 'A3:J22',
            'campaigns': 'K:M',
            'tools': 'N'
        },
        'Israel': {
            'aliases': 'A3:E5',
            'campaigns': 'F:G',
            'tools': 'H'
        },
        'Middle East': {
            'aliases': 'A3:D15',
            'campaigns': 'E:G',
            'tools': 'I'
        },
        'NATO': {
            'aliases': 'A3:G5',
            'campaigns': 'H:J',
            'tools': 'K'
        },
        'Others': {
            'aliases': 'A3:F55',
            'campaigns': 'G:I',
            'tools': 'J'
        },
        'Unknown': {
            'aliases': 'A3:I30',
            'campaigns': 'J:L',
            'tools': 'M'
        },
    }
	
    def __init__(self, *args, **kwargs):
        super(ThreatTracking, self).__init__(*args, **kwargs)
        return

    def update(self):
        params = {'key': yeti_config.get('threattracking', 'google_api_key')}
        # , 'includeGridData': 'True'} - we don't want to do that. 200Mo file.

        base = "https://sheets.googleapis.com/v4/spreadsheets/" + yeti_config.get(
            'threattracking', 'sheet_key')

        self.api = hammock.Hammock(base, params=params)

        r = self.api.GET()

        if r.status_code != 200:
            raise requests.ConnectionError(
                'Return code for {query} is {code}'.format(
                    query=r.request.url, code=r.status_code))

        sheets = r.json()['sheets']

        for s_p in sheets:
            s = s_p['properties']
            title = s['title']

            if title in ['README', 'Home', '_Malware', '_Download', '_Schemes',
                         '_Sources']:
                continue

            size = s['gridProperties']
            actors_list_info = self.each_sheet_work(s)
            self.create_entities(title, actors_list_info)

        return

    def each_sheet_work(self, sheet):
        title = sheet['title']
        range_info = self.target_sheet[title]
        names = self.get_aliases(title, range_info)
        campaigns = self.get_campaign(title, range_info)
        tools = self.get_tools(title, range_info)

        return zip(names, campaigns, tools)

    def get_aliases(self, sheet_name, range_info):
        """ returns the list of list of aliases.
        The first name in the list is the primary name"""
        actor_primary_name_range = '!'.join([sheet_name, range_info['aliases']])

        actor_json = self.api.values.GET(actor_primary_name_range).json()

        r_names = []

        if 'values' in actor_json:
            actor_names = actor_json['values']

            for i, actor_aliases in enumerate(actor_names):
                while u'' in actor_aliases:
                    actor_aliases.remove(u'')

                while '?' in actor_aliases:
                    actor_aliases.remove('?')

                while '???' in actor_aliases:
                    actor_aliases.remove('???')

                if len(actor_aliases) == 0:
                    actor_aliases.append(sheet_name + '-ACTOR-%d' % i)

                else:
                    l = []
                    for alias in actor_aliases:
                        if ',' in alias:
                            l.extend(alias.split(','))
                        else:
                            l.append(alias)
                    actor_aliases = l
                # Can't use a set:
                actor_aliases = [n.strip() for n in actor_aliases]
                r_names.append(actor_aliases)

        return r_names

    @staticmethod
    def _get_numeric_range(range_info, start_col, end_col):
        range_info_size = range_info['aliases']
        start, end = range_info_size.split(':')
        row_start, row_end = start[1:], end[1:]

        return ':'.join([start_col + row_start, end_col + row_end])

    def get_campaign(self, sheet_name, range_info):
        """ returns the list of list of campaigns."""
        campaign_range = range_info['campaigns'].split(":")
        campaign_value_range = self._get_numeric_range(
            range_info, campaign_range[0], campaign_range[1])
        campaign_value_range = '!'.join([sheet_name, campaign_value_range])

        campain_json = self.api.values.GET(campaign_value_range).json()

        r_names = []

        if 'values' in campain_json:
           campaign_names = campain_json['values']
        
           for i, campaigns in enumerate(campaign_names):
                while u'' in campaigns:
                    campaigns.remove(u'')

                campaigns = list(set(campaigns))
                r_names.append(campaigns)

        return r_names

    def get_tools(self, sheet_name, range_info):
        """ returns the list of list of tools."""
        tool_col = range_info['tools']
        tool_value_range = self._get_numeric_range(
            range_info, tool_col, tool_col)
        tool_value_range = '!'.join([sheet_name, tool_value_range])

        tool_json = self.api.values.GET(tool_value_range).json()

        r_names = []

        if 'values' in tool_json:
            tools_names = tool_json['values']
        
            for i, tools in enumerate(tools_names):
                if len(tools) > 0:
                    tools = tools[0].split(',')
                    tools = [t.strip() for t in tools]
                    tools = list(set(tools))
                    while u'' in tools:
                        tools.remove(u'')
                r_names.append(tools)

        return r_names

    def create_entities(self, sheet_name, actors_list_info):
        for actor_names, campaigns, tools in actors_list_info:
            primary = actor_names[0]

            _actor = Actor.get_or_create(name=primary)
            _actor.aliases = actor_names[1:]
            _actor.save()

            # Create the campaign:
            for c in campaigns:
                # logging.info(repr(c))
                # BUG Issue #120 - is there a bug where two entities cannot have the same name.
                # Naikon the actor conflicts with Naikon the campaign.
                _campaign = ''

                try:
                    _campaign = Campaign.get_or_create(name=c)

                except DoesNotExist:
                    _campaign = Campaign.get_or_create(name="CAMPAIGN-" + c)

                _actor.action(_campaign, self.name)

            # Create the tools:
            for mal in tools:
                _mal = ''

                try:
                    _mal = Malware.get_or_create(name=mal)

                except DoesNotExist:
                    _mal = Malware.get_or_create(name="MALWARE-" + mal)

                _actor.action(_mal, self.name)
        return


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    logging.getLogger('threattracking').setLevel(level=logging.DEBUG)

    feed = ThreatTracking()
    feed.name = ThreatTracking.default_values['name']
    feed.update()
