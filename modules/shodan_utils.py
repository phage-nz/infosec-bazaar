#!/usr/bin/python3

from .log_utils import get_module_logger
from web.models import Host, Compromise, OpenPort, PortCVE, Setting

import json
import shodan
import time

logger = get_module_logger(__name__)

SHODAN_API_KEY = Setting.objects.get(name='Shodan API Key').value1
SHODAN_API = shodan.Shodan(SHODAN_API_KEY)


def get_shodan_scan_data(host):
    try:
        results = SHODAN_API.host(host.address)
        time.sleep(1)

        if 'data' in results:
            entry_list = []

            for result in results['data']:
                event_port = result['port']

                if not OpenPort.objects.filter(host=host, port=event_port).exists():
                    service_name = None
                    service_banner = None

                    if 'product' in result:
                        service_name = result['product']

                    elif 'devicetype' in result:
                        service_name = result['devicetype']

                    if 'banner' in result:
                        service_banner = result['banner']

                    logger.info('Found open port {0}:{1}!'.format(host.address, event_port))

                    new_entry = OpenPort(host=host, port=event_port, service=service_name, banner=service_banner, organisation=host.organisation)
                    entry_list.append(new_entry)

            if len(entry_list) > 0:
                logger.info('Saving items...')
                OpenPort.objects.bulk_create(entry_list)

            else:
                logger.info('There are no new items to save.')

        else:
            logger.info('No port data available for address.')

        return True

    except shodan.APIError as e:
        logger.error('Shodan Error: {0}'.format(e))

    except Exception as e:
        logger.error('Error: {0}'.format(e))

    return False
