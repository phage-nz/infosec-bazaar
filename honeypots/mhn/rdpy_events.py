from normalizer.modules.basenormalizer import BaseNormalizer

import logging
logger = logging.getLogger(__name__)


class RdpyEvents(BaseNormalizer):
    channels = ('rdpy.events',)

    def normalize(self, data, channel, submission_timestamp, ignore_rfc1918=True):
        if ignore_rfc1918 and self.is_RFC1918_addr(data['src_ip']):
            return []

        session = {
            'timestamp': submission_timestamp,
            'source_ip': data['src_ip'],
            'source_port': data['src_port'],
            'destination_ip': data['dst_ip'],
            'destination_port': data['dst_port'],
            'honeypot': 'rdpy',
            'protocol': 'RDP',
            }

        relations = [{'session': session},]

        return relations

