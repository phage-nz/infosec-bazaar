#!/usr/bin/env python
# encoding: utf-8

from cortexutils.analyzer import Analyzer
import requests
from requests.auth import HTTPBasicAuth
import time


class HybridAnalysisAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

        self.url = self.get_param('config.url', None, 'Hybrid Analysis base URL is missing')
        self.apikey = self.get_param('config.key', None, 'Hybrid Analysis apikey is missing')
        self.environmentid = self.get_param('config.environment_id', None, 'Hybrid Analysis environment_id is missing')
        self.timeout = self.get_param('config.timeout', 15, None)
        self.verify = self.get_param('config.verifyssl', True, None)

        if not self.verify:
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


    def summary(self, raw):
        taxonomies = []
        level = 'safe'
        namespace = 'HybridAnalysis'
        predicate = 'ThreatScore'
        value = '0/100'

        result = {
            'service': '{0}_analysis'.format(self.data_type),
            'dataType': self.data_type,
            'verdict': raw.get('verdict', None),
            'vx_family': raw.get('vx_family', None),
            'threat_score': raw.get('threat_score', None)
        }

        if result['verdict'] == 'malicious':
            level = 'malicious'

        elif result['verdict'] == 'suspicious':
            level = 'suspicious'

        else:
            level = 'safe'

        if result.get('threat_score'):
            value = '{}/100'.format(result['threat_score'])

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        return {'taxonomies': taxonomies}


    def run(self):
        Analyzer.run(self)

        try:
            request_headers = {'User-agent': 'Cortex Analyzer', 'api-key': self.apikey}

            url_is_file = False

            # Analyse file:
            if self.data_type == 'file':
                file_submit_url = '{0}/api/v2/submit/file'.format(self.url.strip('/'))
                data = {'environment_id': self.environmentid}

                filepath = self.get_param('file', None, 'File path is missing.')
                f = open(filepath, 'rb')
                files = {'file': f}

                response = requests.post(file_submit_url, data=data, headers=request_headers, files=files, verify=self.verify)
                data = response.json()

                if response.status_code == 201:
                    if 'sha256' in data:
                        sha256 = data['sha256']

                    else:
                        self.error('The server returned an incomplete response.')

                elif response.status_code == 429:
                    self.error('Your API quota has been reached.')

                else:
                    if 'message' in data:
                        self.error('File analysis failed due to a submission related error: {0}'.format(data['message']))

                    else:
                        self.error('File analysis failed due to a submission related error.')

            # Analyse URL:
            elif self.data_type == 'url':
                url_submit_url = '{0}/api/v2/submit/url-for-analysis'.format(self.url.strip('/'))
                data = {'environment_id': self.environmentid, 'url': self.get_data()}

                response = requests.post(url_submit_url, data=data, headers=request_headers, verify=self.verify)
                data = response.json()

                if response.status_code == 201:
                    if 'sha256' in data:
                        sha256 = data['sha256']

                    else:
                        self.error('The server returned an incomplete response.')

                elif response.status_code == 429:
                    self.error('Your API quota has been reached.')

                else:
                    if 'message' in data:
                        if data['message'] == 'download-not-a-url':
                            url_is_file = True

                        else:
                            self.error('URL analysis failed due to a submission related error: {0}'.format(data['message']))

                    else:
                        self.error('URL upload failed due to a submission related error.')

            else:
                self.error('Unknown Hybrid Analysis analyzer error encountered.')

            # Resubmit URLs that return a file:
            if url_is_file:
                url_submit_url = '{0}/api/v2/submit/url-to-file'.format(self.url.strip('/'))
                data = {'environment_id': self.environmentid, 'url': self.get_data()}

                response = requests.post(url_submit_url, data=data, headers=request_headers, verify=self.verify)
                data = response.json()

                if response.status_code == 201:
                    if 'sha256' in data:
                        sha256 = data['sha256']

                    else:
                        self.error('The server returned an incomplete response.')

                elif response.status_code == 429:
                    self.error('Your API quota has been reached.')

                else:
                    if 'message' in data:
                        self.error('File (via URL) analysis failed due to a submission related error: {0}'.format(data['message']))

                    else:
                        self.error('File (via URL) analysis failed due to a submission related error.')

            # Poll service until analysis completes:
            state_url = '{0}/api/v2/report/{1}:{2}/state'.format(self.url.strip('/'), sha256, self.environmentid)

            finished = False
            tries = 0

            while not finished and tries <= self.timeout:
                time.sleep(60)

                response = requests.get(state_url, headers=request_headers, verify=self.verify)
                data = response.json()

                if response.status_code == 200:
                    if 'state' in data:
                        if data['state'] == 'SUCCESS':
                            finished = True

                    tries += 1

                else:
                    if 'message' in data:
                        self.error('Error encountered fetching report state: {0}'.format(data['message']))

                    else:
                        self.error('Error encountered fetching report state.')

            if not finished:
                self.error('Hybrid Analysis analysis timed out')

            # Fetch summary report:
            report = {}
            summary_url = '{0}/api/v2/report/{1}:{2}/summary'.format(self.url.strip('/'), sha256, self.environmentid)

            response = requests.get(summary_url, headers=request_headers, verify=self.verify)
            report = response.json()

            if response.status_code == 200:
                report['report_url'] = '{0}/sample/{1}?environmentId={2}'.format(self.url.strip('/'), sha256, str(self.environmentid))

            else:
                if 'message' in data:
                    self.error('Error encountered fetching report summary: {0}'.format(data['message']))

                else:
                    self.error('Error encountered fetching report summary.')

            if 'sha256' in report:
                sha256 = report['sha256']

            screenshots_url = '{0}/api/v2/report/{1}:{2}/screenshots'.format(self.url.strip('/'), sha256, self.environmentid)

            # Fetch screenshots:
            response = requests.get(screenshots_url, headers=request_headers, verify=self.verify)
            data = response.json()

            if response.status_code == 200:
                if data:
                    report['screenshots'] = data

                else:
                    self.error('The server returned an incomplete response.')

            else:
                if 'message' in data:
                    self.error('Error encountered fetching report screenshots: {0}'.format(data['message']))

                else:
                    self.error('Error encountered fetching report screenshots.')

            # Return report:
            if 'report_url' in report:
                self.report(report)

        except requests.exceptions.RequestException as e:
            self.error(e)

        except Exception as e:
            self.unexpectedError(e)


if __name__ == '__main__':
    HybridAnalysisAnalyzer().run()
