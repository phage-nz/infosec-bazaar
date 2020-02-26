#!/usr/bin/python3

# Atomic Test Wrapper for Turla.
# https://attack.mitre.org/groups/G0010/

import coloredlogs
import logging
import os
import platform
import runner
import yaml

START_FRESH = True

ACTOR_NAME = 'Turla'
ACTOR_URL = 'https://attack.mitre.org/groups/G0010/'
ACTOR_CONFIG = {
  "T1004": {"name": "Winlogon Helper DLL", "tests": [0, 1, 2]},
  "T1007": {"name": "System Service Discovery", "tests": [0, 1]},
  "T1012": {"name": "Query Registry", "tests": [0]},
  "T1016": {"name": "System Network Configuration Discovery", "tests": [0, 1, 2, 3]},
  "T1018": {"name": "Remote System Discovery", "tests": [0, 1, 2, 3, 4, 5]},
  "T1022": {"name": "Data Encrypted", "tests": [0, 2]},
  "T1027": {"name": "Obfuscated Files or Information", "tests": [0, 1]},
  "T1048": {"name": "Exfiltration Over Alternative Protocol", "tests": [0], "parameters": {"ip_address": "128.199.156.165"}},
  "T1049": {"name": "System Network Connections Discovery", "tests": [0, 1]},
  "T1055": {"name": "Process Injection", "tests": [0, 1, 2, 3]},
  "T1057": {"name": "Process Discovery", "tests": [0]},
  "T1060": {"name": "Registry Run Keys / Startup Folder", "tests": [0, 1, 2]},
  "T1064": {"name": "Scripting", "tests": [0]},
  "T1071": {"name": "Standard Application Layer Protocol", "tests": [0, 1, 2, 3, 4, 5]},
  "T1077": {"name": "Windows Admin Share", "tests": [0, 1, 2, 3]},
  "T1081": {"name": "Credentials in File", "tests": [0, 1]},
  "T1082": {"name": "System Information Discovery", "tests": [0, 1, 2]},
  "T1083": {"name": "File and Directory Discovery", "tests": [0, 1]},
  "T1084": {"name": "Windows Management Instrumentation Event Subscription", "tests": [0]},
  "T1086": {"name": "PowerShell", "tests": [0, 1, 2, 4, 5, 6, 7, 9, 10, 11, 12, 13]},
  "T1089": {"name": "Disabling Security Tool", "tests": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]},
  "T1090": {"name": "Connection Proxy", "tests": [0]},
  "T1102": {"name": "Web Service", "tests": [0, 1]},
  "T1105": {"name": "Remote File Copy", "tests": [0, 1, 2, 3]},
  "T1110": {"name": "Brute Force", "tests": [0]},
  "T1112": {"name": "Modify Registry", "tests": [0, 1, 2, 3, 4, 5, 6]},
  "T1124": {"name": "System Time Discovery", "tests": [0, 1]},
  "T1134": {"name": "Access Token Manipulation", "tests": [0]},
  "T1140": {"name": "Deobfuscate/Decode Files or Information", "tests": [0, 1]},
  "T1193": {"name": "Spearphishing Attachment", "tests": [0]},
  "T1504": {"name": "PowerShell Profile", "tests": [0]}
  }

LOGGER = logging.getLogger(ACTOR_NAME)
coloredlogs.install(level='INFO', logger=LOGGER)

def run_tests():
    LOGGER.info('Atomic assessment underway for actor: {0} ({1})'.format(ACTOR_NAME, ACTOR_URL))

    if START_FRESH and os.path.exists('techniques_hash.db'):
        LOGGER.info('Removing previous ART hash DB...')
        os.remove('techniques_hash.db')

    techniques = runner.AtomicRunner()

    for tid, tvals in ACTOR_CONFIG.items():
        for test in tvals['tests']:
            LOGGER.info('Running test: {0}:{1} ({2})'.format(tid, test, tvals['name']))

            if 'parameters' in tvals:
                techniques.execute(tid, position=test, parameters=tvals['parameters'])
                
            else:
                techniques.execute(tid, position=test)
                
            LOGGER.info('Test complete. Check for alerts!')

if __name__ == "__main__":
    run_tests()