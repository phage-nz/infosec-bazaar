#!/usr/bin/python3

# Atomic Test Wrapper for APT33/Refined Kitten.
# https://attack.mitre.org/groups/G0064/

import coloredlogs
import logging
import os
import platform
import runner
import yaml

START_FRESH = True

ACTOR_NAME = 'APT33'
ACTOR_URL = 'https://attack.mitre.org/groups/G0064/'
ACTOR_CONFIG = {
  "T1002": {"name": "Data Compressed", "tests": [0, 1]},
  "T1003": {"name": "Credential Dumping", "tests": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]},
  "T1027": {"name": "Obfuscated Files or Information", "tests": [0, 1]},
  "T1032": {"name": "Standard Cryptographic Protocol", "tests": [0]},
  "T1040": {"name": "Network Sniffing", "tests": [0, 1]},
  "T1048": {"name": "Exfiltration Over Alternative Protocol", "tests": [0], "parameters": {"ip_address": "127.0.0.1"}},
  "T1053": {"name": "Scheduled Task", "tests": [0, 1, 2, 3]},
  "T1060": {"name": "Registry Run Keys / Startup Folder", "tests": [0, 1, 2]},
  "T1065": {"name": "Uncommonly Used Port", "tests": [0]},
  "T1071": {"name": "Standard Application Layer Protocol", "tests": [0, 1, 3, 4, 5]},
  "T1086": {"name": "PowerShell", "tests": [0, 1, 2, 4, 5, 6, 7, 9, 10, 11, 12, 13]},
  "T1105": {"name": "Remote File Copy", "tests": [0, 1, 2, 3]}
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