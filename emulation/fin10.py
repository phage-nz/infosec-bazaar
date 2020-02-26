#!/usr/bin/python3

# Atomic Test Wrapper for FIN10.
# https://attack.mitre.org/groups/G0051/

import coloredlogs
import logging
import os
import platform
import runner
import yaml

START_FRESH = True

ACTOR_NAME = 'FIN10'
ACTOR_URL = 'https://attack.mitre.org/groups/G0051/'
ACTOR_CONFIG = {
  "T1033": {"name": "System Owner/User Discovery", "tests": [0]},
  "T1053": {"name": "Scheduled Task", "tests": [0, 1, 2, 3]},
  "T1060": {"name": "Registry Run Keys / Startup Folder", "tests": [0, 1, 2]},
  "T1064": {"name": "Scripting", "tests": [0]},
  "T1076": {"name": "Remote Desktop Protocol", "tests": [0, 1]},
  "T1086": {"name": "PowerShell", "tests": [0, 1, 2, 4, 5, 6, 7, 9, 10, 11, 12]},
  "T1105": {"name": "Remote File Copy", "tests": [0, 1, 2, 3]},
  "T1107": {"name": "File Deletion", "tests": [0, 1, 2, 3, 4, 5, 6, 7, 8]} 
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