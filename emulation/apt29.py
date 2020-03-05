#!/usr/bin/python3

# Atomic Test Wrapper for APT29.
# https://attack.mitre.org/groups/G0010/

import coloredlogs
import logging
import os
import platform
import runner
import yaml

START_FRESH = True

ACTOR_NAME = 'APT29'
ACTOR_URL = 'https://attack.mitre.org/groups/G0016/'
ACTOR_CONFIG = {
  "T1015": {"name": "Accessibility Features", "tests": [0]},
  "T1023": {"name": "Shortcut Modification", "tests": [0, 1]},
  "T1027": {"name": "Obfuscated Files or Information", "tests": [0, 1]},
  "T1035": {"name": "Service Execution", "tests": [0, 1]},
  "T1049": {"name": "System Network Connections Discovery", "tests": [0, 1]},
  "T1053": {"name": "Scheduled Task", "tests": [0, 1, 2, 3]},
  "T1057": {"name": "Process Discovery", "tests": [0]},
  "T1060": {"name": "Registry Run Keys / Startup Folder", "tests": [0, 1, 2]},
  "T1064": {"name": "Scripting", "tests": [0]},
  "T1070": {"name": "Indicator Removal on Host", "tests": [0, 1, 2, 3]},
  "T1071": {"name": "Standard Application Layer Protocol", "tests": [0, 1, 2, 3, 4, 5, 6]},
  "T1077": {"name": "Windows Admin Shares", "tests": [0, 1, 2, 3]},
  "T1083": {"name": "File and Directory Discovery", "tests": [0, 1]},
  "T1084": {"name": "Windows Management Instrumentation Event Subscription", "tests": [0]},
  "T1085": {"name": "Rundll32", "tests": [0, 1, 2, 3, 4, 5]},
  "T1086": {"name": "PowerShell", "tests": [0, 1, 2, 4, 5, 6, 7, 9, 10, 11, 12, 13]},
  "T1088": {"name": "Bypass User Account Control", "tests": [0, 1, 2, 3, 4, 5]},
  "T1090": {"name": "Connection Proxy", "tests": [0]},
  "T1095": {"name": "Standard Non-Application Layer Protocol", "tests": [0, 1, 2]},
  "T1097": {"name": "Pass the Ticket", "tests": [0]},
  "T1102": {"name": "Web Service", "tests": [0, 1]},
  "T1107": {"name": "File Deletion", "tests": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]},
  "T1112": {"name": "Modify Registry", "tests": [0, 1, 2, 3, 4, 5, 6]},
  "T1135": {"name": "Network Share Discovery", "tests": [0, 1, 2]},
  "T1140": {"name": "Deobfuscate/Decode Files or Information", "tests": [0, 1]},
  "T1193": {"name": "Spearphishing Attachment", "tests": [0]},
  "T1204": {"name": "User Execution", "tests": [0, 1, 2]}
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
