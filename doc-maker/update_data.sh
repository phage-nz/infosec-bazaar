#!/bin/bash
wget https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/mitre-attack-pattern.json -O data/mitre-attack-pattern.json
wget https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/mitre-course-of-action.json -O data/mitre-course-of-action.json
wget https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json -O data/threat-actor.json
wget https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/mitre-malware.json -O data/mitre-malware.json
wget https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/mitre-tool.json -O data/mitre-tool.json
wget https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/mitre-intrusion-set.json -O data/mitre-intrusion-set.json
wget https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/malpedia.json -O data/malpedia.json

if [ -d atomic-red-team ]; then rm -rf atomic-red-team; fi

git clone https://github.com/redcanaryco/atomic-red-team

if [ -d docs/sources ]; then rm -rf docs/sources; fi

git clone https://github.com/fastfire/deepdarkCTI docs/sources
rm -rf docs/sources/.git && rm docs/sources/README.md && rm docs/sources/LICENSE
mv docs/sources/cve_most_exploited docs/sources/cve_most_exploited.md