#!/usr/bin/python3
import glob
import json
import re
import os
import yaml

print('[*] Loading threat data...')

with open('data/mitre-attack-pattern.json', 'r') as f:
    techniques = json.load(f)['values']

with open('data/mitre-course-of-action.json', 'r') as f:
    mitigations = json.load(f)['values']

with open('data/threat-actor.json', 'r') as f:
    threat_actors = json.load(f)['values']
    threat_actors = [x for x in threat_actors if 'meta' in x]

with open('data/mitre-malware.json', 'r') as f:
    malwares = json.load(f)['values']

with open('data/mitre-tool.json', 'r') as f:
    tools = json.load(f)['values']

with open('data/mitre-intrusion-set.json', 'r') as f:
    intrusion_sets = json.load(f)['values']

with open('data/malpedia.json', 'r') as f:
    malpedia = json.load(f)['values']

with open('data/cert-actor.json', 'r') as f:
    cert_actors = json.load(f)['values']

with open('data/cert-tool.json', 'r') as f:
    _cert_tools = json.load(f)['values']
    cert_malwares = [x for x in _cert_tools if x['meta']['category'] == 'Malware']
    cert_tools = [x for x in _cert_tools if x['meta']['category'] == 'Tools']

print('[*] Extracting and normalising value data...')
mitre_intrusion_sets = [x['value'].replace(' ','').lower() for x in intrusion_sets]
mitre_malware_names = [x['value'].split(' - ')[0].replace(' ','').lower() for x in malwares]
mitre_tool_names = [x['value'].split(' - ')[0].replace(' ','').lower() for x in tools]
cert_actor_names = [
    x['value'].replace(' ','').lower() for x in cert_actors
    if ',' not in x['value'] and 'related' in x
]
cert_actor_names.extend([
    y.strip().replace(' ','').lower() for z in
    [
        x['value'].split(',') for x in cert_actors
        if ',' in x['value'] and 'related' in x
    ]
    for y in z
])
cert_malware_names = [x['value'].replace(' ','').lower() for x in cert_malwares]
cert_tool_names = [x['value'].replace(' ','').lower() for x in cert_tools]

print('[*] Performing diff...')
cert_actor_diff = [x for x in cert_actor_names if x not in mitre_intrusion_sets]
cert_malware_diff = [x for x in cert_malware_names if x not in mitre_malware_names]
cert_tool_diff = [x for x in cert_tool_names if x not in mitre_tool_names]

print('[*] Merging threat data...')
intrusion_sets.extend([x for x in cert_actors if x['value'].replace(' ','').lower() in cert_actor_diff])
malwares.extend([x for x in cert_malwares if x['value'].replace(' ','').lower() in cert_malware_diff])
tools.extend([x for x in cert_tools if x['value'].replace(' ','').lower() in cert_tool_diff])

print('[*] Loading ART data...')
atomics = []

atomic_files = glob.glob('atomic-red-team/atomics/*/*.yaml', recursive=True)

for atomic in atomic_files:
    with open(atomic, 'r') as f:
        atomics.append(yaml.load(f, Loader=yaml.FullLoader))

atomics = [x for x in atomics if 'attack_technique' in x]

def get_name(value):
    return re.sub(r'\s\-\s\w[\d]{4}(\.[\d]{3})?$', '', value).replace('/','or')

def get_id(value):
    return re.search(r'\w[\d]{4}(\.[\d]{3})?$', value).group(0)

def get_tactic(value):
    return value.split(':')[1].replace('-',' ').title()

def get_technique_link(value):
    technique_id = get_id(value)

    if not '.' in technique_id:
        return '[[{0}]]'.format(
            get_name(value)
        )

    parent_technique = get_id(value).split('.')[0]
    technique = [x for x in techniques if x['value'].endswith(parent_technique)][0]

    return '[[{0}#{1}|{2}]]'.format(
        get_name(technique['value']),
        value,
        get_name(value)
    )

def write_md(md_content, md_file):
    print('[*] Writing: {0}'.format(md_file))

    with open(md_file, 'w') as f:
        f.write(md_content)

def form_technique(technique, technique_id):
    technique_md = '''# {title}
## Description
{description}

## Tactics
{killchain}
'''.format(
    title=technique['value'],
    description=re.sub('</?code>', '`', technique['description']),
    killchain='\n'.join(['* {0}'.format(get_tactic(x)) for x in technique['meta']['kill_chain']])
)

    platforms = technique['meta']['mitre_platforms'] if 'mitre_platforms' in technique['meta'] else []

    if platforms:
        technique_md += '''
## Platforms
{platforms}
'''.format(
    platforms='\n'.join(['* {0}'.format(x) for x in platforms])
)

    data_sources = technique['meta']['mitre_data_sources'] if 'mitre_data_sources' in technique['meta'] else []

    if data_sources:
        technique_md += '''
## Data Sources
{data_sources}
'''.format(
    data_sources='\n'.join(['* {0}'.format(x) for x in data_sources])
)

    mitigations_list = [x for x in mitigations if [y for y in x['related'] if y['dest-uuid'] == technique['uuid']]]

    if mitigations_list:
        technique_md += '''
## Mitigations
{mitigations}
'''.format(
    mitigations='\n'.join(['* [[{0}]]'.format(
        get_name(x['value'])
    ) for x in mitigations_list])
)

    technique_md += '''
## References
{references}
'''.format(
    references='\n'.join(['* {0}'.format(x) for x in technique['meta']['refs']])
)

    emulations = [x for x in atomics if x['attack_technique'] == technique_id]

    if emulations:
        tests = emulations[0]['atomic_tests']

        technique_md += '''
## Emulations'''

        for test in tests:
            technique_md += '''
### {name}
{description}
**Supported Platforms:** {platforms}
'''.format(
    name=test['name'],
    description=test['description'],
    platforms=', '.join([x.title() for x in test['supported_platforms']])
)

            if 'input_arguments' in test:
                technique_md += '''
**Inputs:**
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
{inputs}

'''.format(
    inputs='\n'.join(['| {0} | {1} | {2} | {3}|'.format(
        x,
        test['input_arguments'][x]['description'],
        test['input_arguments'][x]['type'],
        test['input_arguments'][x]['default']
    ) for x in test['input_arguments']])
)

            if 'dependencies' in test:
                if 'dependency_executor_name' in test:
                    dep_exec_name = test['dependency_executor_name']

                else:
                    dep_exec_name = test['executor']['name']

                technique_md += '''
**Dependencies run with:** `{dep_executor}`
{dependencies}
'''.format(
    dep_executor=dep_exec_name,
    dependencies='\n'.join(['''Description: {0}
Check Prereq Commands:
```
{1}
```
Get Prereq Commands:
```
{2}
```
'''.format(
    x['description'],
    x['prereq_command'],
    x['get_prereq_command']) for x in test['dependencies']])
)
            if 'elevation_required' in test['executor']:
                elevation_required = ' (run as admin/root)' if test['executor']['elevation_required'] == True else ''

            else:
                elevation_required = ''

            if 'command' in test['executor']:
                test_exec = test['executor']['command']

            elif 'steps' in test['executor']:
                test_exec = test['executor']['steps']

            else:
                print('Unknown executor type: {0}'.format(test['executor']))
                test_exec = 'Unknown'

            technique_md += '''
Run with `{0}` (elevated: {1}):
```
{2}
```
'''.format(
    test['executor']['name'],
    elevation_required,
    test_exec
)

    return technique_md

def load_techniques():
    print('[*] Loading techniques...')

    for technique in techniques:
        technique_id = get_id(technique['value'])
        technique_name = get_name(technique['value'])

        if '.' in technique_id:
            continue

        if technique['description'].startswith('This object is deprecated'):
            continue

        if 'kill_chain' not in technique['meta']:
            continue

        technique_md = form_technique(technique, technique_id)
        sub_techniques = [x for x in techniques if '{0}.'.format(technique_id) in x['value']]

        if sub_techniques:
            for sub_technique in sub_techniques:
                technique_md += '---\n{0}'.format(form_technique(sub_technique, technique_id))

        write_md(technique_md, 'docs/techniques/{0}.md'.format(technique_name))

def load_actors():
    print('[*] Loading actors...')

    for intrusion_set in intrusion_sets:
        if 'synonyms' not in intrusion_set['meta']:
            print('No synonyms in intrusion set: {0}'.format(intrusion_set['value']))
            continue

        if len(intrusion_set['meta']['synonyms']) == 0:
            print('Empty synonym list in intrusion set: {0}'.format(intrusion_set['value']))
            continue

        actor_name = get_name(intrusion_set['value'])

        if actor_name.startswith(('APT','FIN','TA','UNC')):
            actor_name = actor_name.replace(' ','')

        technique_list = [x for x in techniques
            if [y for y in intrusion_set['related'] if y['dest-uuid'] == x['uuid']]
            and not x['description'].startswith('This object is deprecated')
        ]
        malware_list = [x for x in malwares if [y for y in intrusion_set['related'] if y['dest-uuid'] == x['uuid']]]
        tool_list = [x for x in tools if [y for y in intrusion_set['related'] if y['dest-uuid'] == x['uuid']]]

        actor_profiles = []

        ta_with_synonyms = [x for x in threat_actors if 'synonyms' in x['meta']]
        actor_profiles.extend([x for x in ta_with_synonyms
            if [y for y in intrusion_set['meta']['synonyms'] if y in x['meta']['synonyms']]]
        )
        ta_without_synonyms = [x for x in threat_actors if 'synonyms' not in x['meta']]
        actor_profiles.extend([x for x in ta_without_synonyms
            if [y for y in intrusion_set['meta']['synonyms'] if y == x['value']]]
        )

        references = intrusion_set['meta']['refs']

        if actor_profiles:
            actor_profile = actor_profiles[0]

            if 'refs' in actor_profile['meta']:
                references.extend(actor_profile['meta']['refs'])

                if references:
                    references = list(set(references))

        else:
            actor_profile = None

        intrusion_md = '''# {title}
{description}

## Aliases
{aliases}
'''.format(
    title=intrusion_set['value'],
    description=intrusion_set['description'],
    aliases='\n'.join(['* {0}'.format(x) for x in intrusion_set['meta']['synonyms']])
)
        if actor_profile:
            if 'country' in actor_profile['meta']:
                intrusion_md += '''
## Country
{country}
'''.format(
    country=actor_profile['meta']['country']
)

            if 'cfr-suspected-state-sponsor' in actor_profile['meta']:
                intrusion_md += '''
## State Sponsorship
{actor}
'''.format(
    actor=actor_profile['meta']['cfr-suspected-state-sponsor']
)

            if 'cfr-suspected-victims' in actor_profile['meta']:
                intrusion_md += '''
## Targets
{targets}
'''.format(
    targets='\n'.join(['* {0}'.format(x) for x in actor_profile['meta']['cfr-suspected-victims']])
)

            if 'cfr-target-category' in actor_profile['meta']:
                intrusion_md += '''
## Industries
{industries}
'''.format(
    industries='\n'.join(['* {0}'.format(x) for x in actor_profile['meta']['cfr-target-category']])
)

        if technique_list:
            intrusion_md += '''
## Techniques
{techniques}
'''.format(
    techniques='\n'.join(['* {0}'.format(get_technique_link(x['value'])) for x in technique_list])
)

        if malware_list:
            intrusion_md += '''
## Malware
{malware}
'''.format(
    malware='\n'.join(['* [[{0}]]'.format(
        get_name(x['value'])
    ) for x in malware_list])
)

        if tool_list:
            intrusion_md += '''
## Tools
{tools}
'''.format(
    tools='\n'.join(['* [[{0}]]'.format(
        get_name(x['value'])
    ) for x in tool_list])
)

        intrusion_md += '''
## References
{references}
'''.format(
    references='\n'.join(['* {0}'.format(x) for x in intrusion_set['meta']['refs']])
)

        write_md(intrusion_md, 'docs/actors/{0}.md'.format(actor_name))

def load_software(input_list, category):
    print('[*] Loading {0}...'.format(category))

    for software in input_list:
        software_name = get_name(software['value'])

        if 'related' not in software:
            print('No relations for software: {0}'.format(software['value']))
            software['related'] = []

        if 'synonyms' not in software['meta']:
            print('No synonyms for software: {0}'.format(software['value']))
            software['meta']['synonyms'] = []

        technique_list = [x for x in techniques
            if [y for y in software['related'] if y['dest-uuid'] == x['uuid']]
            and not x['description'].startswith('This object is deprecated')
        ]
        actor_list = [x for x in intrusion_sets if [y for y in x['related'] if y['dest-uuid'] == software['uuid']]]
        malpedia_list = [x for x in malpedia
            if software_name in x['meta']['synonyms']
            or software_name == x['value']
        ]
        references = software['meta']['refs']

        if malpedia_list:
            malpedia_item = malpedia_list[0]
            references.extend(malpedia_item['meta']['refs'])

            if references:
                references = list(set(references))

        software_md = '''# {title}
{description}
'''.format(
    title=software['value'],
    description=software['description']
)

        if len(software['meta']['synonyms']) > 0:
            software_md += '''
## Aliases
{aliases}
'''.format(
    aliases='\n'.join(['* {0}'.format(x) for x in software['meta']['synonyms']])
)

        if 'mitre_platforms' in software['meta']:
            if len(software['meta']['mitre_platforms']) > 0:
                software_md += '''
## Platforms
{platforms}
'''.format(
    platforms='\n'.join(['* {0}'.format(x) for x in software['meta']['mitre_platforms']])
)

        if technique_list:
            software_md += '''
## Techniques
{techniques}
'''.format(
    techniques='\n'.join(['* {0}'.format(get_technique_link(x['value'])) for x in technique_list])
)

        if actor_list:
            software_md += '''
## Used By
{actors}
'''.format(
    actors='\n'.join(['* [[{0}]]'.format(
        get_name(x['value'])
    ) for x in actor_list])
)

        software_md += '''
## References
{references}
'''.format(
    references='\n'.join(['* {0}'.format(x) for x in references])
)

        write_md(software_md, 'docs/{0}/{1}.md'.format(category, software_name))

def load_mitigations():
    for mitigation in mitigations:
        mitigation_name = get_name(mitigation['value'])
        technique_list = [x for x in techniques
            if [y for y in mitigation['related'] if y['dest-uuid'] == x['uuid']]
            and not x['description'].startswith('This object is deprecated')
        ]

        mitigation_md = '''# {title}
{description}
'''.format(
    title=mitigation['value'],
    description=mitigation['description']
)

        if technique_list:
            mitigation_md += '''
## Techniques
{techniques}
'''.format(
    techniques='\n'.join(['* {0}'.format(get_technique_link(x['value'])) for x in technique_list])
)

        mitigation_md += '''
## References
{references}
'''.format(
    references='\n'.join(['* {0}'.format(x) for x in mitigation['meta']['refs']])
)

        write_md(mitigation_md, 'docs/mitigations/{0}.md'.format(mitigation_name))

load_techniques()
load_actors()
load_software(tools, 'tools')
load_software(malwares, 'malware')
load_mitigations()
