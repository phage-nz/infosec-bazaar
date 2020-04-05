#!/usr/bin/python3
# ART ATT&CK Profile Emulator
# By Chris Campbell (@phage_nz)

# Credit to Olivier Lemelin for the original runner.py:
# https://github.com/redcanaryco/atomic-red-team/blob/master/execution-frameworks/contrib/python/runner.py
# Parts of this script have been reused.

from attackcti import attack_client
from collections import ChainMap

import argparse
import coloredlogs
import logging
import os
import platform
import re
import subprocess
import sys
import unidecode
import yaml

INCLUDE_TOOLS = True
COMMAND_TIMEOUT = 20
ATOMICS_DIR_RELATIVE_PATH = os.path.join('atomics')

LOGGER = logging.getLogger('art-emulate')
coloredlogs.install(level='INFO', logger=LOGGER)

class EnterpriseCTI:
  def __init__(self, groups, techniques, relationships):
    self.groups = groups
    self.techniques = techniques
    self.relationships = relationships

def load_atomic(atomic_path, atomic_item):
    atomic_file = os.path.join(atomic_path, '{0}.yaml'.format(atomic_item))

    if not os.path.exists(atomic_file):
        LOGGER.warning('[!] Could not find test file: {0}'.format(atomic_file))
        return False
        
    LOGGER.info('[-] Loading tests from file: {0}'.format(atomic_file))
    
    with open(atomic_file, 'r', encoding='utf-8') as in_file:
        atomic_data = yaml.load(unidecode.unidecode(in_file.read()), Loader=yaml.Loader)
        atomic_data['atomic_tests'] = [t for t in atomic_data['atomic_tests'] if 'windows' in t['supported_platforms']]
        
        if len(atomic_data['atomic_tests']) == 0:
            LOGGER.warning('[!] There are no valid tests for Windows.')
            return False

        return atomic_data
    
def load_atomics(techniques):
    LOGGER.info('[-] Loading atomic test data...')

    current_path = os.path.dirname(os.path.abspath(__file__))
    atomics_path = os.path.join(current_path, 'atomics')
    atomic_items = [a for a in os.listdir(atomics_path) if a in techniques]
    
    atomic_techniques = {}
    
    for atomic_item in atomic_items:
        atomic_path = os.path.join(atomics_path, atomic_item)
        atomic_data = load_atomic(atomic_path, atomic_item)
        
        if atomic_data:
            atomic_techniques[atomic_item] = atomic_data
            atomic_techniques[atomic_item]['atomic_path'] = atomic_path
            
    return atomic_techniques
    
def get_group_refs(cti, group_name):
    LOGGER.info('[-] Getting references for group.')
    groups_with_alias = [g for g in cti.groups if 'aliases' in g]
    groups_without_alias = [g for g in cti.groups if 'aliases' not in g]
    alias = next((g for g in groups_with_alias if group_name in g['aliases']), None)
    group = next((g for g in groups_without_alias if g['name'] == group_name), None)
    group_refs = []

    if alias:
        LOGGER.info('[-] Group found via alias. Returning references...')
        group_refs = [r for r in cti.relationships if r['source_ref'] == alias['id']]
        
    elif group:
        LOGGER.info('[-] Group found. Returning references...')
        group_refs = [r for r in cti.relationships if r['source_ref'] == group['id']]

    if group_refs:
        return [r['target_ref'] for r in group_refs]

    LOGGER.error('[!] Group not found.')

    return None

def get_object_refs(cti, ref):
    LOGGER.info('[-] Getting references for object: {0}'.format(ref))

    item_refs = [r for r in cti.relationships if r['source_ref'] == ref]
    
    if item_refs:
        return [r['target_ref'] for r in item_refs]

    return None

def get_techniques(cti, ref_list):
    techniques = []

    for ref in ref_list:
        technique = next((t for t in cti.techniques if t['id'] == ref), None)

        if technique:
            external_ref = next((r for r in technique['external_references'] if r['source_name'] == 'mitre-attack'), None)

            if external_ref:
                if re.match('T[0-9]{4}', external_ref['external_id']):
                    techniques.append(external_ref['external_id'])
                
    return techniques          

def get_group_techniques(cti, group_name):
    refs = get_group_refs(cti, group_name)

    if refs:
        LOGGER.info('[-] OK! Dumping out reference list...')
        pattern_list = []

        for ref in refs:
            if ref.startswith('attack-pattern'):
                pattern_list.append(ref)
    
            elif INCLUDE_TOOLS:
                object_refs = get_object_refs(cti, ref)

                if object_refs:
                    pattern_list.extend(object_refs)

        if pattern_list:
            LOGGER.info('[-] Assembling technique list...')
            pattern_list = list(set(pattern_list))
            technique_list = get_techniques(cti, pattern_list)
            return technique_list

        else:
            LOGGER.error('[!] Empty pattern list.')

    return []
    
def load_cti():
    LOGGER.info('[-] Initiaing ATT&CK CTI client...')
    client = attack_client()

    LOGGER.info('[-] Loading data...')
    enterprise_groups = client.get_enterprise_groups()
    enterprise_techniques = client.get_enterprise_techniques()
    enterprise_relationships = client.get_enterprise_relationships()
    LOGGER.info('[-] OK!')
    
    return EnterpriseCTI(enterprise_groups, enterprise_techniques, enterprise_relationships)
    
def build_profile(group_name):
    LOGGER.info('[-] Building ATT&CK CTI profile for group.')

    return get_group_techniques(load_cti(), group_name)
    
def construct_configuration(group_name, atomic_techniques):
    config_file = '{0}.yaml'.format(group_name)
    config_data = {'group': group_name}
    parameter_list = {}
    dependency_list = {}
    technique_list = []

    for technique, data in atomic_techniques.items():
        LOGGER.info('---------------------------------------------------------------------------------------')
        LOGGER.info('[-] Technique: {0} ({1})'.format(data['attack_technique'], data['display_name']))
        LOGGER.info('[-] Number of tests: {0}'.format(len(data['atomic_tests'])))

        technique_list.append(technique)
        tests_with_input = [t for t in data['atomic_tests'] if 'input_arguments' in t]
        tests_with_deps = [t for t in data['atomic_tests'] if 'dependencies' in t]
        
        if tests_with_input:
            test_inputs = {}
            inputs = [i['input_arguments'] for i in tests_with_input]
            
            for input in inputs:
                for test_input, input_data in input.items():
                    if not test_input in test_inputs:
                        LOGGER.info('[-] Parameter: {0}: {1} (default: {2})'.format(test_input, input_data['description'], input_data['default']))
                        test_inputs[test_input] = str(input_data['default'])

            parameter_list[technique] = test_inputs
            
        if tests_with_deps:
            test_deps = []
            dependencies = [d['dependencies'] for d in tests_with_deps]

            for dep in dependencies:
                LOGGER.info('[-] Dependency: {0}'.format(dep[0]['description'].rstrip()))
                LOGGER.info('[?] Install with: \r\n{0}'.format(dep[0]['get_prereq_command'].rstrip()))
                test_deps.append(dep[0]['description'].rstrip())

    config_data['techniques'] = technique_list
    
    if parameter_list:
        config_data['parameters'] = parameter_list

    LOGGER.info('[-] Saving to file: {0}'.format(config_file))
    
    with open(config_file, 'w') as out_file:
        yaml.dump(config_data, out_file)
        
    LOGGER.info('[-] OK!')

def check_platform():
    if platform.system().lower() != 'windows':
        LOGGER.warning('[!] Only Windows is supported by this script.')
        sys.exit(1)
        
    LOGGER.info('[-] OS check OK!')

    return True
    
def get_shell_path(launcher):
    if launcher == 'command_prompt':
        return 'C:\\Windows\\System32\\cmd.exe'
        
    elif launcher == 'powershell':
        return 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
        
    LOGGER.warning('[!] Unknown launcher type encountered: {0}'.format(launcher))
    return None
    
def load_yaml_file(config_name):
    LOGGER.info('[-] Loading configuration file...')

    with open(config_name) as in_file:
        return yaml.load(in_file, Loader=yaml.FullLoader)

def run_configuration(yaml_data, mode):
    group_name = yaml_data['group']
    technique_list = yaml_data['techniques']
    parameter_list = yaml_data['parameters']

    LOGGER.info('[-] Running tests for group: {0}'.format(group_name))
    
    for technique, technique_data in load_atomics(technique_list).items():
        working_dir = os.path.join(ATOMICS_DIR_RELATIVE_PATH, technique)

        if mode == 'cleanup':
            cleanup_tasks = [t for t in technique_data['atomic_tests'] if 'cleanup_command' in t['executor']]
            
            if not cleanup_tasks:
                continue

        LOGGER.info('---------------------------------------------------------------------------------------')
        LOGGER.info('[*] Beginning technique: {0} ({1})'.format(technique, technique_data['display_name']))
        
        parameters = {}
        
        if technique in parameter_list:
            parameters = parameter_list[technique]

        if mode == 'run':
            for test in technique_data['atomic_tests']:
                run_atomic(test, parameters, working_dir, mode)
                
        elif mode == 'cleanup':
            for task in cleanup_tasks:
                run_atomic(task, parameters, working_dir, mode)

def run_atomic(test_data, parameters, working_dir, mode):
    LOGGER.info('[-] Test: {0}'.format(test_data['name']))
    LOGGER.info('[-] Description: {0}'.format(test_data['description'].rstrip()))
    
    execution_data = test_data['executor']
    executor = execution_data['name']
    
    if executor == 'manual':
        LOGGER.warning('[!] This is a manual test. Run as follows:')
        LOGGER.info(execution_data['steps'])
        return
    
    shell = get_shell_path(execution_data['name'])
    
    if mode == 'run' and 'command' in execution_data:
        command = execution_data['command']
        
    elif mode == 'cleanup' and 'cleanup_command' in execution_data:
        command = execution_data['cleanup_command']
        
    else:
        LOGGER.warning('[!] No command found in execution data.')
        return

    if parameters:
        command = insert_parameters(command, parameters)

    command = command.replace('$PathToAtomicsFolder', ATOMICS_DIR_RELATIVE_PATH)
    command = command.replace('PathToAtomicsFolder', ATOMICS_DIR_RELATIVE_PATH)
    stage_command(shell, command, working_dir)

def insert_parameters(command, parameters):
    def replacer(matchobj):
        if matchobj.group(1) in parameters:
            val = parameters    [matchobj.group(1)]
        else:
            LOGGER.warning('[!] Warning: no match found while building the replacement string.')
            val = None

        return val

    command = re.sub(r'\$\{(.+?)\}', replacer, command)
    command = re.sub(r'\#\{(.+?)\}', replacer, command)

    return command
        
def stage_command(shell, command, working_dir):
    if 'powershell' in shell:
        LOGGER.info('[-] Executing with {0}: {1}'.format(shell, command))
        stdout, stderr = execute_command([shell, '-Command', command], working_dir)
        print_command_output(stdout, stderr)
        LOGGER.info('[-] Command completed.')

    else:
        for line in command.split('\n'):
            if line:
                LOGGER.info('[-] Executing with {0}: {1}'.format(shell, line))
                stdout, stderr = execute_command([shell, '/k', line], working_dir)
                print_command_output(stdout, stderr)
                LOGGER.info('[-] Command completed.')
                
def execute_command(exec_string, working_dir):
    try:
        process = subprocess.run(exec_string, shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            env=os.environ, cwd=working_dir, timeout=COMMAND_TIMEOUT, universal_newlines=True)

        stdout = process.stdout
        stderr = process.stderr

        return stdout, stderr

    except subprocess.TimeoutExpired as e:
        if e.output:
            LOGGER.info('[?] {0}'.format(e.output))

        if e.stdout:
            LOGGER.info('[?] {0}'.format(e.stdout))

        if e.stderr:
            LOGGER.info('[?] {0}'.format(e.stderr))

        LOGGER.warning('[!] Command timed out.')
        
        return None, None
        
def print_command_output(stdout, stderr):
    def clean_output(input):
        input = re.sub(r'Microsoft\ Windows\ \[version .+\]\r?\nCopyright.*(\r?\n)+[A-Z]\:.+?\>', '', input)
        return re.sub(r'(\r?\n)*[A-Z]\:.+?\>', '', input)

    if stdout:
        LOGGER.info('[-] Output: {}'.format(clean_output(stdout)))

    else:
        LOGGER.info('[-] No output.')

    if stderr:
        LOGGER.error('[!] Errors: {}'.format(clean_output(stderr)))
    
def make_config(group_name):
    LOGGER.info('***************************************************************************************')
    LOGGER.info('[*] Constructing new configuration for group: {0}'.format(group_name))
    LOGGER.info('***************************************************************************************')
    group_techniques = build_profile(group_name)
    LOGGER.info('***************************************************************************************')
    
    if not group_techniques:
        LOGGER.error('Failed to construct test profile.')
        sys.exit(1)

    LOGGER.info('***************************************************************************************')
    atomic_techniques = load_atomics(group_techniques)
    LOGGER.info('***************************************************************************************')
    construct_configuration(group_name, atomic_techniques)
    LOGGER.info('***************************************************************************************')
    LOGGER.info('[!] All finshed!')

def run(config_file, mode):
    LOGGER.info('***************************************************************************************')
    check_platform()
    LOGGER.info('***************************************************************************************')
    yaml_data = load_yaml_file(config_file)
    LOGGER.info('***************************************************************************************')
    run_configuration(yaml_data, mode)
    LOGGER.info('***************************************************************************************')
    LOGGER.info('[!] All finshed!')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', required=True, help='Mode of operation: configure, run or cleanup')
    parser.add_argument('--group', help='Group name or alias as listed on https://attack.mitre.org/groups/')
    parser.add_argument('--config', help='Configuration file name including extension')

    args = parser.parse_args()
    
    if args.mode.lower() == 'configure':
        if args.group:
            make_config(args.group)
            
        else:
            LOGGER.error('[!] Configuration mode requires a group name to be defined.')

    elif args.mode.lower() == 'run' or args.mode.lower() == 'cleanup':
        if args.config:
            if os.path.exists(args.config):
                run(args.config, args.mode.lower())
                
            else:
                LOGGER.error('[!] Config file does not exists.')
                
        else:
            LOGGER.error('[!] Run mode requires a configuration file to be defined.')

    else:
        LOGGER.error('[!] Invalid mode of operation. Choose: configure, run or cleanup')
