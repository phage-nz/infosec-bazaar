## Adversary Emulation

In this folder is a wrapper script for the Atomic Red Team (ART) tests (https://github.com/redcanaryco/atomic-red-team/tree/master/execution-frameworks/contrib/python), to give you an idea how MITRE ATT&CK can be used for emulation of groups.  

Only a few of the tests undo the changes that they make. Either be prepared to unpick the changes or - ideally - take a snapshot of the target before running them.  

Also contained in this folder is "cradle.ps1". Use this to PowerShell script to download live samples (either specific, or random) to test and execute endpoint detection capability.

### Use Cases
Some ideas:
- SIEM+EDR capability demos and benchmarking.  
- Identifying gaps in detection.  
- Analyst training. Fire the scripts at a server and set your analysts on a hunt!  

### Setup
The folder structure you should end up with is:
```
\atomic-tests
\atomic-tests\python-requirements.txt
\atomic-tests\emulate.py
\atomic-tests\atomics\
```

- Clone or download ("Clone or download" > "Download ZIP") the Atomic Red Team project from: https://github.com/redcanaryco/atomic-red-team/  
- Discard all except the atomics folder.  
- Into the same folder, pull emulate.py and python-requirements.txt
- Manually install the pre-req's described in atomic-requirements.txt (not exhaustive, there may be others needed - you'll be informed when generating a config) and use pip to install Python requirements from python-requirements.txt:
```
pip install -r python-requirements.txt
```

### Operation
Once the folder structure is set up you can either develop new profiles by hand or automate the creation of a profile (as per primary name or alias on https://attack.mitre.org/groups/). For example:
```
python emulate.py --mode configure --group APT33
```
This will create the configuration file "APT33.yaml". Config files are laid out as follows:
```
group: NAME
parameters:
  T1000:
    optional_parameter: value
techniques:
- T1000
- T1001
```
T1000 in this case has an optional parameter. Default values are defined when the config is first generated, but you can of course change them. This also means you can build a config by hand, but you must include all optional parameters (even defaults).  

You can then run the tests by passing the config file name:
```
python emulate.py --mode run --config APT33.yaml
```
Or, run any cleanup tasks that are defined for the techniques in your config:
```
python emulate.py --mode cleanup --config APT33.yaml
```
It is recommended to run a cleanup in between runs as some tests can hang if certain artifacts (e.g. registry keys) already exist.
### To-Do
- Provide support for Linux and MacOS tests.  
- Permit disabling of specific tests.  

## Tools
The tooling employed by bad actors isn't solely closed source. There is no shortage of open source or freely available options that can be quickly adopted and fulfil requirements at no cost. The goal of emulation is to match or closely imitate the actions of your adversaries, so being able to use the same or similar tooling to them is more preferable than confining your testing to a suite of controlled, autonomous executions.
- **BeEF:** https://github.com/beefproject/beef/  
- **BloodHound:** https://github.com/BloodHoundAD/BloodHound  
- **Covenant:** https://github.com/cobbr/Covenant  
- **Empire:** https://github.com/BC-SECURITY/Empire ([S0363](https://attack.mitre.org/software/S0363/))  
- **Koadic:** https://github.com/zerosum0x0/koadic ([S0250](https://attack.mitre.org/software/S0250/))  
- **LaZagne:** https://github.com/AlessandroZ/LaZagne ([S0349](https://attack.mitre.org/software/S0349/))  
- **Merlin:** https://github.com/Ne0nd0g/merlin  
- **Metasploit:** https://www.metasploit.com/  
- **Mimikatz:** https://github.com/gentilkiwi/mimikatz ([S0002](https://attack.mitre.org/software/S0002/))  
- **PoshC2:** https://github.com/nettitude/PoshC2 ([S0378](https://attack.mitre.org/software/S0378/))  
- **PsExec:** https://docs.microsoft.com/en-us/sysinternals/downloads/psexec ([S0029](https://attack.mitre.org/software/S0029/))  
- **Pupy:** https://github.com/n1nj4sec/pupy ([S0192](https://attack.mitre.org/software/S0192/))  
- **QuasarRAT:** https://github.com/quasar/QuasarRAT ([S0262](https://attack.mitre.org/software/S0262/))  
- **Responder:** https://github.com/lgandx/Responder ([S0174](https://attack.mitre.org/software/S0174/))  
- **SILENTTRINITY:** https://github.com/byt3bl33d3r/SILENTTRINITY  
- **Sliver:** https://github.com/BishopFox/sliver  
- **SpiderFoot:** https://github.com/smicallef/spiderfoot  
- **Windows Credential Editor:** https://www.ampliasecurity.com/research/windows-credentials-editor/ ([S0005](https://attack.mitre.org/software/S0005/))  

## Server Preparation
Included in this folder is "prepare-server.sh" which can help get you up and running with most of the above tools. Instructions on how to start and use them can be found at the bottom of the script.  The [C2 Matrix](https://www.thec2matrix.com/) may help you to decide what best suits your needs.

Also included is "beacon2empire", which converts Cobalt Strike Malleable C2 profiles to matching Empire listener and Apache mod_rewrite configurations. Refer to the readme in the subfolder for more information.  

## Information Sources
Beyond industry reports and whitepapers, the following publicly available sources will help you in building accurate profiles:
- https://attack.mitre.org/groups/  
- https://docs.google.com/spreadsheets/d/1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU/edit  
- https://malpedia.caad.fkie.fraunhofer.de/  
- https://www.crowdstrike.com/blog/meet-the-adversaries/  
- https://www.fireeye.com/current-threats/apt-groups.html  
- https://www.thaicert.or.th/downloads/files/A_Threat_Actor_Encyclopedia.pdf  
- https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections  
- https://otx.alienvault.com - use search filters such as adversary, country and industry.  