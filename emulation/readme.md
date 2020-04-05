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
- Drop my patched T1086.yml into the T1086 atomics folder. It fixes a problem with the HTA test command syntax.  
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
T1000 in this case has an optional parameter. Default values are defined when the config is first generated, but you can of course change them. This of course means you can build a config by hand, too - but you must include all optional parameters (even defaults).  

You can then run the tests by passing the config file name:
```
python emulate.py --mode run --config APT33.yaml
```
Or, run any cleanup tasks that are defined for the techniques in your config:
```
python emulate.py --mode cleanup --config APT33.yaml
```
It is recommended to run a cleanup in between runs as some tests can hang if certain artifacts (e.g. registry keys) already exist.
### To-Download
- Provide support for Linux and MacOS tests.  

### Information Sources
Beyond industry reports and whitepapers, the following publicly available sources will help you in building accurate profiles:
- https://attack.mitre.org/groups/  
- https://docs.google.com/spreadsheets/d/1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU/edit  
- https://www.crowdstrike.com/blog/meet-the-adversaries/  
- https://www.fireeye.com/current-threats/apt-groups.html  
- https://www.thaicert.or.th/downloads/files/A_Threat_Actor_Encyclopedia.pdf  
- https://otx.alienvault.com - use search filters such as adversary, country and industry.  