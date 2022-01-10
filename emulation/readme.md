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

## Emulation Server Preparation
The tooling employed by bad actors isn't solely closed source. There is no shortage of open source or freely available options that can be quickly adopted and fulfil requirements at no cost. The goal of emulation is to match or closely imitate the actions of your adversaries, so being able to use the same or similar tooling to them is more preferable than confining your testing to a suite of controlled, autonomous executions.

Included in this folder is "prepare-server.sh" which can help get you up and running with a variety of tooling. The [C2 Matrix](https://www.thec2matrix.com/) may help you to decide what best suits your needs.

The following notes are also saved as ~/readme.txt after running the script.

### HTTPS Support
You can use certbot to request an SSL certificate:
```
certbot certonly --manual --preferred-challenges=dns --server https://acme-v02.api.letsencrypt.org/directory --agree-tos -d *.yourdomain.here --email name@yourdomain.here
```

### Tool Reference
**BeEF:**
- Start: `cd /opt/BeEF && ./beef`  
- Reference: https://github.com/beefproject/beef  

**Covenant:**
- Start: `cd /opt/Covenant/Covenant && dotnet run`  
- Reference: https://github.com/cobbr/Covenant  

**Empire:**
- Start server: `cd /opt/Empire && ./ps-empire server`
- Start client: `cd /opt/Empire && ./ps-empire client`
- beacon2empire: `cd /opt/Empire/beacon2empire && ./convert.py`  
- References:  
  - https://github.com/BC-SECURITY/Empire  
  - https://github.com/phage-nz/infosec-bazaar/tree/master/emulation/beacon2empire  

**Exploit DB:**
- Search: `cd /opt/exploit-db && ./searchsploit`  
- Reference: https://github.com/offensive-security/exploitdb  

**Invoke-Obfuscation:**
- Start: `cd /opt/Invoke-Obfuscation && pwsh -Command "Import-Module ./Invoke-Obfuscation.psd1 && Invoke-Obfuscation"`  
- Reference: https://github.com/danielbohannon/Invoke-Obfuscation  

**Koadic:**
- Start: `cd /opt/Koadic && ./koadic`  
- Reference: https://github.com/zerosum0x0/koadic  
- Note: Koadic appears to have been archived by the author. Fork here: https://github.com/offsecginger/koadic (unvalidated)  

**Merlin:**
- Start: `cd /opt/Merlin && ./merlinServer`  
- Reference: https://github.com/Ne0nd0g/merlin  

**Metasploit:**
- Start: `msfconsole`  
- Reference: https://github.com/rapid7/metasploit-framework  

**Modlishka:**
- Start: `cd /opt/Modlishka && ./Modlishka -config modlishka.config`  
- Reference: https://github.com/drk1wi/Modlishka  

**Mythic:**
- Start: `cd /opt/Mythic && ./mythic-cli mythic start`  
- Reference: https://github.com/its-a-feature/Mythic  

**Prelude Operator:**
- Start: `cd /opt/Operator && ./prelude-operator.appImage`  
- Reference: https://www.prelude.org/  

**SILENTTRINITY:**
- Start server: `cd /opt/SILENTTRINITY && python3.7 st.py teamserver --port 6666 0.0.0.0 <password>`  
- Start client: `cd /opt/SILENTTRINITY && python3.7 st.py client wss://<username>:<password>@<server IP>:6666`  
- Reference: https://github.com/byt3bl33d3r/SILENTTRINITY  

**Sliver:**
- Start: `cd /opt/Sliver && ./sliver-server`  
- Reference: https://github.com/BishopFox/sliver  

**SpiderFoot:**
- Start server: `cd /opt/SpiderFoot && python3 sf.py -l <server IP>:5001`  
- Start client: `cd /opt/SpiderFoot && python3 sfcli.py -s http://<server IP>:5001`  
- Reference: https://github.com/smicallef/spiderfoot  

**TrevorC2:**
- Start: `cd /opt/TrevorC2 && ./trevorc2_server.py`  
- Reference: https://github.com/trustedsec/trevorc2  

**Others:**
- Tools intended to be used on the target (e.g. Mimikatz, Ncat, WSO) can be found in categorised folders under /var/www/html  

## Information Sources
Beyond industry reports and whitepapers, the following publicly available sources will help you in building and emulating accurate profiles:
- https://attack.mitre.org/groups/  
- https://docs.google.com/spreadsheets/d/1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU/edit  
- https://malpedia.caad.fkie.fraunhofer.de/  
- https://www.crowdstrike.com/blog/meet-the-adversaries/  
- https://www.fireeye.com/current-threats/apt-groups.html  
- https://www.thaicert.or.th/downloads/files/A_Threat_Actor_Encyclopedia.pdf  
- https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections  
- https://otx.alienvault.com - use search filters such as adversary, country and industry.  
- https://ired.team/  
