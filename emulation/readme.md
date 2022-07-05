## Emulation Server Preparation
The tooling employed by bad actors isn't solely closed source. There is no shortage of open source or freely available options that can be quickly adopted and fulfil requirements at no cost. The goal of emulation is to match or closely imitate the actions of your adversaries, so being able to use the same or similar tooling to them is more preferable than confining your testing to a suite of controlled, autonomous executions.

Included in this folder is `prepare-server.sh` which can help get you up and running with a variety of tooling. The [C2 Matrix](https://www.thec2matrix.com/) may help you to decide what best suits your needs.

The following notes are also saved as `~/readme.txt` after running the script.

### Script Paramters
```
-h show help
-r install XFCE+XRDP
-v install Vectr
```

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
- References:  
  - https://github.com/BC-SECURITY/Empire  

**Exploit DB:**
- Search: `cd /opt/exploit-db && ./searchsploit`  
- Reference: https://github.com/offensive-security/exploitdb  

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
- Get Password: `./mythic-cli config get MYTHIC_ADMIN_PASSWORD`  
- Reference: https://github.com/its-a-feature/Mythic  

**Prelude Operator:**
- Start: `cd /opt/Operator && ./prelude-operator`  
- Reference: https://www.prelude.org/  

**Sliver:**
- Start: `cd /opt/Sliver && ./sliver-server`  
- Reference: https://github.com/BishopFox/sliver  

**SpiderFoot:**
- Start server: `cd /opt/SpiderFoot && python3 sf.py -l <server IP>:5001`  
- Start client: `cd /opt/SpiderFoot && python3 sfcli.py -s http://<server IP>:5001`  
- Reference: https://github.com/smicallef/spiderfoot  

**Others:**
- Loaders can be found in `/opt/Loaders` and Obfuscators in `/opt/Obfuscators`  
- Tools intended to be used on the target (e.g. Mimikatz, Ncat, WSO) can be found in categorised folders under `/var/www/html`  

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
