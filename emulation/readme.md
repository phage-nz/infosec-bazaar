## Emulation Server Preparation
The tooling employed by bad actors isn't solely closed source. There is no shortage of open source or freely available options that can be quickly adopted and fulfil requirements at no cost. The goal of emulation is to match or closely imitate the actions of your adversaries, so being able to use the same or similar tooling to them is more preferable than confining your testing to a suite of controlled, autonomous executions.

Included in this folder is `prepare-server.sh` which can help get you up and running with a variety of tooling. The [C2 Matrix](https://www.thec2matrix.com/) may help you to decide what best suits your needs.

The following notes are also saved as `~/readme.txt` after running the script.

### Script Paramters
```
-h show help
-n do not install XFCE+XRDP
-v install Vectr
```

### HTTPS Support
You can use certbot to request an SSL certificate:
```
certbot certonly --manual --preferred-challenges=dns --server https://acme-v02.api.letsencrypt.org/directory --agree-tos -d *.yourdomain.here --email name@yourdomain.here
```

### Tool Reference
Tool Reference

**Note:** all are example usages. You're encouraged to learn their intent and customise this for your requirements.

**BeEF:**
- Start: `docker run -p 3000:3000 -p 6789:6789 -p 61985:61985 -p 61986:61986 -d --name beef beef`
- Reference: https://github.com/beefproject/beef  

**Chisel:**
- Start server: `cd /opt/Chisel && ./chisel_linux_amd64 server -p 8080 --key "private" --auth "user:pass" --reverse --proxy "https://www.google.com"`
- Start client: `chisel.exe client --auth user:pass https://example.cloudfront.net R:1080:socks`
- Reference: https://github.com/jpillora/chisel

**Empire:**
- Start server: `docker run -it -p 1337:1337 -p 5000:5000 --volumes-from data bcsecurity/empire:latest`
- Container ID: `docker container ls`
- Start client: `docker exec -it {container-id} ./ps-empire client`
- References:  
- https://bc-security.gitbook.io/empire-wiki

**Exploit DB:**
- Search: `cd /opt/exploit-db && ./searchsploit`  
- Reference: https://github.com/offensive-security/exploitdb  

**Havoc:**
- Start server: `cd /opt/Havoc/Teamserver && sudo ./teamserver server --profile ./profiles/havoc.yaotl -v --debug`
- Start client: `cd /opt/Havoc/Client && ./Havoc`
- Reference: https://github.com/HavocFramework/Havoc

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

**NimPlant:**
- Start: `cd /opt/NimPlant && python3 NimPlant.py server`  
- Compile Implants: `python3 NimPlant.py compile all`  
- Reference: https://github.com/chvancooten/NimPlant  

**Prelude Operator:**
- Start: `cd /opt/Operator && ./prelude-operator`  
- Reference: https://www.prelude.org/  

**Sliver:**
- Start: `cd /opt/Sliver && ./sliver-server`  
- Reference: https://github.com/BishopFox/sliver  

**SpiderFoot:**
- Start: `docker run -p 5009:5001 -d --name spiderfoot spiderfoot` 
- Reference: https://github.com/smicallef/spiderfoot  

**Others:**
- Loaders: `/opt/Tools/Loaders`  
- Obfuscators: `/opt/Tools/Obfuscators`  
- Payload Generation: `/opt/Tools/Payloads`  
- Privilege Escalation: `/opt/Tools/Privesc`  
- Recon: `/opt/Tools/Recon`  
- Utilities: `/opt/Tools/Util`  

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
