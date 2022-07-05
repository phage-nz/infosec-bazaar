Tool Reference

BeEF:
- Start: cd /opt/BeEF && ./beef  
- Reference: https://github.com/beefproject/beef  

Covenant:
- Start: cd /opt/Covenant/Covenant && dotnet run  
- Reference: https://github.com/cobbr/Covenant  

Empire:
- Start server: cd /opt/Empire && ./ps-empire server
- Start client: cd /opt/Empire && ./ps-empire client
- References:  
  - https://github.com/BC-SECURITY/Empire  

Exploit DB:
- Search: cd /opt/exploit-db && ./searchsploit  
- Reference: https://github.com/offensive-security/exploitdb  

Merlin:
- Start: cd /opt/Merlin && ./merlinServer  
- Reference: https://github.com/Ne0nd0g/merlin  

Metasploit:
- Start: msfconsole  
- Reference: https://github.com/rapid7/metasploit-framework  

Modlishka:
- Start: cd /opt/Modlishka && ./Modlishka -config modlishka.config  
- Reference: https://github.com/drk1wi/Modlishka  

Mythic:
- Start: cd /opt/Mythic && ./mythic-cli mythic start  
- Reference: https://github.com/its-a-feature/Mythic  

Prelude Operator:
- Start: cd /opt/Operator && ./prelude-operator  
- Reference: https://www.prelude.org/  

Sliver:
- Start: cd /opt/Sliver && ./sliver-server  
- Reference: https://github.com/BishopFox/sliver  

SpiderFoot:
- Start server: cd /opt/SpiderFoot && python3 sf.py -l <server IP>:5001  
- Start client: cd /opt/SpiderFoot && python3 sfcli.py -s http://<server IP>:5001  
- Reference: https://github.com/smicallef/spiderfoot  

Others:
- Loaders can be found in /opt/Loaders and Obfuscators in /opt/Obfuscators  
- Tools intended to be used on the target (e.g. Mimikatz, Ncat, WSO) can be found in categorised folders under /var/www/html
