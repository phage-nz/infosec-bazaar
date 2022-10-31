Tool Reference

BeEF:
- Start: docker run -p 3000:3000 -p 6789:6789 -p 61985:61985 -p 61986:61986 -d --name beef beef
- Reference: https://github.com/beefproject/beef  

Empire:
- Start server: cd /opt/Empire && ./ps-empire server
- Start client: cd /opt/Empire && ./ps-empire client
- References:  
  - https://github.com/BC-SECURITY/Empire  

Exploit DB:
- Search: cd /opt/exploit-db && ./searchsploit  
- Reference: https://github.com/offensive-security/exploitdb  

Havoc:
- Start server: cd /opt/Havoc/Teamserver && sudo ./teamserver server --profile ./profiles/havoc.yaotl -v --debug
- Start client: cd /opt/Havoc/Client && ./Havoc
- Reference: https://github.com/HavocFramework/Havoc

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
- Get Password: ./mythic-cli config get MYTHIC_ADMIN_PASSWORD  
- Reference: https://github.com/its-a-feature/Mythic  

Prelude Operator:
- Start: cd /opt/Operator && ./prelude-operator  
- Reference: https://www.prelude.org/  

Sliver:
- Start: cd /opt/Sliver && ./sliver-server  
- Reference: https://github.com/BishopFox/sliver  

SpiderFoot:
- Start: docker run -p 5009:5001 -d --name spiderfoot spiderfoot 
- Reference: https://github.com/smicallef/spiderfoot  

Others:
- Loaders can be found in /opt/Loaders, Payload tools in /opt/Payloads and Obfuscators in /opt/Obfuscators  
- Tools intended to be used on the target (e.g. Mimikatz, Ncat, WSO) can be found in categorised folders under /var/www/html
