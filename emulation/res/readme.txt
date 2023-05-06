Tool Reference

Note: all are example usages. You're encouraged to learn their intent and customise this for your requirements.

BeEF:
- Start: docker run -p 3000:3000 -p 6789:6789 -p 61985:61985 -p 61986:61986 -d --name beef beef
- Reference: https://github.com/beefproject/beef  

Chisel:
- Start server: cd /opt/Chisel && ./chisel_linux_amd64 server -p 8080 --key "private" --auth "user:pass" --reverse --proxy "https://www.google.com"
- Start client: chisel.exe client --auth user:pass https://example.cloudfront.net R:1080:socks
- Reference: https://github.com/jpillora/chisel

Empire:
- Start server: docker run -it -p 1337:1337 -p 5000:5000 --volumes-from data bcsecurity/empire:latest
- Container ID: docker container ls
- Start client: docker exec -it {container-id} ./ps-empire client
- References:  
- https://bc-security.gitbook.io/empire-wiki

Exploit DB:
- Search: cd /opt/exploit-db && ./searchsploit  
- Reference: https://github.com/offensive-security/exploitdb  

Havoc:
- Start server: cd /opt/Havoc && sudo ./havoc server --profile ./profiles/havoc.yaotl -v --debug
- Start client: cd /opt/Havoc && ./havoc client
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

NimPlant:
- Activate virtualenv: cd /opt/NimPlant && source env/bin/activate
- Start: python3 NimPlant.py server  
- Compile Implants: python3 NimPlant.py compile all  
- Reference: https://github.com/chvancooten/NimPlant  

Sliver:
- Start: cd /opt/Sliver && ./sliver-server  
- Reference: https://github.com/BishopFox/sliver  

SpiderFoot:
- Start: docker run -p 5009:5001 -d --name spiderfoot spiderfoot 
- Reference: https://github.com/smicallef/spiderfoot  

Villain:
- Activate virtualenv: cd /opt/Villain && source env/bin/activate  
- Start: python Villain.py  
- Reference: https://github.com/t3l3machus/Villain  

Others:
- Loaders: /opt/Tools/Loaders  
- Obfuscators: /opt/Tools/Obfuscators  
- Payload Generation: /opt/Tools/Payloads  
- Privilege Escalation: /opt/Tools/Privesc  
- Recon: /opt/Tools/Recon  
- Utilities: /opt/Tools/Util  
