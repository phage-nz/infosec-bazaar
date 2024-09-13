Tool Reference

Note: all are example usages. You're encouraged to learn their intent and customise this for your requirements.

BeEF:
- Start: docker run -p 3000:3000 -p 6789:6789 -p 61985:61985 -p 61986:61986 -d --name beef beef
- Reference: https://github.com/beefproject/beef  

Caldera:
- Activate virtualenv: cd /opt/caldera && source env/bin/activate
- Build: python server.py --insecure --build
- Start (manual): python server.py --insecure
- Start (service): sudo systemctl start caldera
- Reference: https://github.com/mitre/caldera

Chisel:
- Start server: cd /opt/Chisel && ./chisel_linux_amd64 server -p 8080 --key "private" --auth "user:pass" --reverse --proxy "https://www.google.com"
- Start client (on Windows): chisel.exe client --auth user:pass https://example.cloudfront.net R:1080:socks
- Reference: https://github.com/jpillora/chisel

Evilginx:
- Note: requires DNS glue records to point to the server IP.
- Start: cd /opt/evilginx && sudo ./evilginx2
- Reference: https://github.com/kgretzky/evilginx2

Exploit DB:
- Search: cd /opt/exploit-db && ./searchsploit  
- Reference: https://github.com/offensive-security/exploitdb  

Havoc:
- Activate virtualenv: cd /opt/Havoc && source env/bin/activate
- Start server: sudo ./havoc server --profile ./profiles/havoc.yaotl -v --debug
- Start client (in RDP session): ./havoc client
- Reference: https://github.com/HavocFramework/Havoc

Metasploit:
- Start: sudo msfconsole  
- Reference: https://github.com/rapid7/metasploit-framework  

Mythic:
- Start: cd /opt/Mythic && ./mythic-cli mythic start  
- Get Password: ./mythic-cli config get MYTHIC_ADMIN_PASSWORD  
- Reference: https://github.com/its-a-feature/Mythic  

ROADtools:
- Activate virtualenv: cd /opt/ROADtools && source env/bin/activate
- Example: roadtx interactiveauth --estscookie "value of the ESTSAUTHPERSISTENT cookie"
- Example: roadrecon gather -f .roadtools_auth
- Reference: https://github.com/dirkjanm/ROADtools

Sliver:
- Start: cd /opt/Sliver && ./sliver-server  
- Reference: https://github.com/BishopFox/sliver  

Vectr:
- Start: cd /opt/VECTR && docker compose up -d
- Reference: https://github.com/SecurityRiskAdvisors/VECTR

Villain:
- Activate virtualenv: cd /opt/Villain && source env/bin/activate  
- Start: python Villain.py  
- Reference: https://github.com/t3l3machus/Villain  

Others:
- Python Tools: cd /opt/Tools && source env/bin/activate
- Utilities: cd /opt/Tools/Util && ls