#!/bin/bash
echo "---------------------------------------------------"
echo "[*] EMULATION SERVER PREPARATION SCRIPT - 13/6/20"
echo '[*] "Train like you fight..."'
echo "---------------------------------------------------"
echo "[!] Note: this isn't completely unattended."
echo "[-] Some installers require interaction."
echo "---------------------------------------------------"
sleep 5
echo "[*] Updating OS..."
apt update && apt upgrade -y
echo "---------------------------------------------------"
echo "[*] Installing OS pre-requisites..."
apt install -y apache2 autoconf build-essential default-jdk g++ git libssl-dev libssl1.1 libxml2-dev make mingw-w64 mingw-w64-common nmap p7zip-full python-dev python-pip python-setuptools python3-dev python3-pip python3-setuptools python3.7-dev ruby software-properties-common swig unzip zlib1g-dev
gem install bundle
echo "---------------------------------------------------"
echo "[*] Enabling Apache..."
systemctl enable apache2 && systemctl start apache2
echo "---------------------------------------------------"
echo "[*] Installing BeEF"
git clone https://github.com/beefproject/beef /opt/BeEF
cd /opt/BeEF
./install
echo "---------------------------------------------------"
echo "[*] Installing Empire..."
git clone https://github.com/BC-SECURITY/Empire /opt/Empire
cd /opt/Empire
pip3 install -r setup/requirements.txt
./setup/install.sh
echo "---------------------------------------------------"
echo "[*] Installing Koadic"
git clone https://github.com/zerosum0x0/koadic /opt/Koadic
cd /opt/Koadic
pip3 install -r requirements.txt
echo "---------------------------------------------------"
echo "[*] Installing Merlin"
mkdir /opt/Merlin && cd /opt/Merlin
wget https://github.com/Ne0nd0g/merlin/releases/download/v0.8.0/merlinServer-Linux-x64-v0.8.0.BETA.7z
7z x -pmerlin merlinServer-Linux-x64-v0.8.0.BETA.7z && rm merlinServer-Linux-x64-v0.8.0.BETA.7z
echo "---------------------------------------------------"
echo "[*] Installing Metasploit..."
cd /tmp
wget https://raw.githubusercontent.com/rapid7/metasploit-Omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb -O msfinstall
chmod +x msfinstall && ./msfinstall && rm msfinstall
echo "---------------------------------------------------"
echo "[*] Installing PoshC2..."
cd /tmp
wget https://raw.githubusercontent.com/nettitude/PoshC2/master/Install.sh -O poshinstall
chmod +x poshinstall && ./poshinstall && rm poshinstall
echo "---------------------------------------------------"
echo "[*] Installing SILENTTRINITY"
git clone https://github.com/byt3bl33d3r/SILENTTRINITY /opt/SILENTTRINITY
cd /opt/SILENTTRINITY
python3.7 -m pip install -r requirements.txt
echo "---------------------------------------------------"
echo "[*] Installing Sliver..."
mkdir /opt/Sliver && cd /opt/Sliver
wget https://github.com/BishopFox/sliver/releases/download/v1.0.3-beta/sliver-server_linux.zip
unzip sliver-server_linux.zip && rm sliver-server_linux.zip
echo "---------------------------------------------------"
echo "[*] Setting up Exploit DB"
git clone https://github.com/offensive-security/exploit-database /opt/exploit-db
echo "---------------------------------------------------"
echo "[*] Setting up theHarvester"	
git clone https://github.com/laramies/theHarvester /opt/theHarvester
cd /opt/theHarvester
python3.7 -m pip install -r requirements/base.txt
echo "---------------------------------------------------"
echo "[*] Fetching credential access tools..."
cd /var/www/html
mkdir credentials
wget https://github.com/maaaaz/thc-hydra-windows/archive/master.zip -O credentials/hydra.zip
wget https://github.com/danielmiessler/SecLists/raw/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz -O credentials/rockyou.txt.tar.gz
wget https://github.com/danielmiessler/SecLists/raw/master/Passwords/Common-Credentials/10k-most-common.txt -O 10k-most-common.txt
wget https://github.com/lgandx/Responder/archive/master.zip -O credentials/Responder.zip
wget https://github.com/lgandx/Responder-Windows/archive/master.zip -O credentials/Responder-Windows.zip
wget https://www.ampliasecurity.com/research/wce_v1_42beta_x32.zip -O credentials/wce_x32.zip
wget https://www.ampliasecurity.com/research/wce_v1_42beta_x64.zip -O credentials/wce_x64.zip
echo "---------------------------------------------------"
echo "[*] Fetching privilege escalation tools..."
mkdir privesc
wget https://github.com/AlessandroZ/BeRoot/archive/master.zip -O privesc/BeRoot.zip
wget https://raw.githubusercontent.com/411Hall/JAWS/master/jaws-enum.ps1 -O privesc/jaws.ps1
wget https://github.com/AlessandroZ/LaZagne/releases/download/2.4.3/lazagne.exe -O privesc/lazagne.exe
wget https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20200519/mimikatz_trunk.zip -O privesc/mimikatz.zip
wget https://raw.githubusercontent.com/M4ximuss/Powerless/master/Powerless.bat -O privesc/Powerless.bat
wget https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Ingestors/SharpHound.ps1 -O privesc/SharpHound.ps1
wget https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/winPEAS/winPEASbat/winPEAS.bat -O privesc/winPEAS.bat
wget https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/raw/master/winPEAS/winPEASexe/winPEAS/bin/Obfuscated%20Releases/winPEASx64.exe -O privesc/winPEASx64.exe
wget https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/raw/master/winPEAS/winPEASexe/winPEAS/bin/Obfuscated%20Releases/winPEASx86.exe -O privesc/winPEASx86.exe
wget https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/raw/master/winPEAS/winPEASexe/winPEAS/bin/Obfuscated%20Releases/winPEASany.exe -O privesc/winPEASany.exe
echo "---------------------------------------------------"
echo "[*] Fetching reconnaissance tools..."
mkdir recon
wget https://github.com/angryip/ipscan/releases/download/3.7.2/ipscan-win64-3.7.2.exe -O recon/ipscan-win64-3.7.2.exe
wget https://nmap.org/dist/nmap-7.80-setup.exe -O recon/nmap-7.80-setup.exe
echo "---------------------------------------------------"
echo "[*] Fetching other utilities..."
mkdir util
wget https://www.7-zip.org/a/7z1900-x64.exe -O util/7z1900-x64.exe
wget https://notepad-plus-plus.org/repository/7.x/7.0/npp.7.bin.x64.zip -O npp.7.bin.x64.zip
wget https://download.java.net/java/GA/jdk14.0.1/664493ef4a6946b186ff29eb326336a2/7/GPL/openjdk-14.0.1_windows-x64_bin.zip -O util/openjdk-14.0.1_windows-x64_bin.zip
wget https://the.earth.li/~sgtatham/putty/latest/w32/putty.zip -O util/putty_w32.zip
wget https://the.earth.li/~sgtatham/putty/latest/w64/putty.zip -O util/putty_w64.zip
wget https://www.python.org/ftp/python/3.8.3/python-3.8.3.exe -O util/python-3.8.3.exe
wget https://download.sysinternals.com/files/SysinternalsSuite.zip -O SysinternalsSuite.zip
unzip SysinternalsSuite.zip -d util && rm SysinternalsSuite.zip && rm util/*.txt
wget https://winscp.net/download/WinSCP-5.17.6-Portable.zip -O util/WinSCP-5.17.6-Portable.zip
echo "---------------------------------------------------"
echo "[*] All finished!"
echo "---------------------------------------------------"
echo "[!] WEB SERVER NOTES:"
echo "[-] Tools are in categorised folders under the web root (/var/www/html)"
echo "[-] They can be pulled over HTTP onto targets"
echo "---------------------------------------------------"
echo "[!] FRAMEWORK NOTES:"
echo "[*] BeEF:"
echo "[-] Start: cd /opt/BeEF && ./beef"
echo "[-] Reference: https://github.com/beefproject/beef"
echo "[*] Empire:"
echo "[-] Start: cd /opt/Empire && ./empire"
echo "[-] Reference: https://github.com/BC-SECURITY/Empire"
echo "[*] Koadic:"
echo "[-] Start: cd /opt/Koadic && ./koadic"
echo "[-] Reference: https://github.com/zerosum0x0/koadic"
echo "[*] Merlin:"
echo "[-] Start: cd /opt/Merlin && ./merlinServer-Linux-x64"
echo "[-] Reference: https://github.com/Ne0nd0g/merlin"
echo "[*] Metasploit:"
echo "[-] Start: msfconsole"
echo "[-] Reference: https://github.com/rapid7/metasploit-framework"
echo "[*] PoshC2"
echo "[-] Edit config: posh-config"
echo "[-] Start server: posh-server"
echo "[-] Start client: posh"
echo "[-] Reference: https://github.com/nettitude/PoshC2"
echo "[*] SILENTTRINITY"
echo "[-] Start server: cd /opt/SILENTTRINITY && python3.7 st.py teamserver --port 6666 0.0.0.0 <passsword>"
echo "[-] Start client: cd /opt/SILENTTRINITY && python3.7 st.py client wss://<username>:<password>@<server IP>:6666"
echo "[-] Reference: https://github.com/byt3bl33d3r/SILENTTRINITY"
echo "[*] Sliver:"
echo "[-] Start: cd /opt/Sliver && ./sliver-server"
echo "[-] Reference: https://github.com/BishopFox/sliver"
echo "---------------------------------------------------"
echo "[!] USEFUL UTILITIES:"
echo "[*] Exploit DB:"
echo "[-] Search: cd /opt/exploit-db && ./searchsploit"
echo "[-] Reference: https://github.com/offensive-security/exploitdb"
echo "[*] theHarvester:"
echo "[-] Start: cd /opt/theHarvester && python3.7 theHarvester.py"
echo "[-] Reference: https://github.com/laramies/theHarvester"
echo "---------------------------------------------------"