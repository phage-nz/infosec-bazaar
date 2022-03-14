#!/bin/bash
echo "---------------------------------------------------"
echo "[*] EMULATION SERVER PREPARATION SCRIPT - 15/03/22"
echo '[*] "Train like you fight..."'
echo '[*] https://github.com/phage-nz/infosec-bazaar/tree/master/emulation'
echo "---------------------------------------------------"
SHOW_HELP="FALSE"
INSTALL_RDP="FALSE"
while getopts hru OPT
do
    case "${OPT}" in
        h) SHOW_HELP="TRUE";;
        r) INSTALL_RDP="TRUE";;
        u) UPGRADE_OS="TRUE";;
    esac
done
if [[ $SHOW_HELP = "TRUE" ]]; then
    echo "-h show this message."
    echo "-r install Lubuntu desktop and enable xRDP."
    echo "-u upgrade OS packages."
    exit 0
fi
echo "[*] Updating OS..."
apt update
if [[ $UPGRADE_OS = "TRUE" ]]; then
    apt upgrade -y
fi
echo "---------------------------------------------------"
echo "[*] Installing OS pre-requisites..."
add-apt-repository -y "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
wget https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb -O /tmp/packages-microsoft-prod.deb
dpkg -i /tmp/packages-microsoft-prod.deb
apt-get update
apt install -y apache2 autoconf build-essential certbot default-jdk docker-ce dotnet-sdk-3.1 g++ git golang-go libffi-dev libssl-dev libssl1.1 libxml2-dev make mingw-w64 mingw-w64-common net-tools nmap osslsigncode p7zip-full python3-certbot-apache python3-dev python3-pip python3-setuptools python3-testresources ruby ruby-dev software-properties-common swig unzip zlib1g-dev
curl -L "https://github.com/docker/compose/releases/download/1.24.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose
gem install bundle
if [[ $INSTALL_RDP = "TRUE" ]]; then
    echo "[-] Including remote desktop packages..."
    apt install -y lubuntu-core xrdp
    systemctl enable xrdp && systemctl start xrdp
else
    echo "[!] Skipping remote desktop setup..."
fi
echo "---------------------------------------------------"
echo "[*] Preparing Apache..."
a2enmod rewrite proxy proxy_http
systemctl restart apache2
echo "---------------------------------------------------"
echo "[*] Installing BeEF"
git clone https://github.com/beefproject/beef /opt/BeEF
cd /opt/BeEF
echo "[-] Fixing BeEF install script..."
sed -i '/get_permission$/s/^/#/g' install
sed -i 's/apt-get install/apt install -y/g' install
./install
echo "---------------------------------------------------"
echo "[*] Installing Covenant"
git clone --recurse-submodules https://github.com/cobbr/Covenant /opt/Covenant
cd /opt/Covenant/Covenant
dotnet build
echo "---------------------------------------------------"
echo "[*] Installing Empire..."
echo "[!] Note: the install script will require your input at several points."
git clone https://github.com/BC-SECURITY/Empire /opt/Empire
cd /opt/Empire
export STAGING_KEY=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
./setup/install.sh
mkdir beacon2empire && cd beacon2empire
pip3 install coloredlogs
wget https://raw.githubusercontent.com/phage-nz/infosec-bazaar/master/emulation/beacon2empire/convert.py
git clone https://github.com/rsmudge/Malleable-C2-Profiles profiles
echo "---------------------------------------------------"
echo "[*] Setting up Exploit DB"
git clone https://github.com/offensive-security/exploit-database /opt/exploit-db
echo "---------------------------------------------------"
echo "[*] Setting up Obfuscators"
mkdir /opt/Obfuscators
git clone https://github.com/danielbohannon/Invoke-Obfuscation /opt/Obfuscators/Invoke-Obfuscation
git clone https://github.com/CBHue/PyFuscation /opt/Obfuscators/PyFuscation
echo "---------------------------------------------------"
echo "[*] Installing Merlin"
mkdir /opt/Merlin && cd /opt/Merlin
wget https://github.com/Ne0nd0g/merlin/releases/download/v1.3.0/merlinServer-Linux-x64.7z
wget https://github.com/Ne0nd0g/merlin/releases/download/v1.3.0/merlinAgent-Linux-x64.7z
wget https://github.com/Ne0nd0g/merlin/releases/download/v1.3.0/merlinAgent-Windows-x64.7z
7z x -pmerlin merlinServer-Linux-x64.7z && rm merlinServer-Linux-x64.7z
mv merlinServer-Linux-x64 merlinServer
echo "---------------------------------------------------"
echo "[*] Installing Metasploit..."
cd /tmp
wget https://raw.githubusercontent.com/rapid7/metasploit-Omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb -O msfinstall
chmod +x msfinstall && ./msfinstall && rm msfinstall
echo "---------------------------------------------------"
echo "[*] Installing Modlishka..."
mkdir /opt/Modlishka && cd /opt/Modlishka
wget https://github.com/drk1wi/Modlishka/releases/download/v.1.1.0/Modlishka-linux-amd64 -O Modlishka
chmod +x Modlishka
cat > modlishka.config << EOF
{
  "proxyDomain": "yourdomain.here",
  "listeningAddress": "0.0.0.0",
  "target": "targetdomain.here",
  "targetResources": "",
  "targetRules": "PC9oZWFkPg==:",
  "terminateTriggers": "",
  "terminateRedirectUrl": "",
  "trackingCookie": "id",
  "trackingParam": "id",
  "jsRules":"",
  "forceHTTPS": false,
  "forceHTTP": false,
  "dynamicMode": false,
  "debug": true,
  "logPostOnly": false,
  "disableSecurity": false,
  "log": "requests.log",
  "plugins": "all",
  "cert": "",
  "certKey": "",
  "certPool": ""
}
EOF
echo "---------------------------------------------------"
echo "[*] Installing Mythic"
git clone https://github.com/its-a-feature/Mythic /opt/Mythic
./mythic-cli install github https://github.com/MythicAgents/Apollo
./mythic-cli install github https://github.com/MythicAgents/Medusa
./mythic-cli install github https://github.com/MythicC2Profiles/dns
./mythic-cli install github https://github.com/MythicC2Profiles/dynamichttp
./mythic-cli install github https://github.com/MythicC2Profiles/http
./mythic-cli install github https://github.com/MythicC2Profiles/websocket
echo "---------------------------------------------------"
echo "[*] Installing Prelude Operator"
mkdir /opt/Operator && cd /opt/Operator
wget "https://download.prelude.org/latest?arch=x64&platform=linux&variant=appImage" -O prelude-operator.appImage
echo "---------------------------------------------------"
echo "[*] Installing ScareCrow"
mkdir /opt/ScareCrow && cd /opt/ScareCrow
wget https://github.com/optiv/ScareCrow/releases/download/v3.01/ScareCrow_3.01_linux_amd64 -O ScareCrow
echo "---------------------------------------------------"
echo "[*] Installing shad0w"
git clone --recurse-submodules https://github.com/bats3c/shad0w /opt/shad0w
cd /opt/shad0w
./shad0w install
echo "---------------------------------------------------"
echo "[*] Installing SILENTTRINITY"
git clone https://github.com/byt3bl33d3r/SILENTTRINITY /opt/SILENTTRINITY
cd /opt/SILENTTRINITY
pip3 install -r requirements.txt
echo "---------------------------------------------------"
echo "[*] Installing Sliver..."
mkdir /opt/Sliver && cd /opt/Sliver
wget https://github.com/BishopFox/sliver/releases/download/v1.5.8/sliver-server_linux.zip
unzip sliver-server_linux.zip && rm sliver-server_linux.zip
chmod +x sliver-server
echo "---------------------------------------------------"
echo "[*] Installing SpiderFoot"
git clone https://github.com/smicallef/spiderfoot /opt/SpiderFoot
cd /opt/SpiderFoot
pip3 install -r requirements.txt
echo "---------------------------------------------------"
echo "[*] Installing TrevorC2"
git clone https://github.com/trustedsec/trevorc2/ /opt/TrevorC2
cd /opt/TrevorC2
pip3 install -r requirements.txt
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
echo "[*] Fetching delivery objects..."
mkdir delivery
git clone https://github.com/mdsecactivebreach/CACTUSTORCH delivery/CACTUSTORCH
echo "---------------------------------------------------"
echo "[*] Fetching privilege escalation tools..."
mkdir privesc
wget https://github.com/AlessandroZ/BeRoot/archive/master.zip -O privesc/BeRoot.zip
wget https://github.com/l0ss/Grouper2/releases/download/0.9.64/Grouper2.exe -O privesc/Grouper2.exe
wget https://raw.githubusercontent.com/411Hall/JAWS/master/jaws-enum.ps1 -O privesc/jaws.ps1
wget https://github.com/AlessandroZ/LaZagne/releases/download/2.4.3/lazagne.exe -O privesc/lazagne.exe
wget https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20210810-2/mimikatz_trunk.zip -O privesc/mimikatz.zip
wget https://raw.githubusercontent.com/M4ximuss/Powerless/master/Powerless.bat -O privesc/Powerless.bat
wget https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Ingestors/SharpHound.ps1 -O privesc/SharpHound.ps1
wget https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/winPEAS/winPEASbat/winPEAS.bat -O privesc/winPEAS.bat
wget https://github.com/carlospolop/PEASS-ng/raw/master/winPEAS/winPEASexe/binaries/Obfuscated%20Releases/winPEASx64.exe -O privesc/winPEASx64.exe
wget https://github.com/carlospolop/PEASS-ng/raw/master/winPEAS/winPEASexe/binaries/Obfuscated%20Releases/winPEASx86.exe -O privesc/winPEASx86.exe
wget https://github.com/carlospolop/PEASS-ng/raw/master/winPEAS/winPEASexe/binaries/Obfuscated%20Releases/winPEASany.exe -O privesc/winPEASany.exe
echo "---------------------------------------------------"
echo "[*] Fetching reconnaissance tools..."
mkdir recon
wget https://github.com/angryip/ipscan/releases/download/3.7.2/ipscan-win64-3.7.2.exe -O recon/ipscan-win64-3.7.2.exe
wget https://nmap.org/dist/nmap-7.80-setup.exe -O recon/nmap-7.80-setup.exe
echo "---------------------------------------------------"
echo "[*] Fetching shells..."
mkdir webshell
wget https://raw.githubusercontent.com/tennc/webshell/master/net-friend/aspx/aspxspy.aspx -O webshell/aspxspy.txt
wget https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj -O MSBuildShell.csproj
wget http://nmap.org/dist/ncat-portable-5.59BETA1.zip -O ncat.zip
wget https://raw.githubusercontent.com/mIcHyAmRaNe/wso-webshell/master/wso.php -O webshell/wso.txt
wget https://raw.githubusercontent.com/WhiteWinterWolf/wwwolf-php-webshell/master/webshell.php -O webshell/wolf.txt
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
echo "[*] Fetching readme..."
wget https://raw.githubusercontent.com/phage-nz/infosec-bazaar/master/emulation/res/readme.txt -O ~/readme.txt
echo "---------------------------------------------------"
echo "[*] All finished!"
echo "[-] Refer to ~/readme.txt for help getting started."
echo "---------------------------------------------------"
