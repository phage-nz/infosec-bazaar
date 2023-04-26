#!/bin/bash
echo "---------------------------------------------------"
echo "[*] EMULATION SERVER PREPARATION SCRIPT - 26/04/23"
echo '[*] "Train like you fight..."'
echo '[?] https://github.com/phage-nz/infosec-bazaar/tree/master/emulation'
echo '[?] Intended for use with Ubuntu 20.04'
echo "---------------------------------------------------"
SHOW_HELP="FALSE"
NO_RDP="FALSE"
UPGRADE_OS="FALSE"
INTSALL_VECTR="FALSE"
while getopts hru OPT
do
    case "${OPT}" in
        h) SHOW_HELP="TRUE";;
        n) NO_RDP="TRUE";;
        u) UPGRADE_OS="TRUE";;
        v) INSTALL_VECTR="TRUE";;
    esac
done
if [[ $SHOW_HELP = "TRUE" ]]; then
    echo "-h show this message."
    echo "-n do not install Lubuntu desktop and enable xRDP (default: false)."
    echo "-u upgrade OS packages  (default: false)."
    echo "-v install Vectr  (default: false)."
    exit 0
fi
if [[ -z "$SUDO_COMMAND" ]]; then
    echo "[!] Must be run with sudo."
    exit
fi
read -p "[?] Enter hostname to be used in configs: " hostname
if [[ -z $(getent hosts $hostname) ]]; then
    echo "[!] Hostname could not be resolved."
    exit
fi
read -p "[?] Enter username to be used in configs: " app_user
read -p "[?] Enter password to be used in configs: " app_pass
echo "[*] Updating OS..."
apt update
if [[ $UPGRADE_OS = "TRUE" ]]; then
    apt upgrade -y
fi
USER_HOME=$(getent passwd $SUDO_USER | cut -d: -f6)
echo "---------------------------------------------------"
echo "[*] Setting up non-default repositories..."
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
add-apt-repository -y ppa:deadsnakes/ppa
echo "[*] Installing OS pre-requisites..."
curl -L "https://github.com/docker/compose/releases/download/v2.16.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose
apt-get update
apt install -y apache2 apt-utils autoconf build-essential cmake default-jdk docker-ce git make mingw-w64 mingw-w64-common nasm net-tools nmap p7zip-full python3-dev python3-pip python3.10 python3.10-dev software-properties-common unzip
snap install go --classic
curl https://nim-lang.org/choosenim/init.sh -sSf | sh
echo 'export PATH=/root/.nimble/bin:$PATH' >> ~/.bashrc && source ~/.bashrc
if [[ ":$PATH:" != *"/.nimble/bin"* ]]; then
    export PATH=/root/.nimble/bin:$PATH
fi
usermod -aG docker $SUDO_USER
if [[ $NO_RDP = "FALSE" ]]; then
    echo "[-] Including remote desktop packages..."
    apt install -y xrdp xfce4 xubuntu-core xorg dbus-x11 x11-xserver-utils firefox
    adduser xrdp ssl-cert
    systemctl enable xrdp && systemctl start xrdp
    echo xfce4-session > $USER_HOME/.xsession
    chown $SUDO_USER:$SUDO_USER $USER_HOME/.xsession
    echo "[!] Remote desktop setup complete."
    echo "[?] Please ensure that you set a password for your user."
        sleep 5
else
    echo "[!] Skipping remote desktop setup..."
fi
echo "[*] Disabling host firewall..."
ufw disable
echo "---------------------------------------------------"
echo "[*] Preparing Apache..."
a2enmod rewrite proxy proxy_http
systemctl restart apache2
echo "---------------------------------------------------"
echo "[*] Setting up BeEF"
git clone https://github.com/beefproject/beef /opt/BeEF
cd /opt/BeEF
sed -i "s/user:   \"beef\"/user:   \"$app_user\"/g" config.yaml
sed -i "s/passwd: \"beef\"/passwd: \"$app_pass\"/g" config.yaml
docker build -t beef .
#docker run -p 3000:3000 -p 6789:6789 -p 61985:61985 -p 61986:61986 -d --name beef beef
echo "---------------------------------------------------"
echo "[*] Setting up Chisel"
mkdir /opt/Chisel && cd /opt/Chisel
wget https://github.com/jpillora/chisel/releases/download/v1.8.1/chisel_1.8.1_linux_amd64.gz -O chisel_linux_amd64.gz
wget https://github.com/jpillora/chisel/releases/download/v1.8.1/chisel_1.8.1_windows_amd64.gz -O chisel_windows_amd64.gz
wget https://github.com/jpillora/chisel/releases/download/v1.8.1/chisel_1.8.1_windows_386.gz -O chisel_windows_386.gz
gunzip chisel_linux_amd64.gz
chmod +x chisel_linux_amd64
echo "---------------------------------------------------"
echo "[*] Setting up Empire..."
docker pull bcsecurity/empire:latest
docker create -v /empire --name data bcsecurity/empire:latest
#docker run -it -p 1337:1337 -p 5000:5000 --volumes-from data bcsecurity/empire:latest
#docker exec -it {container-id} ./ps-empire client
echo "---------------------------------------------------"
echo "[*] Setting up Exploit DB"
git clone https://gitlab.com/exploit-database/exploitdb /opt/exploit-db
echo "---------------------------------------------------"
echo "[*] Installing Havoc"
apt install -y libfontconfig1 libglu1-mesa-dev libgtest-dev libspdlog-dev libboost-all-dev libncurses5-dev libgdbm-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev libbz2-dev mesa-common-dev qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools libqt5websockets5 libqt5websockets5-dev qtdeclarative5-dev qtbase5-dev libqt5websockets5-dev libspdlog-dev libboost-all-dev
git clone https://github.com/HavocFramework/Havoc.git /opt/Havoc
cd /opt/Havoc/Teamserver
go mod download golang.org/x/sys
go mod download github.com/ugorji/go
wget https://musl.cc/x86_64-w64-mingw32-cross.tgz -O /tmp/mingw-musl.tgz
if [ ! -d "data" ]; then
    mkdir data
fi
tar zxvf /tmp/mingw-musl.tgz -C data
cd /opt/Havoc
make
echo "---------------------------------------------------"
echo "[*] Setting up Merlin"
mkdir /opt/Merlin && cd /opt/Merlin
wget https://github.com/Ne0nd0g/merlin/releases/latest/download/merlinServer-Linux-x64.7z
wget https://github.com/Ne0nd0g/merlin/releases/latest/download/merlinAgent-Linux-x64.7z
wget https://github.com/Ne0nd0g/merlin/releases/latest/download/merlinAgent-Windows-x64.7z
7z x -pmerlin merlinServer-Linux-x64.7z && rm merlinServer-Linux-x64.7z
mv merlinServer-Linux-x64 merlinServer
echo "---------------------------------------------------"
echo "[*] Setting up Metasploit..."
cd /tmp
wget https://raw.githubusercontent.com/rapid7/metasploit-Omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb -O msfinstall
chmod +x msfinstall && ./msfinstall && rm msfinstall
echo "---------------------------------------------------"
echo "[*] Setting up Modlishka..."
mkdir /opt/Modlishka && cd /opt/Modlishka
wget https://github.com/drk1wi/Modlishka/releases/latest/download/Modlishka-linux-amd64 -O Modlishka
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
echo "[*] Setting up Mythic"
git clone https://github.com/its-a-feature/Mythic /opt/Mythic
cd /opt/Mythic
./mythic-cli install github https://github.com/MythicAgents/Athena
./mythic-cli install github https://github.com/MythicAgents/Apollo
./mythic-cli install github https://github.com/MythicAgents/Medusa
./mythic-cli install github https://github.com/MythicAgents/tetanus
./mythic-cli install github https://github.com/MythicC2Profiles/dns
./mythic-cli install github https://github.com/MythicC2Profiles/dynamichttp
./mythic-cli install github https://github.com/MythicC2Profiles/http
./mythic-cli install github https://github.com/MythicC2Profiles/websocket
./mythic-cli install github https://github.com/MythicAgents/scarecrow_wrapper
./mythic-cli install github https://github.com/MythicAgents/service_wrapper
echo "---------------------------------------------------"
echo "[*] Installing NimPlant"
git clone https://github.com/chvancooten/NimPlant /opt/NimPlant
cd /opt/NimPlant/client && nimble install -d
cd /opt/NimPlant/server && pip install -r requirements.txt
echo "---------------------------------------------------"
echo "[*] Setting up Prelude Operator"
mkdir /opt/Operator && cd /opt/Operator
wget "https://download.prelude.org/latest?arch=x64&platform=linux&variant=appImage" -O prelude-operator
chmod +x prelude-operator
echo "---------------------------------------------------"
echo "[*] Installing Python Packages"
apt remove -y python3-openssl
pip install bloodhound pyopenssl impacket pypykatz twisted
echo "---------------------------------------------------"
echo "[*] Setting up Sliver..."
mkdir /opt/Sliver && cd /opt/Sliver
wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-server_linux
mv sliver-server_linux sliver-server
chmod +x sliver-server
echo "---------------------------------------------------"
echo "[*] Setting up SpiderFoot"
git clone https://github.com/smicallef/spiderfoot /opt/SpiderFoot
cd /opt/SpiderFoot
docker build -t spiderfoot .
#docker run -p 5009:5001 -d --name spiderfoot spiderfoot
if [[ $INSTALL_VECTR = "TRUE" ]]; then
    echo "---------------------------------------------------"
    echo "[*] Setting up Vectr"
    mkdir /opt/vectr && cd /opt/vectr
    wget https://github.com/SecurityRiskAdvisors/VECTR/releases/download/ce-8.3.2/sra-vectr-runtime-8.3.2-ce.zip
    unzip sra-vectr-runtime-8.3.2-ce.zip
    sed -i "s/sravectr.internal/$hostname/g" .env
    sed -i "s/Test1234/$(openssl rand -hex 16)/g" .env
    sed -i "s/CHANGEMENOWPLEASE/$(openssl rand -hex 16)/g" .env
    docker-compose up -d
    echo "[*] Vectr started on port 8081."
    echo "[-] Find the default credentials here: https://docs.vectr.io/Installation/"
fi
echo "---------------------------------------------------"
echo "[*] Setting up Villain"
git clone https://github.com/t3l3machus/Villain /opt/Villain
cd /opt/Villain
pip install -r requirements.txt
echo "---------------------------------------------------"
echo "[*] Beginning helper tools"
mkdir /opt/Tools/
echo "---------------------------------------------------"
echo "[*] Fetching Loaders"
mkdir /opt/Tools/Loaders
git clone https://github.com/mdsecactivebreach/CACTUSTORCH /opt/Tools/Loaders/CACTUSTORCH
git clone https://github.com/TheWover/donut /opt/Tools/Loaders/donut
git clone https://github.com/xuanxuan0/DripLoader /opt/Tools/Loaders/DripLoader
git clone https://github.com/assume-breach/Home-Grown-Red-Team /tmp/Home-Grown-Red-Team
mv /tmp/Home-Grown-Red-Team/* /opt/Tools/Loaders && rm -rf /tmp/Home-Grown-Red-Team
git clone https://github.com/icyguider/Shhhloader /opt/Tools/Loaders/Shhhloader
echo "---------------------------------------------------"
echo "[*] Fetching obfuscators"
mkdir /opt/Tools/Obfuscators
git clone https://github.com/danielbohannon/Invoke-Obfuscation /opt/Tools/Obfuscators/Invoke-Obfuscation
git clone https://github.com/CBHue/PyFuscation /opt/Tools/Obfuscators/PyFuscation
echo "---------------------------------------------------"
echo "[*] Fetching payloads"
mkdir /opt/Tools/Payloads
git clone https://github.com/ORCx41/AtomPePacker /opt/Tools/Payloads/AtomPePacker
git clone https://github.com/optiv/Freeze /opt/Tools/Payloads/Freeze
mkdir /opt/Payloads/ScareCrow && cd /opt/Tools/Payloads/ScareCrow
wget https://github.com/optiv/ScareCrow/releases/download/v4.11/ScareCrow_4.11_linux_amd64 -O ScareCrow
echo "---------------------------------------------------"
echo "[*] Fetching privilege escalation Tools..."
mkdir /opt/Tools/Privesc && cd /opt/Tools/Privesc
wget https://github.com/AlessandroZ/BeRoot/archive/master.zip -O BeRoot.zip
git clone https://github.com/r3motecontrol/Ghostpack-CompiledBinaries /opt/Tools/Privesc/Ghostpack
wget https://github.com/l0ss/Grouper2/releases/latest/download/Grouper2.exe -O Grouper2.exe
wget https://raw.githubusercontent.com/411Hall/JAWS/master/jaws-enum.ps1 -O jaws.ps1
wget https://github.com/AlessandroZ/LaZagne/releases/latest/download/lazagne.exe -O lazagne.exe
wget https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip -O mimikatz.zip
wget https://raw.githubusercontent.com/itm4n/PrivescCheck/master/PrivescCheck.ps1 -O PrivescCheck.ps1
wget https://raw.githubusercontent.com/M4ximuss/Powerless/master/Powerless.bat -O Powerless.bat
wget https://github.com/BC-SECURITY/Empire/raw/main/empire/server/data/module_source/privesc/PowerUp.ps1 -O PowerUp.ps1
wget https://github.com/lgandx/Responder/archive/master.zip -O Responder.zip
wget https://github.com/lgandx/Responder-Windows/archive/master.zip -O Responder-Windows.zip
wget https://github.com/BloodHoundAD/SharpHound/releases/download/v1.0.3/SharpHound-v1.0.3.zip -O SharpHound.zip
wget https://www.ampliasecurity.com/research/wce_v1_42beta_x32.zip -O wce_x32.zip
wget https://www.ampliasecurity.com/research/wce_v1_42beta_x64.zip -O wce_x64.zip
wget https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/winPEAS/winPEASbat/winPEAS.bat -O winPEAS.bat
wget https://github.com/carlospolop/PEASS-ng/raw/master/winPEAS/winPEASexe/binaries/Obfuscated%20Releases/winPEASx64.exe -O winPEASx64.exe
wget https://github.com/carlospolop/PEASS-ng/raw/master/winPEAS/winPEASexe/binaries/Obfuscated%20Releases/winPEASx86.exe -O winPEASx86.exe
wget https://github.com/carlospolop/PEASS-ng/raw/master/winPEAS/winPEASexe/binaries/Obfuscated%20Releases/winPEASany.exe -O winPEASany.exe
echo "---------------------------------------------------"
echo "[*] Fetching reconnaissance tools..."
mkdir /opt/Tools/Recon && cd /opt/Tools/Recon
wget https://github.com/angryip/ipscan/releases/download/3.9.1/ipscan-win64-3.9.1.exe -O ipscan.exe
wget https://nmap.org/dist/nmap-7.93-setup.exe -O nmap.exe
echo "---------------------------------------------------"
echo "[*] Fetching webshells..."
mkdir /opt/Tools/Webshell && cd /opt/Tools/Webshell
wget https://raw.githubusercontent.com/tennc/webshell/master/net-friend/aspx/aspxspy.aspx -O aspxspy.txt
wget https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj -O MSBuildShell.csproj
wget http://nmap.org/dist/ncat-portable-5.59BETA1.zip -O ncat.zip
wget https://raw.githubusercontent.com/mIcHyAmRaNe/wso-webshell/master/wso.php -O wso.txt
wget https://raw.githubusercontent.com/WhiteWinterWolf/wwwolf-php-webshell/master/webshell.php -O wolf.txt
echo "---------------------------------------------------"
echo "[*] Fetching other utilities..."
mkdir /opt/Tools/Util && cd /opt/Tools/Util
wget https://www.7-zip.org/a/7z2201-x64.exe -O 7z.exe
wget https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.4.9/npp.8.4.9.Installer.x64.exe -O npp.exe
wget https://download.java.net/java/GA/jdk14.0.1/664493ef4a6946b186ff29eb326336a2/7/GPL/openjdk-14.0.1_windows-x64_bin.zip -O openjdk.zip
wget https://the.earth.li/~sgtatham/putty/latest/w64/putty.zip -O putty.zip
wget https://www.python.org/ftp/python/3.10.10/python-3.10.10.exe -O python-3.exe
wget https://download.sysinternals.com/files/SysinternalsSuite.zip -O /tmp/SysinternalsSuite.zip
unzip /tmp/SysinternalsSuite.zip -d /opt/Tools/Util && rm /tmp/SysinternalsSuite.zip && rm /opt/Tools/Util/*.txt
wget https://winscp.net/download/WinSCP-5.21.5-Portable.zip -O WinSCP.zip
echo "---------------------------------------------------"
echo "[*] Fetching readme..."
wget https://raw.githubusercontent.com/phage-nz/infosec-bazaar/master/emulation/res/readme.txt -O $USER_HOME/readme.txt
echo "---------------------------------------------------"
echo "[*] All finished!"
echo "[-] Refer to $USER_HOME/readme.txt for help getting started."
echo "---------------------------------------------------"
