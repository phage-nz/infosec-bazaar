#!/bin/bash
echo "**************************************************"
echo "* EMULATION SERVER PREPARATION SCRIPT - 27/09/24 *"
echo '*           "Train like you fight..."            *'
echo "***************************************************"
echo ""
echo "Intended for use with Ubuntu 22.04+"
echo "Note: The script isn't totally standalone. It will require your input at times."
sleep 2

# Allow ubuntu to sudo without password:
# sudo echo "ubuntu ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/90-cloud-init-users

echo "---------------------------------------------------"
echo "[*] Checking Dependencies..."

if [ -f /usr/bin/docker ]; then
    if id -nG "$USER" | grep -qw "docker"; then
        echo "[*] User is a member of the docker group."
    else
        echo "[!] User must be a member of the docker group."
        exit
    fi
else
    echo "[!] Docker does not appear to be installed."
    echo "[-] Please run install-docker.sh first."
    exit
fi

echo "---------------------------------------------------"
echo "[*] Installing OS Dependencies..."
sudo apt update
sudo apt install -y apt-transport-https build-essential ca-certificates cmake curl git librust-openssl-dev libssl-dev libxml2-dev masscan musl-tools mingw-w64 net-tools nmap p7zip-full proxychains4 python3-dev python3-pip python3-virtualenv software-properties-common unzip
sudo apt install --upgrade snapd
sudo snap install core22
echo "[*] Step OK!"
sleep 2

echo "---------------------------------------------------"
echo "[*] Installing XFCE and XRDP..."
sudo apt install -y mousepad xrdp xfce4 xubuntu-core xorg dbus-x11 x11-xserver-utils firefox
sudo adduser xrdp ssl-cert
sudo systemctl enable xrdp
sudo systemctl start xrdp
echo xfce4-session > ~/.xsession
echo "[!] Please ensure that you set a password for your user."
echo "[*] Step OK!"
sleep 2

echo "---------------------------------------------------"
echo "[*] Fetching Install Variables..."
read -p "[?] Enter hostname to be used in configs: " hostname
if [[ -z $(getent hosts $hostname) ]]; then
    echo "[!] Hostname could not be resolved."
    exit
fi
read -p "[?] Enter username to be used in configs: " app_user
read -p "[?] Enter password to be used in configs: " app_pass

echo "---------------------------------------------------"
echo "[*] Installing Go..."
sudo apt remove --purge -y golang-*
sudo snap install go --classic
echo "[*] Step OK!"
sleep 2

echo "---------------------------------------------------"
echo "[*] Installing Ruby..."
sudo apt install ruby ruby-dev
sudo gem update
echo "[*] Step OK!"
sleep 2

echo "---------------------------------------------------"
echo "[*] Installing Rust..."
echo "[-] Press ENTER when prompted to."
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env" 
rustup default nightly
rustup target add x86_64-pc-windows-gnu
echo "[*] Step OK!"
sleep 2

echo "---------------------------------------------------"
echo "[*] Disabling OS Firewall..."
sudo ufw disable
echo "[*] Step OK!"
sleep 2

echo "---------------------------------------------------"
echo "[*] Installing BeEF..."
sudo git clone https://github.com/beefproject/beef /opt/BeEF
sudo chown -R ubuntu:ubuntu /opt/BeEF
cd /opt/BeEF
sed -i "s/user:   \"beef\"/user:   \"$app_user\"/g" config.yaml
sed -i "s/passwd: \"beef\"/passwd: \"$app_pass\"/g" config.yaml
docker build -t beef .
echo "[*] Step OK!"
sleep 2

echo "---------------------------------------------------"
echo "[*] Installing Bore..."
sudo git clone https://github.com/ekzhang/bore /opt/bore
sudo chown -R ubuntu:ubuntu /opt/bore
cd /opt/bore
cargo update
cargo build
mv target/debug/bore .
cargo build --target x86_64-pc-windows-gnu
mv target/x86_64-pc-windows-gnu/debug/bore.exe .
echo "[*] Step OK!"
sleep 2

echo "---------------------------------------------------"
echo "[*] Installing Caldera..."
sudo snap install node --classic
sudo apt install -y python3-tk zlib1g
sudo git clone https://github.com/mitre/caldera.git --recursive /opt/caldera
sudo wget wget https://raw.githubusercontent.com/phage-nz/infosec-bazaar/master/emulation/res/caldera.service -O /etc/systemd/system/caldera.service
sudo chown -R ubuntu:ubuntu /opt/caldera
cd /opt/caldera
python3 -m virtualenv env
source /opt/caldera/env/bin/activate
pip3 install -r requirements.txt
pip3 install docker
cd plugins/emu
echo "[?] The password for AdFind is: NotMalware"
./download_payloads.sh
pip3 install -r requirements.txt
cd ../human
pip3 install -r requirements.txt
cd ../sandcat
./update_plugins.sh
deactivate
echo "[!] Please ensure you pass the --build parameter when first starting Caldera."
echo "[*] Step OK!"
sleep 2

echo "---------------------------------------------------"
echo "[*] Installing Chisel..."
sudo git clone https://github.com/jpillora/chisel /opt/chisel
sudo chown -R ubuntu:ubuntu /opt/chisel
cd /opt/chisel
env CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o chisel-linux_amd64
env CGO_ENABLED=1 GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o chisel-windows_amd64.exe
chmod +x chisel-linux_amd64
sudo sed -e '/socks4/ s/^#*/#/' -i /etc/proxychains4.conf
echo -e 'socks5\t127.0.0.1\t1080'| sudo tee -a /etc/proxychains4.conf > /dev/null
echo "[*] Step OK!"
sleep 2

echo "---------------------------------------------------"
echo "[*] Installing Evilginx2..."
sudo git clone https://github.com/kgretzky/evilginx2 /opt/evilginx2
sudo chown -R ubuntu:ubuntu /opt/evilginx2
cd /opt/evilginx2
make
mv build/evilginx .
echo "[*] Step OK!"
sleep 2

echo "---------------------------------------------------"
echo "[*] Setting up Exploit DB"
sudo git clone https://gitlab.com/exploit-database/exploitdb /opt/exploitdb
sudo chown -R ubuntu:ubuntu /opt/exploitdb
echo "[*] Step OK!"
sleep 2

echo "---------------------------------------------------"
echo "[*] Installing Havoc..."
sudo git clone -b dev https://github.com/HavocFramework/Havoc /opt/Havoc
sudo chown -R ubuntu:ubuntu /opt/Havoc
cd /opt/Havoc
sudo apt install -y git build-essential apt-utils cmake libfontconfig1 libglu1-mesa-dev libgtest-dev libspdlog-dev libboost-all-dev libncurses5-dev libgdbm-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev libbz2-dev mesa-common-dev qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools libqt5websockets5 libqt5websockets5-dev qtdeclarative5-dev qtbase5-dev libqt5websockets5-dev python3-dev libboost-all-dev mingw-w64 nasm
python3 -m virtualenv env
source /opt/Havoc/env/bin/activate
cd teamserver
sed -i "s/golang-go\ //g" Install.sh
go mod download golang.org/x/sys
go mod download github.com/ugorji/go
cd ..
make ts-build
make client-build
deactivate
echo "[*] Step OK!"
sleep 2

echo "---------------------------------------------------"
echo "[*] Installing Metasploit..."
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall
chmod +x /tmp/msfinstall
sudo sh /tmp/msfinstall
msfdb init
echo "[*] Step OK!"
sleep 2

echo "---------------------------------------------------"
echo "[*] Installing Mythic..."
sudo git clone https://github.com/its-a-feature/Mythic /opt/Mythic
sudo chown -R ubuntu:ubuntu /opt/Mythic
cd /opt/Mythic
sudo make
sudo chown ubuntu:ubuntu mythic-cli
./mythic-cli install github https://github.com/MythicAgents/arachne
./mythic-cli install github https://github.com/MythicAgents/Athena
./mythic-cli install github https://github.com/MythicAgents/Apollo
./mythic-cli install github https://github.com/MythicAgents/service_wrapper
./mythic-cli install github https://github.com/MythicAgents/thanatos
./mythic-cli install github https://github.com/MythicC2Profiles/dynamichttp
./mythic-cli install github https://github.com/MythicC2Profiles/http
./mythic-cli install github https://github.com/MythicC2Profiles/websocket
echo "[*] Step OK!"
sleep 2

echo "---------------------------------------------------"
echo "[*] Installing ROADtools..."
sudo git clone https://github.com/dirkjanm/ROADtools /opt/ROADtools
sudo chown -R ubuntu:ubuntu /opt/ROADtools
cd /opt/ROADtools
python3 -m virtualenv env
source /opt/ROADtools/env/bin/activate
pip install roadlib/
pip install roadrecon/
pip install roadtx/
deactivate

echo "---------------------------------------------------"
echo "[*] Installing Sliver..."
sudo git clone https://github.com/BishopFox/sliver /opt/sliver
sudo chown -R ubuntu:ubuntu /opt/sliver
cd /opt/sliver
make
echo "[*] Step OK!"
sleep 2

echo "---------------------------------------------------"
echo "[*] Installing Vectr..."
sudo mkdir /opt/vectr
sudo chown -R ubuntu:ubuntu /opt/vectr
cd /opt/vectr
wget https://github.com/SecurityRiskAdvisors/VECTR/releases/download/ce-9.3.3/sra-vectr-runtime-9.3.3-ce.zip
unzip sra-vectr-runtime-9.3.3-ce.zip
sed -i "s/VECTR_HOSTNAME.*/VECTR_HOSTNAME=$hostname/" .env
sed -i "s/JWS_KEY.*/JWS_KEY=$(openssl rand -hex 16)/" .env
sed -i "s/JWE_KEY.*/JWE_KEY=$(openssl rand -hex 16)/" .env
docker compose build
wget https://raw.githubusercontent.com/improsec/calderaToAttire/main/CalderaToAttire.py
echo "[*] Step OK!"
sleep 2

echo "---------------------------------------------------"
echo "[*] Installing Villain..."
sudo git clone https://github.com/t3l3machus/Villain /opt/Villain
sudo chown -R ubuntu:ubuntu /opt/Villain
cd /opt/Villain
python3 -m virtualenv env
source /opt/Villain/env/bin/activate
pip3 install -r requirements.txt
deactivate
echo "[*] Step OK!"
sleep 2

echo "---------------------------------------------------"
echo "[*] Setting Up Supplementary Tools..."
sudo mkdir /opt/Tools
sudo chown ubuntu:ubuntu /opt/Tools
cd /opt/Tools
git clone https://github.com/Hackplayers/evil-winrm
cd evil-winrm
sudo gem install fileutils krb5 logger stringio winrm winrm-fs
cd ..
python3 -m virtualenv env
source /opt/Tools/env/bin/activate
git clone https://github.com/fortra/impacket
cd impacket
pip install .
cd ..
git clone https://github.com/dirkjanm/BloodHound.py BloodHound
cd BloodHound
pip install .
cd ..
git clone https://github.com/skelsec/pypykatz
cd pypykatz
pip install .
echo "[*] Step OK!"
sleep 2

echo "---------------------------------------------------"
echo "[*] Downloading Common Utilities..."
cd /opt/Tools
mkdir Util
cd Util
wget https://7-zip.org/a/7z2408-x64.exe -O 7z.exe
wget https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.6.9/npp.8.6.9.portable.x64.zip -O npp.zip
wget https://github.com/vletoux/pingcastle/releases/download/3.2.0.1/PingCastle_3.2.0.1.zip -O PingCastle.zip
wget https://the.earth.li/~sgtatham/putty/latest/w64/putty.zip -O putty.zip
wget https://www.python.org/ftp/python/3.12.6/python-3.12.6-amd64.exe -O python.exe
wget https://github.com/BloodHoundAD/SharpHound/releases/download/v2.5.6/SharpHound-v2.5.6.zip -O SharpHound.zip
wget https://download.sysinternals.com/files/SysinternalsSuite.zip -O /tmp/SysinternalsSuite.zip
unzip /tmp/SysinternalsSuite.zip -d /opt/Tools/Util && rm /tmp/SysinternalsSuite.zip && rm /opt/Tools/Util/*.txt
wget https://winscp.net/download/WinSCP-6.3.5-Portable.zip/download -O WinSCP.zip
echo "[*] Step OK!"
sleep 2

echo "---------------------------------------------------"
echo "[*] Fetching Readme..."
wget https://raw.githubusercontent.com/phage-nz/infosec-bazaar/master/emulation/res/readme.txt -O ~/readme.txt
echo "[*] Step OK!"
sleep 2

echo "---------------------------------------------------"
echo "[*] Setup Complete!"
echo "[-] Find the readme in: ~/readme.txt"
