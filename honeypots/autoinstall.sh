#!/bin/bash

# Honeypot Autoinstall Script v0.1
# by Chris Campbell
#
# Twitter: @t0x0_nz
# GitHub: t0x0-nz
# Blog: bytefog.blogspot.com

# Installs:
# Dionaea
# p0f
# Cowrie
#
# Tested on Ubuntu 14.04 (EC2 t2.micro instance)

# Variables:
SSL_C="US" # Country code.
SSL_CN="server.domain.com" # Certificate CN.
SSL_O="Company Name Inc."  # Company name.
SSL_OU="OU" # Organisational unit.
DOMAIN="DOMAIN-GROUP" # Domain name.
SERVER="SERVER-DOMAIN" # Server name.

#
# SCRIPT START
#

echo "Operations must be elevated..."
sudo su
echo "Updating server..."
add-apt-repository ppa:honeynet/nightly -y
apt-get update
apt-get upgrade -y
echo "Installing dependencies..."
apt-get -f install p0f dionaea software-properties-common python-software-properties git python-twisted python-configparser python-crypto python-pyasn1 python-gmpy2 python-mysqldb python-zope.interface sqlite3 -y
echo "Making Dionaea honeypot database..."
mkdir /opt/dionaea/var/dionaea/scripts
wget https://raw.githubusercontent.com/t0x0-nz/malware-hunting/master/honeypots/generate_user_db.py -P /opt/dionaea/var/dionaea/scripts
wget https://raw.githubusercontent.com/t0x0-nz/malware-hunting/master/honeypots/wordlist.txt -P /opt/dionaea/var/dionaea/scripts
chown -R dionaea:dionaea /opt/dionaea/var/dionaea/scripts
chmod +x /opt/dionaea/var/dionaea/scripts/generate_user_db.py
sudo -u dionaea touch /opt/dionaea/var/dionaea/target_db.sqlite
sudo -u dionaea /opt/dionaea/var/dionaea/scripts/generate_user_db.py
echo "Fixing up Dionaea config files..."
sed -e '/errors.filename/ s/^#*/#/' -i /opt/dionaea/etc/dionaea/dionaea.cfg
sed -e '/errors.levels/ s/^#*/#/' -i /opt/dionaea/etc/dionaea/dionaea.cfg
sed -e '/errors.domains/ s/^#*/#/' -i /opt/dionaea/etc/dionaea/dionaea.cfg
sed -i 's/^\(default.levels=\).*/\1all,-debug/' /opt/dionaea/etc/dionaea/dionaea.cfg
sed -i 's/# ssl.default/ssl.default/g' /opt/dionaea/etc/dionaea/dionaea.cfg
sed -i 's/^\(ssl.default.c=\).*/\1'"$SSL_C"'/' /opt/dionaea/etc/dionaea/dionaea.cfg
sed -i 's/^\(ssl.default.cn=\).*/\1'"$SSL_CN"'/' /opt/dionaea/etc/dionaea/dionaea.cfg
sed -i 's/^\(ssl.default.o=\).*/\1'"$SSL_O"'/' /opt/dionaea/etc/dionaea/dionaea.cfg
sed -i 's/^\(ssl.default.ou=\).*/\1'"$SSL_OU"'/' /opt/dionaea/etc/dionaea/dionaea.cfg
sed -i '9,10 s/^#//' /opt/dionaea/etc/dionaea/services-available/mysql.yaml
sed -i 's/\/path\/to\/cc_info.sqlite/\/opt\/dionaea\/var\/dionaea\/target_db.sqlite/g' /opt/dionaea/etc/dionaea/services-available/mysql.yaml
sed -i '4,6 s/^#//' /opt/dionaea/etc/dionaea/services-available/pptp.yaml
sed -e '/self.root_path\s*=\s*/ s/^#*/#/' -i /opt/dionaea/lib/dionaea/python/dionaea/sip/extras.py
sed -e '/self.users\s*=\s*/ s/^#*/#/' -i /opt/dionaea/lib/dionaea/python/dionaea/sip/extras.py
sed -i 's/sqlite3.connect(self.users)/sqlite3.connect("\/opt\/dionaea\/var\/dionaea\/sipaccounts.sqlite")/g' /opt/dionaea/lib/dionaea/python/dionaea/sip/extras.py
sed -i 's/"OemDomainName", "WORKGROUP"/"OemDomainName", "'"$DOMAIN"'"/g' /opt/dionaea/lib/dionaea/python/dionaea/smb/include/smbfields.py
sed -i 's/"ServerName", "HOMEUSER-3AF6FE"/"ServerName", "'"$SERVER"'"/g' /opt/dionaea/lib/dionaea/python/dionaea/smb/include/smbfields.py
sed -i  's/^\(\s*r\.VersionToken\.TokenType\s*=\s*\).*$/\10xAA/' /opt/dionaea/lib/dionaea/python/dionaea/mssql/mssql.py
echo "Enabling Dionaea p0f handler..."
ln -s /opt/dionaea/etc/dionaea/ihandlers-available/p0f.yaml /opt/dionaea/etc/dionaea/ihandlers-enabled
echo "Making a folder for SIP pcap's..."
sudo -u dionaea mkdir -p /opt/dionaea/var/dionaea/rtp/default
echo "Installing Cowrie..."
mkdir /opt/cowrie/
git clone https://github.com/micheloosterhof/cowrie /opt/cowrie/
cp /opt/cowrie/cowrie.cfg.dist /opt/cowrie/cowrie.cfg
echo "Making Cowrie user and applying permissions..."
useradd -r -s /bin/false cowrie
mkdir -p /var/run/cowrie
chown -R cowrie:cowrie /opt/cowrie/
chown -R cowrie:cowrie /var/run/cowrie/
echo "Fixing up the Cowrie config file..."
sed -i 's/^\(hostname\s*=\s*\).*/\1'"$SERVER"'/' /opt/cowrie/cowrie.cfg
echo "Making the Cowrie filesystem..."
/opt/cowrie/bin/createfs
echo "Making logrotate scripts..."
wget https://raw.githubusercontent.com/t0x0-nz/malware-hunting/master/honeypots/dionaea.logrotate -O /etc/logrotate.d/dionaea
wget https://raw.githubusercontent.com/t0x0-nz/malware-hunting/master/honeypots/cowrie.logrotate -O /etc/logrotate.d/cowrie
echo "Setting all services to autostart..."
wget https://raw.githubusercontent.com/t0x0-nz/malware-hunting/master/honeypots/p0f.init -O /etc/init.d/p0f
wget https://raw.githubusercontent.com/t0x0-nz/malware-hunting/master/honeypots/cowrie.init -O /etc/init.d/cowrie
chmod +x /etc/init.d/p0f
chmod +x /etc/init.d/cowrie
update-rc.d dionaea defaults
update-rc.d p0f defaults
update-rc.d cowrie defaults
echo "Redirecting port 22 to Cowrie. You will need to re-establish your SSH session on port 8925 after the service reloads."
sed -i 's/Port 22/Port 8925/g' /etc/ssh/sshd_config
service ssh reload
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
iptables-save > /etc/iptables.rules
echo '#!/bin/sh' >> /etc/network/if-up.d/iptablesload 
echo 'iptables-restore < /etc/iptables.rules' >> /etc/network/if-up.d/iptablesload 
echo 'exit 0' >> /etc/network/if-up.d/iptablesload
chmod +x /etc/network/if-up.d/iptablesload
echo "Starting services..."
/etc/init.d/p0f start
/etc/init.d/dionaea start
/etc/init.d/cowrie start
echo "Exiting su..."
exit 0
echo "Exiting session..."
exit 0