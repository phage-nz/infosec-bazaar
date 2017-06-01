Default Install Notes
"""""""""""""""""""""

# Fetch the autoinstall script.
wget https://raw.githubusercontent.com/phage-nz/malware-hunting/master/honeypots/autoinstall.sh
chmod +x autoinstall.sh
# Edit variables where required.
nano autoinstall.sh
# Run the script and happy hunting!
sudo autoinstall.sh

Refer to the manual install notes below for information on where customisations can be made.

Files required for automated Vagrant deployment are also available in ../honeypot-vagrant.


Manual Install Notes
""""""""""""""""""""

- Spin up t2.micro Ubuntu 14.04 EC2 instance. Create and apply security group with the following ports:
ftp (21/tcp) 
http/https (80/tcp and 443/tcp) 
nameserver (42/tcp) 
msrpc (135/tcp ) 
smb (445/tcp) 
tftp (69/udp) 
ms-sql (1433/tcp)
pptp (1723/tcp)
scada (1883/tcp)
upnp (1900/udp)
mysql (port 3306/tcp) 
sip/sip-tls (5060/tcp+udp and 5061/tcp)
memcache (11211/tcp)

- Relocate the private key:
mv PrivateKey.pem ~/.ssh
chmod 400 ~/.ssh/PrivateKey.pem

- Connect to the instance:
ssh -i ~/.ssh/PrivateKey.pem ubuntu@ec2-xx-xxx-xxx-xx.us-west-2.compute.amazonaws.com

- Install Dionaea and p0f:
sudo apt-get update
apt-get install software-properties-common python-software-properties p0f autoconf automake check cython3 libcurl4-openssl-dev libemu-dev libev-dev libglib2.0-dev libloudmouth1-dev libnetfilter-queue-dev libnl-dev libpcap-dev libreadline-dev libsqlite3-dev libssl-dev libtool libudns-dev libxml2-dev libxslt1-dev python3 python3-dev python3-yaml -y
sudo apt-get upgrade -y
(reboot if required for kernel updates)
cd /opt
git clone https://github.com/DinoTools/dionaea
cd dionaea
git clone https://github.com/gento/liblcfg
cd liblcfg/code
autoreconf -vi
./configure --prefix=/opt/dionaea
make install
cd ..
cd ..
autoreconf -vi
./configure \
	--disable-werror \
	--prefix=/opt/dionaea \
	--with-python=/usr/bin/python3 \
	--with-cython-dir=/usr/bin \
	--with-ev-include=/usr/include \
	--with-ev-lib=/usr/lib \
	--with-emu-lib=/usr/lib/libemu \
	--with-emu-include=/usr/include \
	--with-gc-include=/usr/include/gc \
	--enable-nl \
	--with-nl-include=/usr/include/libnl3 \
	--with-nl-lib=/usr/lib \
	--with-lcfg-lib=/opt/dionaea/lib/ \
	--with-curl-config=/usr/bin/
make
sudo make install
useradd -r -s /bin/false dionaea
chown -R dionaea:dionaea /opt/dionaea/
mkdir /home/dionaea
chown dionaea:dionaea /home/dionaea

- Install sqlite3 command line utility (useful for ad-hoc queries):
apt-get install sqlite3 -y

- Edit the main config:
nano /opt/dionaea/etc/dionaea/dionaea.cfg
-- To mitigate issues with the error log not being written to, comment out:
#errors.filename=/opt/dionaea/var/dionaea/dionaea-errors.log
#errors.levels=warning,error
#errors.domains=*
-- Edit as follows (SSL details as example):
FROM> default.levels=all
TO> default.levels=all,-debug

TO> ssl.default.c=XX
TO> ssl.default.cn=XXXX.domain.com
TO> ssl.default.o=XXXX Inc
TO> ssl.default.ou=XX

- Create the MySQL target database:
-- Copy out wordlist.txt and generate_user_db.py to your home folder.
chmod +x generate_user_db.py
sudo -u dionaea touch /opt/dionaea/var/dionaea/target_db.sqlite
sudo -u dionaea ./generate_user_db.py

- Edit the MySQL config:
nano /opt/dionaea/etc/dionaea/services-available/mysql.yaml
-- Uncomment the following two lines and correct the path of the user database:
psn:
  path: "/opt/dionaea/var/dionaea/target_db.sqlite"

- Edit the PPTP config:
nano /opt/dionaea/etc/dionaea/services-available/pptp.yaml
-- Uncomment three lines under the device you wish to emulate, e.g.
firmware_revision: 4608
hostname: PIX
vendor_name: Cisco Systems

- Edit the SIP script:
nano /opt/dionaea/lib/dionaea/python/dionaea/sip/extras.py
-- Comment out:
#self.root_path = os.getcwd()
#self.users = os.path.join(self.root_path, config.get("users", "var/dionaea/sipaccounts.sqlite"))
-- Edit both occurences of:
FROM> sqlite3.connect(self.users)
TO> sqlite3.connect("/opt/dionaea/var/dionaea/sipaccounts.sqlite")

- Edit the SMB script:
nano /opt/dionaea/lib/dionaea/python/dionaea/smb/include/smbfields.py
-- Edit as follows (where X is specified, define your own entry):
FROM>        ConditionalField(UnicodeNullField(
FROM>            "OemDomainName", "WORKGROUP"), lambda x: not x.Capabilities & CAP_EXTENDED_SECURITY),

TO>        ConditionalField(UnicodeNullField(
TO>            "OemDomainName", "XXXX"), lambda x: not x.Capabilities & CAP_EXTENDED_SECURITY),

FROM>        ConditionalField(UnicodeNullField(
FROM>            "ServerName", "HOMEUSER-XXXX"), lambda x: not x.Capabilities & CAP_EXTENDED_SECURITY),

TO>        ConditionalField(UnicodeNullField(
TO>            "ServerName", "XXXX"), lambda x: not x.Capabilities & CAP_EXTENDED_SECURITY),


- It's not necessary to edit the FTP script in later releases. You can edit the welcome banner in /opt/dionaea/etc/dionaea/services-available/ftp.yaml

- Edit the MSSQL script:
nano /opt/dionaea/lib/dionaea/python/dionaea/mssql/mssql.py
-- Edit as follows:
FROM> r.VersionToken.TokenType = 0x00
TO> r.VersionToken.TokenType = 0xAA

?> Refer to http://www.freetds.org/tds.html#responses for options.

- Insert your VirusTotal API key into: /opt/dionaea/etc/dionaea/ihandlers-available/virustotal.yaml
- Comment out the following line in /opt/dionaea/lib/dionaea/python/dionaea/virustotal.py if you wish to disable automatic commenting on uploaded files:

self.make_comment(sf[0], sf[1], sf[2], 'comment')

- Enable the VirusTotal plugin:

sudo -u dionaea ln -s /opt/dionaea/etc/dionaea/ihandlers-enabled/virustotal.yaml /opt/dionaea/etc/dionaea/ihandlers-enabled

- Make a directory for SIP pcap's:
sudo -u dionaea mkdir -p /opt/dionaea/var/dionaea/rtp/default

- Create a logrotate script to rotate the logs on a daily basis using dionaea.logrotate (copy to /etc/logrotate.d/dionaea)

- Enable Dionaea p0f handler:
sudo -u dionaea ln -s /opt/dionaea/etc/dionaea/ihandlers-available/p0f.yaml /opt/dionaea/etc/dionaea/ihandlers-enabled

- Make p0f init script using p0f.init (copy to /etc/init.d/p0f) then:
chmod +x /etc/init.d/p0f

- Set all to autostart:
update-rc.d dionaea defaults
update-rc.d p0f defaults

- Start the honeypot:
/etc/init.d/p0f start
/etc/init.d/dionaea start

- Make sure that Dionaea is listening on all expected ports:
netstat -putan|grep dionaea

- Check the error log in /opt/dionaea/var/dionaea/dionaea-errors.log

- Add Custom TCP rule to AWS SSH security group for port 8925.

- Edit listen port of SSH service:
nano /etc/ssh/sshd_config

FROM> Port 22
TO> Port 8925

- Reload SSH service:
service ssh reload

- Establish new SSH session.

- Install dependencies:
apt-get install python-twisted python-configparser python-crypto python-pyasn1 python-gmpy2 python-mysqldb python-zope.interface

- Install Cowrie:
mkdir /opt/cowrie/
git clone https://github.com/micheloosterhof/cowrie /opt/cowrie/
cp /opt/cowrie/cowrie.cfg.dist /opt/cowrie/cowrie.cfg

- Edit the host name:
nano /opt/cowrie/cowrie.cfg

FROM>srv03
TO>*whatever you want*

- Create filesystem:
/opt/cowrie/bin/createfs

- Add some more root passwords if desired:
nano /opt/cowrie/data/userdb.txt

-- Format for an accepted password:
<user>:0:<password>
e.g. root:0:toor

-- Format for a denied password:
<user>:0:!<password>
e.g. root:0:!toor

- Create cowrie user:
useradd -r -s /bin/false cowrie

- Apply directory permissions:
mkdir -p /var/run/cowrie
chown -R cowrie:cowrie /opt/cowrie/
chown -R cowrie:cowrie /var/run/cowrie/

- Redirect port 22 to 2222:
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222

- Make changes persistent:
iptables-save > /etc/iptables.rules
echo '#!/bin/sh' >> /etc/network/if-up.d/iptablesload 
echo 'iptables-restore < /etc/iptables.rules' >> /etc/network/if-up.d/iptablesload 
echo 'exit 0' >> /etc/network/if-up.d/iptablesload
chmod +x /etc/network/if-up.d/iptablesload

- Copy init.d script in place as /etc/init.d/cowrie

- Allow init script to execute:
chmod +x /etc/init.d/cowrie

- Set to autostart:
update-rc.d cowrie defaults

-Copy logrotate script to /etc/logrotate.d/cowrie

- Start Cowrie:
/etc/init.d/cowrie start

- Ensure it's listening:
netstat -putan|grep 2222

- Test:
ssh root@<server name>

- Use a password defined in userdb.txt
