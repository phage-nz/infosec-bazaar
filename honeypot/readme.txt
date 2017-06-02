Honeypot AutoInstall Script v0.3
by Chris Campbell

Twitter: @phage_nz
GitHub: phage-nz
Blog: https://phage.nz

Installs:
Dionaea
p0f
Cowrie

Tested on Ubuntu 14.04 (EC2 t2.micro instance)


Default Install Notes
"""""""""""""""""""""

# Fetch the latest release of the autoinstall script.
wget https://raw.githubusercontent.com/phage-nz/malware-hunting/master/honeypot/autoinstall.sh
chmod +x autoinstall.sh
# Edit the variables at the top of the script.
nano autoinstall.sh
# Run the script and happy hunting!
sudo ./autoinstall.sh

Refer to the notes below for information on where customisations can be made.

Files required for automated Vagrant deployment are also available in ../honeypot-vagrant.


Post-Install Notes
""""""""""""""""""
Dionaea
'''''''
Essential:

- Create and apply security group with the following ports:
Management SSH (22/TCP) - restricted to your public IP. Only used if Cowrie is not installed.
FTP (21/TCP) 
HTTP/HTTPS (80/TCP and 443/TCP) 
NameServer (42/TCP) 
MSRPC (135/TCP ) 
SMB (445/TCP) 
TFTP (69/UDP) 
MSSQL (1433/TCP)
PPTP (1723/TCP)
SCADA (1883/TCP)
UPnP (1900/UDP)
MySQL (port 3306/TCP) 
SIP/SIP-TLS (5060/TCP+UDP and 5061/TCP)
Memcache (11211/TCP)

- Ensure Dionaea is listening:
netstat -putan|grep dionaea

- Check the error log in /opt/dionaea/var/dionaea/dionaea-errors.log

- General logs is /opt/dionaea/var/dionaea/dionaea.log and download binaries are in /opt/dionaea/var/dionaea/binaries


Optional:

- The main operational config is /opt/dionaea/etc/dionaea/dionaea.cfg

- To generate a fresh MySQL target database:

python /opt/dionaea/var/dionaea/scripts/generate_user_db.py

- To emulate different PPTP devices:

nano /opt/dionaea/etc/dionaea/services-available/pptp.yaml

-- Uncomment three lines under the device you wish to emulate, e.g.
firmware_revision: 4608
hostname: PIX
vendor_name: Cisco Systems

- It's not necessary to edit the FTP script in later releases. You can edit the welcome banner in /opt/dionaea/etc/dionaea/services-available/ftp.yaml

- To change the MSSQL version ID, edit the MSSQL script:

nano /opt/dionaea/lib/dionaea/python/dionaea/mssql/mssql.py

-- Edit as follows:
FROM> r.VersionToken.TokenType = 0x00
TO> r.VersionToken.TokenType = 0xAA

?> Refer to http://www.freetds.org/tds.html#responses for options.

- Comment out the following line in /opt/dionaea/lib/dionaea/python/dionaea/virustotal.py if you wish to disable automatic commenting of files uploaded to VirusTotal (done by default):

self.make_comment(sf[0], sf[1], sf[2], 'comment')


Cowrie
''''''
Essential:

- Create and apply security group with the following ports:
Cowrie SSH (22/TCP)
Management SSH (8925/TCP) - restrict to your public IP.

- Ensure Cowrie is listening:
netstat -putan|grep 2222

- Test:
ssh root@<server name>

-- Use a password defined in userdb.txt


Optional:

- Edit the host name:
nano /opt/cowrie/cowrie.cfg

FROM>srv03
TO>*whatever you want*

- Recreate filesystem:
/opt/cowrie/bin/createfs

- Add some more root passwords if desired:
nano /opt/cowrie/data/userdb.txt

-- Format for an accepted password:
<user>:0:<password>
e.g. root:0:toor

-- Format for a denied password:
<user>:0:!<password>
e.g. root:0:!toor
