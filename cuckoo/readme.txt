Cuckoo Install Notes
""""""""""""""""""""
- Update apt:
apt-get update

- Install Cuckoo and Volatility:
(from: https://github.com/buguroo/cuckooautoinstall)
sudo ./cuckooautoinstall.bash --upgrade

- Install Suricata:
apt-get install suricata
cp /etc/suricata/suricata-debian.yaml /etc/suricata/suricata-cuckoo.yaml

- Edit Suricata config:
nano /etc/suricata/suricata-cuckoo.yaml
-- Disable fast and unified2 log types.
-- Enable file-store. Set force-md5 and force-filestore to yes. Enable file-log.
-- Locate reassembly: and set depth to 0
-- Under default-config: set request-body-limit and response-body-limit to 0.
-- Under vars: address-groups: set EXTERNAL_NET to any.

- Enable Suricata ruleset updates:
git clone https://github.com/seanthegeek/etupdate.git
cp etupdate/etupdate /usr/bin
/usr/sbin/etupdate -V
crontab-e
ADD> 30 * * * * /usr/sbin/etupdate


Configuring Cuckoo
""""""""""""""""""
- Edit configuration files:
/opt/cuckoo/conf/cuckoo.conf:
[cuckoo]
memory_dump = on

[resultserver]
ip = [ip address of the vboxnet0 interface]

/opt/cuckoo/conf/memory.conf:
[basic]
delete_memdump = yes

/opt/cuckoo/conf/processing.conf: 
[memory]
enabled = yes
[suricata]
enabled = yes
conf = /etc/suricata/suricata-cuckoo.yaml
[virustotal]
enabled = yes
key = [key of the virus total API, could be obtained registering in http://www.virustotal.com

/opt/cuckoo/conf/reporting.conf:
[mongodb]
enabled = yes

- Install vmcloak:
apt-get install genisoimage
pip install vmcloak

- Configure VM (example):
vmcloak init -d --win7x86 --iso-mount <location of mounted ISO> --serial-key <serial>
vmcloak install win7 adobe9 wic pillow dotnet40 firefox_41 java7 silverlight5 pil chrome iexplore removetooltips windows_cleanup winrar
vmcloak install win7 office2007 office2007.isopath=<path to iso> office2007.serialkey=<serial>
-- 'win7' is now your working template. It can be further modified if need be.
vmcloak clone win7 win7a1
vmcloak snapshot win7a1 cuckoo1 192.168.56.101
-- This creates a VM named 'cuckoo1', and 'win7a1' becomes immutable.

- After this you can start the VM and perform such tasks as enabling MS Office macro's, ensuring IP addressing is correct, etc.

- Adjust /opt/cuckoo/conf/virtualbox.conf according to the VM's you've built:
[cuckoo1]
label = [Name of the guest virtual machine as configured in VirtualBox]
ip = [ip address configured in the guest]
snapshot = [the name of the snapshot taken with virtual box]

- You can use the following script to ensure that all interfaces are up and correctly configured:

#!/bin/bash
VBoxManage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1
iptables -A FORWARD -o eth0 -i vboxnet0 -s 192.168.56.0/24 -m conntrack --ctstate NEW -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A POSTROUTING -t nat -j MASQUERADE
sysctl -w net.ipv4.ip_forward=1