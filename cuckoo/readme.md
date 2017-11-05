## Cuckoo Install Notes ##
- Update apt:

*apt-get update && apt-get upgrade*

- Install Cuckoo:

*wget https://raw.githubusercontent.com/phage-nz/malware-hunting/master/cuckoo/install.sh  
chmod +x install.sh
sudo ./install.sh*

#### Configuring Suricata ####
- Edit configuration file:
nano /etc/suricata/suricata-cuckoo.yaml
-- Disable fast and unified2 log types.
-- Enable file-store. Set force-md5 and force-filestore to yes. Enable file-log.
-- Locate reassembly: and set depth to 0
-- Under default-config: set request-body-limit and response-body-limit to 0.
-- Under vars: address-groups: set EXTERNAL_NET to any.

#### Configuring Cuckoo ####
- Edit configuration files:

**/opt/cuckoo/conf/cuckoo.conf:**  
\[cuckoo\]  
memory_dump = on  
\[resultserver\]  
ip = [ip address of the vboxnet0 interface]  

**/opt/cuckoo/conf/memory.conf:**  
\[basic\]  
delete_memdump = yes

**/opt/cuckoo/conf/processing.conf:**  
\[memory\]  
enabled = yes  
\[suricata\]  
enabled = yes  
conf = /etc/suricata/suricata-cuckoo.yaml  
\[virustotal\]  
enabled = yes  
key = \[key of the virus total API, could be obtained registering in http://www.virustotal.com\]  

**/opt/cuckoo/conf/reporting.conf:**
\[mongodb\]
enabled = yes

- Adjust /opt/cuckoo/conf/virtualbox.conf according to the VM's you've built:

\[cuckoo1\]  
label = \[Name of the guest virtual machine as configured in VirtualBox\]  
ip = \[ip address configured in the guest\]  
snapshot = \[the name of the snapshot taken with virtual box\]


#### VMCloak Notes ####
- Mount ISO (example):

*mkdir /mnt/win10x64*  
*mount -o loop,ro vms/Win10_1511_2_EnglishInternational_x64.iso /mnt/win10x64*

- Configure VM (example):

*vmcloak init -d --win10x64 --iso-mount /mnt/win10x64 --serial-key \<serial\> \<VM name\>*

- Install software (e.g. Acrobat Reader 9, WinRAR) and perform tasks (e.g. remotetooltips, windows_cleanup). See full list of options here: https://github.com/jbremer/vmcloak/tree/master/vmcloak/dependencies:

*vmcloak install <VM name> adobe9 wic pillow dotnet40 java7 silverlight pillow removetooltips windows_cleanup winrar*

- Install Office 2k7:

*vmcloak install \<VM name\> office2007 office2007.isopath=\<path to iso\> office2007.serialkey=\<serial\>*

- At this point 'win10' is your working template. It can be further modified if need be. To make a usable VM, however, it must be snapshotted which makes it immutable. So, the template is cloned:

*vmcloak clone win10 win10a1*

- A VM is made using this clone, which makes "win10a1" immutable whilst leaving "win10" free to be modified:

*vmcloak snapshot win10a1 cuckoo1 --cpus \<number CPU\> --ramsize \<RAM in MB\> --resolution \<resolution\>*

- After this you can start the VM and perform such tasks as:
 - Enabling MS Office macro's.
 - Ensuring IP addressing is correct.


#### VirtualBox Interfaces ####
- You can use the following script to ensure that all interfaces are up and correctly configured:

*
\#!/bin/bash  
VBoxManage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1
iptables -A FORWARD -o eth0 -i vboxnet0 -s 192.168.56.0/24 -m conntrack --ctstate NEW -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A POSTROUTING -t nat -j MASQUERADE
sysctl -w net.ipv4.ip_forward=1*
