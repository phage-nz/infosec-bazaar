## Sandbox Build Notes ##

### VM Build ###

- Install VirtualBox:  

*sudo echo "deb http://download.virtualbox.org/virtualbox/debian xenial contrib" >> /etc/apt/sources.list  
sudo apt update  
sudo apt install virtualbox-5.2*

- Download the latest VirtualBox extensions from https://www.virtualbox.org/wiki/Downloads and install in VirtualBox (File > Preferences > Extensions).

#### Option 1: Pre-Built Microsoft Development VM ####

- Download a 64-bit VirtualBox appliance from: https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/  
- Import the appliance into VirtualBox.  

#### Option 2: Scratch-Built and Hardened VM ####

- These instructions assume you already have the following:
  - Windows 10 ISO + serial.
  - Microsoft Office 2010 ISO + serial.

- Install VMCloak:

*sudo apt install python-pip  
sudo pip install vmcloak*

- Mount the Windows ISO:

*sudo mkdir /mnt/win10x64  
sudo mount -o loop,ro path/to/windows.iso /mnt/win10x64*

- Create the base template. The VM is able to be interacted with by selecting it in VirtualBox. You may need to bypass the language selection - the rest will be automated. It will disappear from the list of available VM's in VirtualBox once the install has completed:

*vmcloak init -d --win10x64 --iso-mount /mnt/win10x64 --serial-key YOUR-WINDOWS-SERIAL-HERE Windows_Base*

- Install a base set of software (example given):  

*vmcloak install Windows adobe9 wic pillow dotnet40 java7 silverlight pillow removetooltips windows_cleanup winrar*

- Clone the base template. This is required as, to make the VM usable, a template must be snapshotted - which makes it immutable:

*vmcloak clone Windows_Base Windows*

- Snapshot the clone. This will make a VM named 'Windows' available in VirtualBox:

*vmcloak snapshot Windows Windows --cpus 2 --ramsize 4096*

- Before starting the VM, add any additional resolutions you desire (these can later be changed inside the guest):

*vboxmanage setextradata "Windows" CustomVideoMode1 1366x768x32*

### Post-Install Configuration ####

- The VM will have a host-only adapter, you can either enable internet access for this (or change to a NAT/NAT network adapter):

*VBoxManage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1  
iptables -A FORWARD -o eth0 -i vboxnet0 -s 192.168.56.0/24 -m conntrack --ctstate NEW -j ACCEPT  
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT  
iptables -A POSTROUTING -t nat -j MASQUERADE  
sysctl -w net.ipv4.ip_forward=1*  

### Precautions ###

- The host should be on it's own VLAN.  
- If permitting internet access, route through a VPN or Tor.  
- Do not permit outbound access on wormable ports, e.g. WinRM and SMB.  

### Guest Configuration ###

- Boot into guest and:
  - Disable UAC.  
  - Create new administrator account.  
  - Log in as the new user.  
  - Reset the password of and then disable the built-in administrator account.  
  - Mount the Office ISO and then install Office.

- Download and FLARE VM from GitHub (https://github.com/fireeye/flare-vm/archive/master.zip) and extract to disk.
- Set PowerShell's ExecutionPolicy to unrestricted (this is a malware sandbox, after all):

*Set-ExecutionPolicy unrestricted -Force*

- Open and run install.ps1 in PowerShell. Let it do it's thing (it may take up to a couple of hours, depending on your internet connection).
- From experience, the install will fail on several items. They can be manually addressed.
- Mount Windows ISO and manually install .NET 3.5 (with Windows ISO mounted):

*Dism /online /enable-feature /featurename:NetFX3 /All /Source:D:\sources\sxs /LimitAccess*

- Install oletools:

*pip install oletools*

- Manually install via cinst (simply run *cinst \<package\>* in a terminal):
  - pestudio --ignore-checksums
  - autohotkey
- Add C:\Program Files\AutoHotKey to system PATH variable.
- Reload the terminal and continue with csint:
  - winpcap
  - wireshark
  - fakenet-ng --force
  - floss.python --force
- Close all windows and take a clean snapshot of the VM.

### File Copies ###

The copyfrom/copyto vboxmanage functions seem to work in the occassional release of VirtualBox - however cannot be relied upon. Additionally, as the Guest Additions is not desirable to in the guest, that basically leaves any native VirtualBox methods of file copy out of the question. The method I've settled on is:

- Put the files you wish to copy to the guest into a single folder on the host.  
- Convert the folder into an ISO image:

*genisoimage -o \<name\>.iso -V BACKUP -R -J ./\<folder name\>/*

- Mount the ISO in the VirtualBox guest. It will become accessible as a regular CD/DVD disc.
