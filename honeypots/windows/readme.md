## Windows Honeypot

These notes describe what is really just a flexible, cloud hosted VM. Use cases include:
- Dynamic malware analysis.  
- A high-interaction honeypot.  
- EDR and SIEM research and training.  

While your specific use case will determine aspects such as it's firewalling and profile, these details can easily be changed at any time.

## Requirements
- At least 1vCPU and 2GB memory  
- Server 2012 R2+  

## Considerations
There are a few considerations you need to make:
- OPSEC.  
- Profile.  
- How are you going to collect endpoint events? Sysmon, EDR or both?  

### OPSEC
This host is **going** to be compromised, therefore you need to consider the impact of all data on it also being compromised - including event logs. When you establish an RDP session to a host your IP address is recorded in *at least* 2 log files: Security events, and Terminal-Services-RemoteConnectionManager\Operational. For obvious reasons, you do not want your public IP being learned by actors who land on your host, particularly if they work out that they've been ensnared by a honeypot. While there is a script further below that can be used to clear all event logs prior to opening the host to the internet, you do not want to rely on this. So, consider means of obscuring your origin. Do not connect directly to the host. This could include:
- A paid VPN service, such as ExpressVPN, Mullvad or ProtonVPN.  
- Your own [algo](https://github.com/trailofbits/algo) VPN server.  
- A Windows jump host.  

Whatever path you take, ensure that you're connected to this before interacting with your VM.

It also goes without saying, do not leave any files on the host that could lead back to you.

### Profile
To give your host some degree of legitimacy, consider:
- An organisation to use for branding (e.g. host name, host artifacts, login warning, user names).  
- A host profile. For example, if emulating a web server you'll want IIS, and an RDS host will likely need an assortment of browsers and document editors.   

Try not to make it too obvious that it's a honeypot. Be mindful of things like what security features you disable, services you install and ports you open.

### Event Collection
This entirely depends on what you've got available to you. The combination of Sysmon and Azure Sentinel is well proven and I'd certainly recommmend it. Included in this folder is a Sentinel workbook that covers:
- Authentication failure and interactive logon events.  
- Web request statistics and client events.  
- MITRE ATT&CK techniques for a given user over time.  
- Sysmon events for the user and system.  

The workbook relies on Sysmon and Sentinel both being configured according to the [Sentinel ATT&CK project](https://github.com/BlueTeamLabs/sentinel-attack) (you can also find my modular config [here](https://github.com/phage-nz/infosec-bazaar/tree/master/soc/sysmon)).

Remember to hide the Sysmon service:
```
sc sdset Sysmon64 D:(D;;DCLCWPDTSD;;;IU)(D;;DCLCWPDTSD;;;SU)(D;;DCLCWPDTSD;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)
```
And to restore it:
```
sc sdset Sysmon64 D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)
```
If deploying an EDR agent to the host, consider your end goal. If you want to see a compromise play out, you'll want to ensure that the agent operates passively, is hidden from the end user and doesn't impact Sysmon (if also in use, and vice versa in that case).

## Setup
- Deploy the VM with your hosting provider of choice. AWS, Azure, Vultr - take your pick. Assign it a firewall that permits inbound:
  - TCP 22 (SFTP/SSH) from your public IP.  
  - **Optional:** TCP 80 (HTTP) from all IP's.  
  - TCP 3389 (RDP) from your public IP.  
- RDP to the host.  
- **Optional:**  
  - Apply all outstanding patches.  
  - Rename the host.  
- Install any additional roles and features required by the profile you've decided upon. One addition I'd recommend including is .NET 3.5, as there are quite a few RAT's that still require this. You can defer the reboot as that'll be done shortly anyway.  
- Open Group Policy Editor (gpedit.msc) and apply the following changes:  
  - Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Device and Resource Redirection: Enable all Settings that begin with "do not allow" (e.g. "Do not allow clipboard redirection").  
  - **Optional:** Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options: Set "Accounts: Rename administrator account" to something of your choosing.  
- Under Control Panel > System and Security > Allow remote access: uncheck "Allow connections only from computers running Remote Desktop with Network Level Authentication".  
- Reboot the server, allow patches to complete installation and sign on with your new local administrator account.  
- Open the Local Users and Groups snap-in (lusrmgr.msc). Prepare the user accounts:  
  - If you renamed the built-in administrator account, remove the description of your account and create a new account named Administrator:  
    - Provide it the description: "Built-in account for administering the computer/domain".  
    - Set a password. Choose something that you're sure will be in a list of compromised passwords (maybe 200-500 hits on the [Have I Been Pwned Password Test](https://haveibeenpwned.com/Passwords)) but also won't make it obvious the host is a honeypot.  
    - Add it to whatever groups you deem necessary, depending how much of a headache you want to cause those signing on with it (e.g. Administrators, Remote Desktop Users).  
  - If you didn't rename the built-in account, use the above password selection guidelines to set a password for your account. Otherwise, ensure it's strong.  
  - Set up any other user accounts required by your host profile, too.  
- Install your browser of choice and configure it not to retain history.  
- Download the latest release of OpenSSH for Windows from https://github.com/PowerShell/Win32-OpenSSH/releases and extract it to C:\Program Files\OpenSSH. Add this path to the system PATH environment variable.  
- In a PowerShell prompt, install OpenSSH:  
```
mkdir C:\ProgramData\ssh
cd "C:\Program Files\OpenSSH"
.\install-sshd.ps1
.\ssh-keygen.exe -A
.\FixHostFilePermissions.ps1
.\FixUserFilePermissions.ps1
sc config sshd start= auto
sc start sshd
```
- If required, permit TCP 22 (SFTP/SSH) through the Windows firewall.  
- On your local workstation, assemble the software you wish to install on the host. This will need to include the requirements to pull events off the host. Additionally, you may want to include:
  - .NET 4.8  
  - 7zip  
  - Notepad ++  
  - OpenJDK  
  - pestudio  
  - Python 3.8  
  - Sysinternals Suite  
  - Wireshark  
- If deploying the host as a honeypot, try to keep it as free from analysis tools as possible. However, if you're using the host for malware analysis, [FLARE VM](https://github.com/fireeye/flare-vm) will save you a great deal of time.  
- Use Google to download as many documents and images as possible that will help build up your chosen profile. Google dorks such as "site:orgname.com filetype:pdf" will help.  
- Using WinSCP, copy out the software and profile artifacts over SFTP. Install the software, set up any agents and clean up any installation files.  
- While SFTP provides a secure method of transferring files to the host, if you need to paste text into it it consider: https://github.com/jlaundry/TypeClipboard  
- Log in with each of the users you created to ensure their profiles are created. Distribute the profile artifacts between the profiles.  
- Check that endpoint telemetry and Windows events are being successfully sent to their target.  
- Clear all event logs:  
```
@echo off
FOR /F "tokens=1,2*" %%V IN ('bcdedit') DO SET adminTest=%%V
IF (%adminTest%)==(Access) goto noAdmin
for /F "tokens=*" %%G in ('wevtutil.exe el') DO (call :do_clear "%%G")
echo.
echo Event Logs have been cleared!
goto theEnd
:do_clear
echo clearing %1
wevtutil.exe cl %1
goto :eof
:noAdmin
echo You must run this script as an Administrator!
echo.
:theEnd
```
- Take a snapshot of the host. This will be your rollback point.  
- Once the snapshot has completed, adjust the firewall:
  - TCP 22 (SFTP/SSH) from your public IP.  
  - **Optional:** TCP 80 (HTTP) from all IP's.  
  - **Optional:** TCP 445 (SMB) from all IP's.  
  - TCP 3389 (RDP) from all IP's.  
- Setup is complete. Keep an eye out for signs of anomalous activity or compromise.  

## Rollback  
Due to the possibility that an actor may return using the same credentials, post-compromise rollback isn't as straight forward as just reverting to snapshot:  
- Reimplement the restricted firewall profile.  
- Restore your host from snapshot.  
- RDP to the host and reset user credentials.  
- Clear event logs.  
- Take a fresh snapshot.  
- Once the snapshot has completed, open the host to the public again.  

## FAQ
**How long will it take to be compromised?**  
This depends entirely on where you've deployed it and how easily it can be discovered. I've seen it happen in hours and also months.

**Who will it be compromised by?**  
Again, this depends on factors like the context of it's deployment.

**I accidentally connected directly to it. What do I do?**  
If during setup, begin by enabling your method of connection masking and restrict host access to your new public IP. Reboot the host, clear the event logs and determine other locations your IP could have been logged (e.g. web server and application logs). At any other point in time, determine if there were any sessions held by "others" at the time (and respond accordingly), then roll back to the snapshot.