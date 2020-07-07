## Linux Honeypot

These notes describe setting up a Linux honeypot using:
- Cowrie SSH+telnet honeypot.  
- "Dockerised" Apache.  

The logs of both are ingested by Azure Sentinel using custom parsers.

## Requirements
- At least 1vCPU and 2GB memory  
- Ubuntu 18.04+  

## Considerations
As compared to the Windows honeypot, there aren't really many considerations to be made beforehand:
- What host profile do you want to adopt? What's under attack at the moment that you want to research?  
- You want the combination of web server and SSH server to appear plausible. Adopting an IIS profile for the web server but serving up SSH from a "CentOS" server will arouse suspicion. However, WordPress and Apache on Ubuntu 18.04 should fly under the radar of most. For some profiles this may mean disabling one or more services.  

## Host Setup
- Deploy the VM with your hosting provider of choice. AWS, Azure, Vultr - take your pick. Assign it a firewall that permits inbound:
  - TCP 22 (SCP/SSH) from your public IP.  
  - TCP 80 (HTTP) from your public IP.  
  - TCP 2322 (SCP/SSH) from your public IP.  
- SSH to the host on TCP 22.  
- Update the host and install all required dependencies:  
```
apt update && apt upgrade
apt install docker.io git python-virtualenv libssl-dev libffi-dev build-essential libpython3-dev python3-minimal authbind virtualenv
```

## Cowrie Setup
- Cowrie should not be run as root, so create a dedicated user:  
```
adduser --disabled-password cowrie
```
- Clone the Cowrie repo to /opt/cowrie and transfer ownership of it to the Cowrie user:  
```
git clone http://github.com/cowrie/cowrie /opt/cowrie && chown -R cowrie:cowrie /opt/cowrie
```
- As an elevated user, copy the systemd and sockets configuration files to /etc/systemd:  
```
cp /opt/cowrie/docs/systemd/etc/systemd/system/cowrie.service /etc/systemd/system
cp /opt/cowrie/docs/systemd/etc/systemd/system/cowrie.socket /etc/systemd/system
```
- A few changes must be made to both files:  
  - **cowrie.service:** `/opt/cowrie-env` should be changed to `/opt/cowrie/cowrie-env`  
  - **cowrie.service:** `/opt/cowrie/cowrie-env/bin/python` should be changed to `/opt/cowrie/cowrie-env/bin/python3`  
  - **cowrie.socket:** `ListenStream=2222` should be changed to `ListenStream=0.0.0.0:2222`  
  - **cowrie.socket:** `ListenStream=2223` should be changed to `ListenStream=0.0.0.0:2223`  
- Also, drop the logrotate configuration in place:  
```
cp /opt/cowrie/docs/systemd/etc/logrotate.d/cowrie /etc/logrotate.d
```
- Correct the paths in /etc/logrotate.d/cowrie:  
  - `/var/log/cowrie/*.log` should be changed to `/opt/cowrie/var/log/cowrie/*.log`  
  - `/var/log/cowrie/*.log` should be changed to `/opt/cowrie/var/log/cowrie/*.log`  
- Reconfigure SSH to listen on a different port (e.g. 2322) and redirect SSH and telnet traffic to the Cowrie listeners:  
```
sed -i 's/#Port 22/Port 2322/g' /etc/ssh/sshd_config
service ssh reload
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2223
iptables-save > /etc/iptables.rules
echo '#!/bin/sh' >> /etc/network/if-up.d/iptablesload 
echo 'iptables-restore < /etc/iptables.rules' >> /etc/network/if-up.d/iptablesload 
echo 'exit 0' >> /etc/network/if-up.d/iptablesload
chmod +x /etc/network/if-up.d/iptablesload
```
- Next time you SSH to the host, remember to connect to this port. Ensure this port is also firewalled off to restrict access to only your IP.  
- A couple of sample filesystems are included in this repository (under the "cowrie" folder) that were generated on a fresh Kali VM. Which one you use depends on the performance of your host. Begin with _6 and test SSH performance. If it's inadequate, try _5. If you wish to create your own, the following syntax can be used:  
```
mkdir /tmp/.fs
wget https://raw.githubusercontent.com/cowrie/cowrie/master/bin/createfs -O /tmp/.fs && chmod +x chmod +x /tmp/.fs/createfs
/tmp/.fs/createfs -d 5 -o /tmp/.fs/kali_5.pickle
/tmp/.fs/createfs -d 6 -o /tmp/.fs/kali_6.pickle
```
- SCP the pickle files into /opt/cowrie/share/cowrie.  
- While on the filesystem source, collect some basic information about the host. This will be required at a later step:  
```
uname -ra
ssh -V
```
- Drop the configuration files into place:  
```
cp /opt/cowrie/etc/cowrie.cfg.dist etc/cowrie.cfg
cp /opt/cowrie/etc/userdb.example etc/userdb.txt
````
- userdb.txt is used to define what credentials can be used to successfully authenticate. The header of the file describes the expected format:  
```
# ':' separated fields, file is processed line for line
# processing will stop on first match
#
# Field #1 contains the username
# Field #2 is currently unused
# Field #3 contains the password
# '*' for password allows any password
# '!' at the start of a password will not grant this password access
# '/' can be used to write a regular expression
```
- cowrie.cfg requires a few changes:  
  - **Host name:** change the value of `hostname` to something of your choosing.  
  - **File system:** the value of `filesystem` must point to the file system pickle, e.g. `filesystem = ${honeypot:share_path}/kali_6.pickle`  
  - **Listen endpoints:** as systemd is being used to manage the Cowrie process, each setting of `listen_endpoints` must be changed:  
    - `tcp:2222:interface=0.0.0.0` becomes `systemd:domain=INET:index=0`  
    - `tcp:2223:interface=0.0.0.0` becomes `systemd:domain=INET:index=1`
  - **Scan hardening:** Using the output of the uname and ssh commands from the "source" host, configure the following settings:
```
[shell]
kernel_version = 5.5.0-kali2-cloud-amd64
kernel_build_string = #1 SMP Debian 5.5.17-1kali1
hardware_platform = x86_64
operating_system = GNU/Linux
ssh_version = OpenSSH_8.2p1 Debian-4, OpenSSL 1.1.1g  21 Apr 2020

[ssh]
version = SSH-2.0-OpenSSH_8.2p1 Debian-4
```
- Switch to the Cowrie user and configure the virtualenv:  
```
sudo su - cowrie
cd /opt/cowrie
virtualenv --python=python3 cowrie-env
source cowrie-env/bin/activate
pip install --upgrade pip
pip install --upgrade -r requirements.txt
```
- Cowrie can now be started:  
```
systemctl daemon-reload
systemctl enable cowrie.service
systemctl start cowrie.service
```
- Check the status of the Cowrie service:  
```
systemctl status cowrie.service
```
- If the service has started OK, attempt to SSH on with a mix of good and bad credentials. The Azure agent will be tailing the JSON log, so ensure it is being written to:  
```
tail -f /opt/cowrie/var/log/cowrie/cowrie.json
```
- Should you find only IPv6 addresses are being logged, you can disable IPv6. Edit /etc/default/grub and add `ipv6.disable=1` to the values of both GRUB_CMDLINE_LINUX_DEFAULT and GRUB_CMDLINE_LINUX. For example:  
```
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash ipv6.disable=1"
GRUB_CMDLINE_LINUX="ipv6.disable=1"
```
- Save the updated configuration by running `update-grub` and then reboot the host.  
- Once the log looks good, SCP a copy to your local machine as it'll be required for setup of Azure Sentinel.  

## Apache Setup
- Once again, begin by making a new user:  
```
adduser --disabled-password webpot
```
- Add the new user to the docker group:  
```
usermod -aG docker webpot
```
- Copy the "webpot" structure from within the "apache" folder of this repo into /home/webpot. This consists of three main components:  
  - **Dockerfile:** Defines the build of the Apache container.  
  - **headers.conf:** Copied to /etc/apache2/mods-enabled/ to define custom headers.  
  - **src folder:** Copied to /var/www/html/ (i.e. this is what is rendered in browsers).  

- How you assemble the contents of the src folder is really up to you. Ideally, you'd have the required files on hand. If not, wget could be used to clone a page:  
```
wget -mpEHk -np --restrict-file-names=windows -D example.com,cdnjs.cloudflare.com https://example.com
```
- Or, pywebcopy can also be used. Install it with pip:  
```
pip3 install pywebcopy
```
- Then clone a single page or a site:  
```
from pywebcopy import save_webpage
save_webpage(url='http://example.com/index.html', project_folder='/path/to/page')

from pywebcopy import save_website
save_website(url='http://example.com/index.html', project_folder='/path/to/site')
```
- Navigate through the downloaded content in your browser to ensure it still renders properly and there are no requests being made to the origin. Tidy up any dead or undesired links, postback URLs, etc. Ensure that the default page is either index.html or index.php - something that'll be loaded by a request to the site root. Once complete, copy the resulting page into the src folder on the honeypot server.  

- Switch to the user shell:  
```
su - webpot
```
- Build the container:  
```
cd ~
docker build -t webpot webpot/
```
- Start the server on port 80:  
```
docker run -v /var/log/webpot:/var/log/apache2 -p 80:80 --restart unless-stopped --name "webpot_docker" -d webpot
```
- Check that the docker process stays up:  
```
docker ps -a
```
- If you make any changes to the contents of src, you can easily rebuild and restart the container with this (filthy) script:  
```
#!/bin/bash
cd ~
docker stop webpot_docker
docker rm webpot_docker
docker rmi webpot
docker build -t webpot webpot/
docker run -v /var/log/webpot:/var/log/apache2 -p 80:80 --name "webpot_docker" -d webpot
sleep 2
docker ps -a
```

## Enabling Access
- Adjust the firewall to permit inbound:
  - TCP 22 (SCP/SSH) from the internet.  
  - TCP 23 (telnet) from the internet.  
  - TCP 80 (HTTP) from the internet.  
  - TCP 2322 (SCP/SSH) from your public IP.  

## Log Collection
- Open your Sentinel worksapce and navigate to "Data connectors" > "Syslog" > "Open connector page". Expand "Install agent on a non-Azure Linux Machine", the select "Download & install agent for non-Azure Linux machines". Select the Linux tab and either copy the shell script that is presented, or take note of your Workspace ID and Primary Key and install the agent on your host by hand:  
```
wget https://raw.githubusercontent.com/Microsoft/OMS-Agent-for-Linux/master/installer/scripts/onboard_agent.sh
chmod +x onboard_agent.sh
./onboard_agent.sh -w <workspace ID> -s <key> -d opinsights.azure.com
```
- Once installed, return to the Syslog connector page and select "Open your workspace advanced settings configuration". Select "Data" > "Custom Logs". Check "Apply below configuration to my linux machines" then add a new custom log source:  
  - When prompted, upload the cowrie.json file you downloaded.  
  - The default delimeter is correct (newline).  
  - Specify `/opt/cowrie/var/log/cowrie/cowrie.json` as the log collection path.  
  - Name the custom log "cowrie_JSON" (without quotes). Sentinel will automatically append _CL to this name.  
- Repeat the above for the Apache access log, setting the log paths as `/var/log/apache2/access.log` and `/var/log/webpot/access.log`. Name the custom log "Apache_Access".  
- It will take a while for this to roll out to the host, but eventually you'll be able to run the log analytics queries `cowrie_JSON_CL` and `Apache_Access_CL` and see data coming in.  
- Take the contents of cowrie.txt from the "cowrie" folder of this repo and paste them into a new log analytics query. Run the query, then save this off as a **function** with the name, alias and category of "Cowrie". Likewise, take the contents of apache.txt from the "apache" folder and save them as a function with the name and alias of "ApacheAccess" under the category "Apache".  
- Once events are being ingested and parsed by Azure Sentinel, linux_workbook.json can be imported to define a custom workbook to interact with Cowrie and Apache data.  