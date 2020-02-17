## Preparation
Stand up a VM with at least:
- 4GB RAM  
- 2 CPU  
- 80GB disk

The more the better.

Prepare DNS for the FQDN you'll use to access it.

Some services such as DigitalOcean only provide a root user. If this is the case, make a new sudo user:
```
adduser ubuntu  
mv /root/.ssh /home/ubuntu/.ssh  
chown -R ubuntu:ubuntu /home/ubuntu/.ssh  
sudo usermod -a -G sudo ubuntu
```

For development instances, you may want to allow it to sudo without a password. If so, add to /etc/sudoers:
```
ubuntu ALL=(ALL) NOPASSWD:ALL
```
**Don't do this in production!**

## Install
SSH on as the ubuntu user.

Update the box and install some pre-req's:
```
sudo apt-get update -y && sudo apt-get upgrade -y
sudo apt install mysql-client haveged libfuzzy-dev libffi-dev -y
sudo dpkg-reconfigure tzdata
```

Fetch and run the install script:
```
curl https://raw.githubusercontent.com/MISP/MISP/2.4/INSTALL/INSTALL.sh -o misp_install.sh
chmod +x misp_install.sh
./misp_install.sh -c -M
```

The installation isn't completely hands-off:
- Define your base URL when requested to. 
- Let the installer create the "misp" user.  
- Enter your sudo users password when requested to during the Modules install.

## Basic Setup
- Reset the admin password.
- Optional: Make a new organisation (Administration > Add Organisations).  
- Make a new organisation admin user (Administration > Add User, role: "Org Admin").  
- Make a new organisation API user (Administration > Add User, role: "Publisher")  
- Enable required feeds, including caching (Sync Actions > List Feeds).  
- Define a feed pull schedule (Administration > Scheduled Tasks).

## Tweaks
You may need to bump up memory in /etc/php/7.2/apache2/php.ini:
```
memory_limit = 2048M
```
Generally half the RAM value suffices. If you're still hitting the limit then you'll want to throw more RAM at the server.

The number of workers defined in /var/www/MISP/app/Console/worker/start.sh:
```
../cake CakeResque.CakeResque start --interval 5 --queue default
```
It's worthwhile adding extra Default workers per CPU core.

Edit the host name in /etc/apache2/sites-enabled/misp-ssl.conf

Install certbot:
```
sudo add-apt-repository ppa:certbot/certbot
sudo apt-get update
sudo apt install python3-certbot-apache
```

Script to renew:
```
#!/bin/bash
sudo certbot -d misp.yourdomain.com --manual --preferred-challenges dns certonly
```

Add new cert+key paths to /etc/apache2/sites-enabled/misp-ssl.conf then restart Apache:
```
/etc/init.d/apache2 reload
```
Adjust the base URL in MISP admin settings.

## References
- General usage: https://www.circl.lu/doc/misp/  
- Training slides: https://www.misp-project.org/misp-training/misp-training.pdf  
- Setup and Python API usage: https://holdmybeersecurity.com/2020/01/28/install-setup-misp-on-ubuntu-18-04-with-an-intro-to-pymisp/
