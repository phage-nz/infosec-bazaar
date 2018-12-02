## T-Pot Honeypot Installation Notes ##

### Requirements ###
#### System ####
This process has been tested on a DigitalOcean and Vultr servers with (roughly) the following specs:

- Ubuntu 16.04  
- 2x vCPU  
- 4GB RAM  
- 80GB disk  
- 1x static public IP  

These instructions will also cover configuring TLS for a custom domain, so configure an A record for web management if so desired.  

I'd also strongly encourage reading through my blog post that discusses some aspects of deployment that you should consider: https://blog.phage.nz/2018/11/15/learnings-from-the-battlefield/  

#### Firewalling ####

Restrict to personal IP ranges:  

- 64295 (T-Pot SSH)  
- 64297 (T-Pot HTTPS)  

Permit to public:  

- 20  
- 21  
- 22  
- 23  
- 25  
- 42  
- 80  
- 135  
- 443  
- 445  
- 1433  
- 1723  
- 1883  
- 3306  
- 3389  
- 5060  
- 5061  
- 5900  
- 8081  
- 9200  
- 27017  
- 28113  

### Installation ###

Begin by SSH'ing onto the box as root and making a regular user (if required, otherwise skip ahead):

*adduser \<username\>*  
*usermod -aG sudo \<username\>*  
*mkdir /home/\<username\>/.ssh*  
*cp /root/.ssh/authorized_keys /home/\<username\>/.ssh*  
*chown -R \<username\>:\<username\> /home/\<username\>/.ssh*  
*chmod 700 /home/\<username\>/.ssh*  
*chmod 600 /home/\<username\>/.ssh/authorized_keys*  
*rm -rf /root/.ssh*  
*wget https://raw.githubusercontent.com/phage-nz/t-pot-autoinstall/master/install.sh*  
*chmod +x install.sh*
*./install.sh*  

Follow the installation script instructions ensuring to have differing OS and web passwords for the regular user. Once complete it will kick you off and reboot the box. From herein SSH on using port 64295 using the regular user account.

Log in to the web interface on HTTPS port 64297 (accept the certificate warning, we'll take care of that) using the name of the regular user and web password that you configured during installation. Stop Glastopf in Portainer to free up port 80 for certbot.

Return to the SSH session and install certbot so the server key can be reissued by Lets Encrypt:

*sudo add-apt-repository ppa:certbot/certbot*  
*sudo apt-get update*  
*sudo apt-get install python3-certbot-nginx*  

More detailed instructions on this process can be found here: https://www.digitalocean.com/community/tutorials/how-to-secure-nginx-with-let-s-encrypt-on-ubuntu-16-04

Edit the nginx configuration for T-Pot and substitute in the host name you've made an A record for to manage the honeypot with:

*sudo nano /etc/nginx/sites-available/tpotweb.conf*  

Test the configuration and reload nginx:

*sudo nginx -t*  
*sudo systemctl reload nginx*  

Issue your certificate:

*sudo certbot --nginx -d example.com -d example.com*  

Test and restart nginx again using the commands above, then log in to the web interface on HTTPS port 64297 (this time using your custom FQDN) and restart Glastopf in Portainer.  

### Notes ###

If your honeypot attracts a high volume of 'wild' SMB traffic it'll likely dump a lot of WannaCry binaries and binary-streams into \/data\/dionaea. Automatic archiving will take place but the backups will fill up your disk very in a matter of days. To keep this under control, create an executable script under \/etc\/cron.daily as follows:  

*#!\/bin\/bash*  
*find \/data\/dionaea -type f -name '\*.gz' -mtime +2 -exec rm {} \\;*  

This will clear dionaea gzip backups older than 2 days on a daily basis.
