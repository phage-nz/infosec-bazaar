## Yeti Installation Notes ##

### Requirements ###
#### System ####
This has been tested on a Vultr server with (roughly) the following specs:  

- Ubuntu 16.04  
- 4x vCPU  
- 8GB RAM  
- 80GB disk  
- 1x static public IP  

#### Firewalling ####

Permit to public:  
- 80  
- 443  

### Installation ###

Begin by SSH'ing onto the box as root and updating it:  

*sudo apt update  
sudo apt upgrade*

SCP the files in this repo to the home folder of your server. Ensure that you retain the folder structure and that all files in the 'res' folder remain there, or else the script will fail.  

Run the install script:  

*chmod +x autoinstall.sh  
./autoinstall.sh*  

Follow the instructions at the end of the script to install a cert for your NGINX site:  

*certbot --nginx -d <domain name>*

Restart NGINX:  

*/etc/init.d/nginx restart*

### Setup ###
- If using uBlock Origin, disable it for the page. It breaks some of the pages (e.g. /js/analytics.js).
- Log in.  
- Reset the password for Yeti.  
- Roll the yeti account API key.  
- Create a new user and log in as them.  
- Under Settings > Analytics disable any processes you do not wish to run (e.g. ResolveHostnames - this can produce sketchy results).
- Define any external API keys under user management for One-Shot operations.  
- Create a CSV export template:  

*value,tags  
{%for obs in elements%},{{obs.value}}{{obs.created}}  
{%endfor%}*