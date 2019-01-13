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

#### Accounts ####

At a minimum you really need:  

- Google Sheets API key.  
- MalShare API key.  
- Shodan API key.   
- VirusTotal API key.  

### Installation ###

Begin by SSH'ing onto the box as root and updating it:  

*sudo apt update  
sudo apt upgrade*

SCP the files in this repo to the home folder of your server. Ensure that you retain the folder structure and that all files in the 'res' folder remain there, or else the script will fail.  

Run the install script:  

*chmod +x autoinstall.sh  
./autoinstall.sh*  

Follow the instructions at the end of the script to install a cert for your NGINX site:  

*certbot --nginx -d \<domain name\>*

Restart NGINX:  

*/etc/init.d/nginx restart*

### Setup ###
- If using uBlock Origin, disable it for the page. It breaks some of the pages (e.g. /js/analytics.js).
- Log in.  
- Reset the password for Yeti.  
- Roll the yeti account API key.  
- Create a new user and log in as them.  
- Disable the default Yeti user.  
- Under Settings > Dataflows disable any feeds you do not wish to use (e.g. VirusTotalHunting if you don't have VTI key, any payload feeds if you only want network observables).  
- Under Settings > Analytics disable any processes you do not wish to run (e.g. ResolveHostnames).  
- Define any external API keys under user management for One-Shot operations.  
- Create a CSV export template:  

*value,created  
{%for entry in elements%}"{{entry.value}}","{{entry.created}}"  
{%endfor%}*

- If you want tags to be included too:

*value,created,tags  
{%for entry in elements%}"{{entry.value}}","{{entry.created}}","{%for tag in entry.tags%}{%if not loop.last%}{{tag}},{%else%}{{tag}}{%endif%}{%endfor%}"  
{%endfor%}*  

### Notes ###
To unlock feeds that are stuck in updating state:  

*$ mongo  
use yeti  
db.schedule_entry.update({lock: true}, {$set :{lock:false}}, {multi:true})*  

Reference: https://github.com/yeti-platform/yeti/issues/88  

To drop the database:  

*$ mongo  
use yeti  
db.dropDatabase()*  
