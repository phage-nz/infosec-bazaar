## Honeypots

**\linux**  
- autoinstall.sh - automatic install script for Dionaea, DionaeaFR, Cowrie and p0f.  
- dionaea-housekeeper.sh - cron script used to archive select Dionaea output on a daily basis.  
- cowrie.init - init.d script for Cowrie.  
- cowrie.logrotate - logrotate.d script for Cowrie.  
- dionaea.init - init.d script for Dionaea.  
- dionaea.logrotate - logrotate.d script for Dionaea.  
- dionaeafr.init - init.d script for DionaeaFR.  
- dionaeafr.logrotate - logrotate.d script for DionaeaFR.  
- generate_user_db.py - script to generate a random target user database for the Dionaea mysql service.  
- p0f.init - init.d script for p0f.  
- readme.md - notes for the installation of Dionaea, p0f and Cowrie.  
- wordlist.txt - required by generate_user_db.py for the generation of plausible usernames and email addresses.  

**\linux\vagrant**  
- \scripts - location where the Vagrantfile sources the bootstrap.sh autoinstall script from.  
- aws.credentials - stores AWS credentials used by Vagrantfile.  
- readme.md - notes for the installaion of Dionaea, p0f and Cowrie via Vagrant in AWS.  
- Vagrantfile - the Vagrantfile for automatic deployment of a honeypot.  
- vagrant-plugin.patch - a patch to fix a bug that prevents the installing of the vagrant-aws plugin.  

**\mhn**  
- readme.md - a collection of notes on extending and troubleshooting MHN.  

**\windows**
- readme.md - information on setting up a Windows honeypot.  