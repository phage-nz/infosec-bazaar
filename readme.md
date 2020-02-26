           .__                           
    ______ |  |__ _____     ____   ____  
    \____ \|  |  \\__  \   / ___\_/ __ \ 
    |  |_> >   Y  \/ __ \_/ /_/  >  ___/ 
    |   __/|___|  (____  /\___  / \___  >
    |__|        \/     \//_____/      \/ 

**Twitter:** @phage_nz  
**GitHub:** phage-nz  
**Blog:** https://phage.nz  

https://github.com/phage-nz/malware-hunting  

A collection of scripts and information for Malware Hunting.  


## Current Inventory ##
**\emulation**  
- apt33.py - sample wrapper for APT33 tests.  
- fin10.py - sample wrapper for FIN10 tests.  
- turla.py - sample wrapper for Turla tests.  
**\honeypot**  
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
- readme.txt - notes for the installation of Dionaea, p0f and Cowrie.
- wordlist.txt - required by generate_user_db.py for the generation of plausible usernames and email addresses.  

**\lokirun**  
- run.ps1 - PowerShell script to automate the operation of Loki IOC scanner.  

**\honeypot-vagrant**  
- \scripts - location where the Vagrantfile sources the bootstrap.sh autoinstall script from.
- aws.credentials - stores AWS credentials used by Vagrantfile.
- readme.txt - notes for the installaion of Dionaea, p0f and Cowrie via Vagrant in AWS.
- Vagrantfile - the Vagrantfile for automatic deployment of a honeypot.
- vagrant-plugin.patch - a patch to fix a bug that prevents the installing of the vagrant-aws plugin.  

**\malware-crawler**  
- readme.txt - reference to ph0neutria.  

**\mhn**  
- readme.md - A collection of notes on extending and troubleshooting MHN.  

**\sandbox**  
- readme.md - A set of instructions to build hardened malware analysis VM's using VMCloak and FLARE VM.  

**\soc**  
- \Cortex-Analyzers - Custom analyzers for Hive Project's Cortex.  
- \Graylog - Custom content packs for Graylog.  
- \MISP - Install documentation and custom feeds.  

**\spamtrap**
- readme.md - Instructions on setting up spam traps using Mail-in-a-Box and Shiva.  

**\t-pot**  
- readme.md - Instructions on deploying T-Pot honeypot platform.  

**\volatility**
- autoinstall.sh - A script to automatically install Volatility, bulk_extractor and vshot by Crowd Strike.  

**\yeti**
- autoinstall.sh - A script to automatically install Yeti and custom plugins stored under \res.  
