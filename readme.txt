       .__                           
______ |  |__ _____     ____   ____  
\____ \|  |  \\__  \   / ___\_/ __ \ 
|  |_> >   Y  \/ __ \_/ /_/  >  ___/ 
|   __/|___|  (____  /\___  / \___  >
|__|        \/     \//_____/      \/ 
               phage
             @phage_nz
        bytefog.blogspot.com


https://github.com/phage-nz/malware-hunting

A collection of scripts and information for Malware Hunting.


Current inventory:
\cuckoo
- install.sh - automatically install Cuckoo Sandbox, all dependencies, additional processing modules and create a cloaked VM.
- readme.txt - notes for the installation of Cuckoo Sandbox and the creation of cloaked VM's.
\honeypot
- autoinstall.sh - automatic install script for Dionaea, DionaeaFR, Cowrie and p0f.
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
\lokirun
- run.ps1 - PowerShell script to automate the operation of Loki IOC scanner.
\honeypot-vagrant
- \scripts - location where the Vagrantfile sources the bootstrap.sh autoinstall script from.
- aws.credentials - stores AWS credentials used by Vagrantfile.
- readme.txt - notes for the installaion of Dionaea, p0f and Cowrie via Vagrant in AWS.
- Vagrantfile - the Vagrantfile for automatic deployment of a honeypot.
- vagrant-plugin.patch - a patch to fix a bug that prevents the installing of the vagrant-aws plugin.
\malware-crawler
- readme.txt - reference to ph0neutria.
