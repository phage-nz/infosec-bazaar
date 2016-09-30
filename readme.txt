 _   _____      _____ 
| | |  _  |    |  _  |
| |_| |/' |_  _| |/' |
| __|  /| \ \/ /  /| |
| |_\ |_/ />  <\ |_/ /
 \__|\___//_/\_\\___/ 

          t0x0
        @t0x0_nz
   bytefog.blogspot.com


https://bitbucket.org/t0x0/malware-hunting

A collection of scripts and information for Malware Hunting.


Current inventory:
\cuckoo
- cuckooautoinstall.sh - automatically install Cuckoo Sandbox, all dependencies and common processing modules. Credit to: dreg@buguroo.com and dfrancos@buguroo.com
- install_notes.txt - notes for the installation of Cuckoo Sandbox, additional processing modules and the creation of cloaked VM's.
\honeypot
- autoinstall.sh - automatic install script for Cowrie, Dionaea and p0f.
- cowrie.init - init.d script for Cowrie.
- cowrie.logrotate - logrotate.d script for Cowrie.
- dionaea.init - init.d script for Dionaea.
- dionaea.logrotate - logrotate.d script for Dionaea.
- dionaea_query.py - script for performing common queries against the Dionaea sqlite database. Original script by Andrew Waite (www.infosanity.co.uk)
- generate_user_db.py - script to generate a random target user database for the Dionaea mysql service.
- p0f.init - init.d script for p0f.
- readme.txt - notes for the installation of Dionaea, p0f and Cowrie.
- wordlist.txt - required by generate_user_db.py for the generation of plausible usernames and email addresses.
\honeypot-vagrant
- \scripts - location where the Vagrantfile sources the bootstrap.sh autoinstall script from.
- aws.credentials - stores AWS credentials used by Vagrantfile.
- readme.txt - notes for the installaion of Dionaea, p0f and Cowrie via Vagrant in AWS.
- Vagrantfile - the Vagrantfile for automatic deployment of a honeypot.
- vagrant-plugin.patch - a patch to fix a bug that prevents the installing of the vagrant-aws plugin.