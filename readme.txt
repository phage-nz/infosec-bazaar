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
\honeypots
- dionaea.init - init.d script for dionaea.
- dionaea.logrotate - logrotate.d script for dionaea.
- dionaea_query.py - script for performing common queries against the dionaea sqlite database. Original script by Andrew Waite (www.infosanity.co.uk)
- generate_user_db.py - script to generate a random target user database for the dionaea mysql service.
- install_notes.txt - notes for the installation of dionaea, p0f and kippo.
- kippo.init - init.d script for kippo.
- kippo.logrotate - logrotate.d script for kippo.
- p0f.init - init.d script for p0f.
- wordlist.txt - required by generate_user_db.py for the generation of plausible usernames and email addresses.