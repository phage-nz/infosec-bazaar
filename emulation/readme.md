## Emulation Server Preparation
The tooling employed by bad actors isn't solely closed source. There is no shortage of open source or freely available options that can be quickly adopted and fulfil requirements at no cost. The goal of emulation is to match or closely imitate the actions of your adversaries, so being able to use the same or similar tooling to them is more preferable than confining your testing to a suite of controlled, autonomous executions.

Included in this folder is:
- `install-docker.sh`: Must be run first.
- `prepare-server.sh`: Installs the following tools.

In indicated in the `prepare-server.sh` script, it isn't totally standalone. Some steps may require minor interactions.

## Tooling
You can find all tooling under `/opt`.
### C2
- Havoc: https://github.com/HavocFramework/Havoc
- Mythic: https://github.com/its-a-feature/Mythic
- Sliver: https://github.com/BishopFox/sliver

### Platform
- Caldera: https://github.com/mitre/caldera
- Metasploit: https://github.com/rapid7/metasploit-framework
- VECTR: https://github.com/SecurityRiskAdvisors/VECTR

### Tunnelling
- Bore: https://github.com/ekzhang/bore
- Chisel: https://github.com/jpillora/chisel

### Loaders
Unlike previous versions of this script, I no longer include off-the-shelf loaders as most are signatured hours/days after being open sourced. I'd encourage you to [learn to develop your own](https://maldevacademy.com/).

### Others
- BeEF: https://github.com/beefproject/beef
- BloodHound.py: https://github.com/dirkjanm/BloodHound.py
- evilginx: https://github.com/kgretzky/evilginx2
- Exploit-DB: https://gitlab.com/exploit-database/exploitdb
- Impacket: https://github.com/fortra/impacket
- pypykatz: https://github.com/skelsec/pypykatz
- ROADtools: https://github.com/dirkjanm/ROADtools

A selection of common Windows utilities (e.g. 7zip, Sysinternals suite) are also copied into `/opt/Tools/Util`.

## Access
Once the script completes, you will be able to access the via either SSH or RDP (xrdp). RDP requires that you first set a password for your user.