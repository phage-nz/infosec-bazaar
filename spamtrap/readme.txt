Shiva Install Notes
"""""""""""""""""""

Official Shiva documentation: https://github.com/shiva-spampot/shiva/blob/master/docs/User%20Manual.pdf

# Install pre-req's:
sudo apt-get install python-dev exim4-daemon-light g++ python-virtualenv libmysqlclient-dev libffi-dev libfuzzy-dev mysql-server mysql-client make automake autoconf
# Record the MySQL root password.

# Make base directory:
cd /opt
sudo mkdir shiva-installer&&sudo chown ubuntu:ubuntu shiva-installer

# Fetch and install Shiva:
git clone https://github.com/shiva-spampot/shiva.git shiva-installer
cd shiva-installer
./install.sh
# Follow install prompts.

# Configure Shiva:
cd shiva
nano shiva.conf
# Set Receiver IP address to NAT'd AWS address.
# Set MySQL creds.
# Disable HPFeeds.
# Disable notification.
python dbcreate.py
sudo nano /etc/exim4/update-exim4.conf.conf
# Disable IPv6:
# dc_local_interfaces='127.0.0.1'
sudo sh setup_exim4.sh

# Redirect port 25 to 2525:
sudo su
iptables -D nat -A PREROUTING -p tcp --dport 25 -j REDIRECT --to-port 2525
iptables-save > /etc/iptables.rules
echo '#!/bin/sh' >> /etc/network/if-up.d/iptablesload 
echo 'iptables-restore < /etc/iptables.rules' >> /etc/network/if-up.d/iptablesload 
echo 'exit 0' >> /etc/network/if-up.d/iptablesload
chmod +x /etc/network/if-up.d/iptablesload

Starting Shiva
""""""""""""""
# Start reciever:
cd /opt/shiva-installer/shiva/shivaReceiver/
source bin/activate
cd receiver
lamson start
exit
# Start analyzer:
cd /opt/shiva-installer/shiva/shivaAnalyzer/
source bin/activate
cd analyzer/
lamson start
exit


Stopping Shiva
""""""""""""""
# Stop Receiver:
cd /opt/shiva-installer/shiva/shivaReceiver/
source bin/activate
cd receiver/
lamson stop

# Stop Receiver:
cd /opt/shiva-installer/shiva/shivaAnalyzer/
source bin/activate
cd analyzer/
lamson stop


Interacting with DB
"""""""""""""""""""
mysql -D Shiva -u root -p
> Enter root password.

# Table layout:

+-----------------+
| Tables_in_Shiva |
+-----------------+
| attachment      |
| inline          |
| ip              |
| ip_spam         |
| links           |
| relay           |
| sdate           |
| sdate_spam      |
| sensor          |
| sensor_spam     |
| spam            |
| whitelist       |
+-----------------+
