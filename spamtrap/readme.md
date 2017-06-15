## Email Honeypot (SpamTrap) Setup ##

#### Preparation ####
- Devise an organisational identity. Consider industries that are currently highly targeted, for example:
    - Political parties
    - Critical infrastructure.
    - Managed Service Providers.
- Produce a static HTML site that will form the public presence of your organisation. Ensure that you embed your email addresses in the site wherever possible.
- Register a domain to be used for creating your organisation's identity. Ensure that your registrar provides WHOIS masking, or that the body who manages and administers the TLD is able to provide this service. If not - choose a different TLD.
- Spin up an EC2 Micro Ubuntu instance.
- Obtain the public IP of the instance and configure the following A record's for your domain that will resolve to it:

*\<naked\>  
www  
mail*

For example:

example.com  
www.example.com  
mail.example.com

- Also configure an MX record (for the naked domain, e.g. example.com) that resolves to mail.<your domain\> (e.g. mail.domain.com).

#### Setup ####
- Upgrade the box:

*apt update && apt upgrade*

- Install Mail-in-a-Box:

*curl -s https://mailinabox.email/setup.sh | sudo bash*

- Follow the installation instructions. Ensure that you record any credentials that you set up in your password manager.
- SCP your static web files to /home/user-data/www/default/ - they will become accessible at https://<your domain\>, which will redirect to https://www.<your domain\>
- Stop Spam Assassin:

*/etc/init.d/spamassassin stop*

- Disable Spam Assassin:

*update-rc.d spamassassin disable*

- Edit the following lines in /etc/postfix/main.cf:

\#smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination    
smtpd_relay_restrictions=permit_sasl_authenticated,permit_mynetworks,reject_unauth_destination

\#mydestination = ...  
mydestination=localhost

\#virtual_transport=lmtp:\[127.0.0.1\]:10025
virtual_transport=lmtp:\[127.0.0.1\]:10026-

\#smtpd_sender_restrictions=reject_non_fqdn_sender,reject_unknown_sender_domain,reject_authenticated_sender_login_mismatch,reject_rhsbl_sender dbl.spamhaus.org
\#smtpd_recipient_restrictions=permit_sasl_authenticated,permit_mynetworks,reject_rbl_client zen.spamhaus.org,reject_unlisted_recipient,check_policy_service inet:127.0.0.1:10023  
smtpd_recipient_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination
smtpd_sender_restrictions = 

- Reboot the box (easy way to restart everything).
- To complete the setup, visit https://mail.<your domain\>/admin
    - Log in with the administrative credentials that you configured during the setup.
    - Work through any issues identified by the status checks.
    - Navigate to System > External DNS. Ensure that all of the listed records are defined in your DNS registrar/provider zone configuration.
    - Navigate to System > TLS (SSL) Certificates. Issue certificates using Lets Encrypt for all of your domains. Optional: use your own CA issued certificates. Important: do not use self-signed certificates.
    - Navigate to Mail > Aliases. Create a 'Catch-All' alias for your domain that forwards to admin@\<your domain\> (e.g. admin@example.com). This will send mail to ANY alias that you make to admin@\<your domain\>, without the requirement to make an inbox for it.
- Log on to the webmail interface using admin@\<your domain\> and the password you configured during setup, at https://mail.<your domain\>/mail
    - Send and receive some test emails. Ensure that you include Windows Live and Gmail in your tests.

#### Operation ####
Some ideas on how to seed your addresses into the world wide interwebs are:

- Add your site to popular search engines like Google and Yandex.
- Sign up to newsletters, subscribe to newsgroups and then create filters for the sender addresses of the newsletters that will send legitimate email straight into the trash.
- Sign up to Social Networking sites like LinkedIn, Twitter, Facebook and forums related to your chosen industry. Make your email address public, and include a link to your website if possible. Make a few comments here and there.
- Create fake dumps on Pastebin that contain your email addresses.
- Submit your email addresses and fake credentials to phishing sites listed on https://www.phishtank.com

If you wish to send mail whilst assuming a specific identity, first log in to the webmail interface using the administrative account and navigate to Settings (top-right) then select the 'Identities' tab. At the bottom of the Identities pane is a '+' icon that will load a form allowing you to create a new sender identity. You can select the identity when composing an email.


## Open Relay Setup ##

Official Shiva documentation: https://github.com/shiva-spampot/shiva/blob/master/docs/User%20Manual.pdf

- Install pre-req's:

*sudo apt-get install python-dev exim4-daemon-light g++ python-virtualenv libmysqlclient-dev libffi-dev libfuzzy-dev mysql-server mysql-client make automake autoconf*

- Record the MySQL root password.
- Make base directory:

*cd /opt  
sudo mkdir shiva-installer  
sudo chown ubuntu:ubuntu shiva-installer*

- Fetch and install Shiva:

*git clone https://github.com/shiva-spampot/shiva.git shiva-installer  
cd shiva-installer  
./install.sh*

- Follow install prompts.
- Configure Shiva:

*cd shiva  
nano shiva.conf*

- Set Receiver IP address to NAT'd AWS address.
- Set MySQL creds.
- Optional: Disable HPFeeds.
- Optional: Disable notification.

*python dbcreate.py
sudo nano /etc/exim4/update-exim4.conf.conf*

- Disable IPv6:  

\# dc_local_interfaces='127.0.0.1'
sudo sh setup_exim4.sh

- Redirect port 25 to 2525:

*iptables -D nat -A PREROUTING -p tcp --dport 25 -j REDIRECT --to-port 2525  
iptables-save > /etc/iptables.rules  
echo '#!/bin/sh' >> /etc/network/if-up.d/iptablesload   
echo 'iptables-restore < /etc/iptables.rules' >> /etc/network/if-up.d/iptablesload  
echo 'exit 0' >> /etc/network/if-up.d/iptablesload  
chmod +x /etc/network/if-up.d/iptablesload*

#### Starting Shiva ####
- Start reciever:

*cd /opt/shiva-installer/shiva/shivaReceiver/  
source bin/activate  
cd receiver  
lamson start  
exit*

- Start analyzer:

*cd /opt/shiva-installer/shiva/shivaAnalyzer/  
source bin/activate  
cd analyzer/  
lamson start  
exit*

#### Stopping Shiva ####
- Stop Receiver:

*cd /opt/shiva-installer/shiva/shivaReceiver/  
source bin/activate  
cd receiver/  
lamson stop* 

- Stop Receiver:

*cd /opt/shiva-installer/shiva/shivaAnalyzer/  
source bin/activate  
cd analyzer/  
lamson stop*

#### Interacting with the DB ####
- Run:

*mysql -D Shiva -u root -p*

- Enter root password.
