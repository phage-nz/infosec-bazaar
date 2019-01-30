#!/bin/bash

# Yeti AutoInstall Script v0.1.0
#
# Derived from: https://github.com/yeti-platform/yeti/blob/master/extras/ubuntu_bootstrap.sh

INSTALL_DIR="$(pwd)"

echo "[?] What FQDN will Yeti be accessed using?"
read YETI_FQDN

echo "[?] How many days worth of observables do you want to ingest for feeds that employ no date limit (e.g. URLhaus)?"
read AGE_LIMIT

echo "[?] What is your Google Sheets API key? (for APT Groups and Operations spreadsheet)."
echo "[+] You can make one here: https://developers.google.com/sheets/api/quickstart/python"
read GOOGLE_KEY

echo "[?] What is your AlienVault OTX API key?"
echo "[+] You can find it here: https://otx.alienvault.com/settings"
read OTX_KEY

echo "[?] What is your CleanMX User Agent?"
echo "[+] You can apply for one here: http://support.clean-mx.com/"
echo "[+] If you do not have one, enter some junk and ensure to disable the plugin."
read CLEANMX_AGENT

# Google Sheets key for the APT Groups and Operations sheet (http://apt.threattracking.com):
TRACKER_KEY="1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU"

echo "[+] Preparing the OS..."

export LC_ALL="en_US.UTF-8"

if [ -f "/usr/bin/apt" ]; then
   APT="/usr/bin/apt"
else
   APT="/usr/bin/apt-get"
fi

$APT update -y
$APT install dirmngr

add-apt-repository ppa:certbot/certbot -y

curl -sSL https://deb.nodesource.com/gpgkey/nodesource.gpg.key | sudo apt-key add -
echo "deb https://deb.nodesource.com/node_6.x $(lsb_release -s -c) main" | sudo tee /etc/apt/sources.list.d/node.list

curl -sSL https://dl.yarnpkg.com/debian/pubkey.gpg | apt-key add -
echo "deb https://dl.yarnpkg.com/debian/ stable main" | tee /etc/apt/sources.list.d/yarn.list

# https://docs.mongodb.com/manual/tutorial/install-mongodb-on-ubuntu/
apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 9DA31620334BD75D9DCB49F368818C72E52529D4

# https://wiki.ubuntu.com/Releases
OS_CODENAME=`lsb_release -c --short`

if [ $OS_CODENAME == "bionic" ] || [ $OS_CODENAME == "artful" ] || [ $OS_CODENAME == "zesty" ] || [ $OS_CODENAME == "yakkety" ] || [ $OS_CODENAME == "xenial" ]; then
  echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu xenial/mongodb-org/4.0 multiverse" | tee /etc/apt/sources.list.d/mongodb-org-4.0.list
elif [ $OS_CODENAME == "wily" ] || [ $OS_CODENAME == "vivid" ] || [ $OS_CODENAME == "utopic" ] || [ $OS_CODENAME == "trusty" ]; then
  echo "deb [ arch=amd64 ] https://repo.mongodb.org/apt/ubuntu trusty/mongodb-org/4.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-4.0.list
else
  echo "[!] Installing on an unsupported or outdated version of Ubuntu, trying Trusty package for Mongo"
  echo "deb [ arch=amd64 ] https://repo.mongodb.org/apt/ubuntu trusty/mongodb-org/4.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-4.0.list
fi

$APT update -y
$APT install build-essential git python-dev mongodb-org redis-server libcurl3 libxml2-dev libxslt-dev zlib1g-dev python-certbot-nginx python-virtualenv python-pip python3-pip nginx yarn nodejs -y

echo "[+] Pulling latest release of Yeti..."
cd /opt
git clone https://github.com/yeti-platform/yeti.git

echo "[+] Patching some files..."
cd /opt/yeti
sed -i "s/pysocks==1.6.8 ; extra == 'socks'/pysocks==1.6.8/g" requirements.txt
sed -i 's/timedelta(minutes=5)/timedelta(hours=1)/g' plugins/feeds/public/hybrid_analysis.py
sed -i 's/timedelta(minutes=20)/timedelta(hours=1)/g' plugins/feeds/public/urlhaus.py

echo "[+] Preparing Yeti configuration file..."
cp yeti.conf.sample yeti.conf
echo -e "\n[limits]\nmax_age = $AGE_LIMIT\n" >> yeti.conf
echo -e "\n[threattracking]\ngoogle_api_key = $GOOGLE_KEY\nsheet_key = $TRACKER_KEY\n" >> yeti.conf
echo -e "\n[otx]\napi_key = $OTX_KEY\n" >> yeti.conf
echo -e "\n[cleanmx]\nuser_agent = $CLEANMX_AGENT\n" >> yeti.conf

echo "[+] Disabling unused plugins..."
mkdir plugins/feeds/disabled
mv plugins/feeds/public/asprox_tracker.py plugins/feeds/disabled
mv plugins/feeds/public/feodo_tracker.py plugins/feeds/disabled

echo "[+] Enabling custom plugins..."
cp $INSTALL_DIR/res/*.py plugins/feeds/public

echo "[+] Installing Yeti requirements..."
pip install setuptools wheel
pip3 install pyasn1
pip install -r requirements.txt
pip install hammock OTXv2 uwsgi validators
yarn install

echo "[+] Configuring Yeti services..."
useradd yeti
cp extras/systemd/*.service /etc/systemd/system/
systemctl enable mongod.service
systemctl enable yeti_uwsgi.service
systemctl enable yeti_oneshot.service
systemctl enable yeti_feeds.service
systemctl enable yeti_exports.service
systemctl enable yeti_analytics.service
systemctl enable yeti_beat.service
systemctl daemon-reload
chown -R yeti:yeti /opt/yeti
chmod +x /opt/yeti/yeti.py

echo "[+] Configuring NGINX..."
rm /etc/nginx/sites-enabled/default
cp $INSTALL_DIR/res/yeti_nginx.conf /etc/nginx/sites-available/yeti
sed -i "s/your.fqdn.here/$YETI_FQDN/g" /etc/nginx/sites-available/yeti
ln -s /etc/nginx/sites-available/yeti /etc/nginx/sites-enabled/yeti
service nginx restart

echo "[+] Starting Yeti services..."
systemctl start mongod.service
systemctl start yeti_oneshot.service
sleep 5
systemctl start yeti_feeds.service
systemctl start yeti_exports.service
systemctl start yeti_analytics.service
systemctl start yeti_beat.service
systemctl start yeti_uwsgi.service

echo "[+] Yeti succesfully installed. Webserver listening on TCP/80"
echo "[+] Configure HTTPS by running:"
echo "certbot --nginx -d <FQDN>"
echo "service nginx restart"
