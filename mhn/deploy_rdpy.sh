set -e
set -x

if [ $# -ne 2 ]
    then
        echo "Wrong number of arguments supplied."
        echo "Usage: $0 <server_url> <deploy_key>."
        exit 1
fi

server_url=$1
deploy_key=$2

# Prepare OS:
cd /root
apt update
apt upgrade -y
apt install -y build-essential python python-dev git libffi-dev openssl libssl-dev supervisor

# Install PIP:
wget https://bootstrap.pypa.io/get-pip.py
python get-pip.py
rm get-pip.py

# Install Python dependencies:
pip install cffi hpfeeds twisted pyopenssl qt4reactor service_identity rsa pyasn1

# Pull RDPY fork:
cd /opt
git clone https://github.com/phage-nz/rdpy
cd rdpy
python setup.py install

# Prepare RDPY configuration:
mkdir pki
SERVER_ID="WIN-$(cat /dev/urandom | tr -dc 'A-Z0-9' | fold -w 11 | head -n 1)"
openssl req -nodes -x509 -newkey rsa:2048 -keyout pki/key.pem -out pki/cert.pem -days 1095 -subj "/CN=$SERVER_ID'"
mkdir rss
wget https://github.com/dtag-dev-sec/tpotce/raw/master/docker/rdpy/dist/1 -O rss/1
wget https://github.com/dtag-dev-sec/tpotce/raw/master/docker/rdpy/dist/2 -O rss/2
wget https://github.com/dtag-dev-sec/tpotce/raw/master/docker/rdpy/dist/3 -O rss/3
mkdir /var/log/rdpy

# Register the sensor with the MHN server.
wget $server_url/static/registration.txt -O registration.sh
chmod 755 registration.sh
# Note: this will export the HPF_* variables
. ./registration.sh $server_url $deploy_key "rdpy"

# Store local IP:
CLIENT_IP=$(ifconfig | sed -En 's/127.0.0.1//;s/.*inet (addr:)?(([0-9]*\.){3}[0-9]*).*/\2/p')

# Config for supervisor.
cat > /etc/supervisor/conf.d/rdpy-rdphoneypot.conf <<EOF
[program:rdpy-rdphoneypot]
command=rdpy-rdphoneypot.py -k /opt/rdpy/pki/key.pem -c /opt/rdpy/pki/cert.pem /opt/rdpy/rss/$(shuf -i 1-3 -n 1)
environment = 
    HPFEEDS_SERVER=$HPF_HOST,
    HPFEEDS_IDENT=$HPF_IDENT,
    HPFEEDS_SECRET=$HPF_SECRET,
    HPFEEDS_PORT=$HPF_PORT,
    HPFEEDS_CHANNEL=rdpy.events,
    HPFEEDS_CLIENT=$CLIENT_IP
stdout_logfile=/var/log/rdpy/rdpy.out
stderr_logfile=/var/log/rdpy/rdpy.err
autostart=true
autorestart=true
redirect_stderr=true
stopsignal=QUIT
EOF

supervisorctl update

