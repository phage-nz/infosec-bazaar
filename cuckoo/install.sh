#!/bin/bash

JANSSON_REPO="https://github.com/akheron/jansson"
YARA_REPO="https://github.com/plusvic/yara"
VOLATILITY_ARCHIVE="http://downloads.volatilityfoundation.org/releases/2.4/volatility-2.4.tar.gz"
CUCKOO_REPO="https://github.com/spender-sandbox/cuckoo-modified"

WIN7_LOCATION="WINDOWS 7 MOUNT POINT"
WIN7_SERIAL="YOUR SERIAL"
OFFICE2007_ISO="OFFICE 2007 ISO PATH"
OFFICE2007_SERIAL="YOUR SERIAL"

ECHO "* Installing pre-requisites..."

apt-get install python-pip python-sqlalchemy mongodb python-bson python-dpkt python-jinja2 python-magic python-gridfs python-libvirt python-bottle python-pefile python-chardet git build-essential autoconf automake libtool dh-autoreconf libcurl4-gnutls-dev libmagic-dev python-dev tcpdump libcap2-bin virtualbox dkms python-pyrex libfuzzy-dev genisoimage
pip install pymongo django pydeep maec py3compat lxml cybox distorm3 pycrypto vmcloak suricata

pip install --upgrade pip

cp /etc/suricata/suricata-debian.yaml /etc/suricata/suricata-cuckoo.yaml

cd ~
git clone https://github.com/seanthegeek/etupdate
cp etupdate/etupdate /usr/sbin
/usr/sbin/etupdate -V
rm -rf etupdate
crontab -l | { cat; echo "30 * * * * /usr/sbin/etupdate"; } | crontab -

cd ~
git clone $JANSSON_REPO
cd jansson
autoreconf -vi --force
./configure
make
make check
make install
cd ~
rm -rf jansson

git clone $YARA_REPO
cd yara
./bootstrap.sh
autoreconf -vi --force
./configure --enable-cuckoo --enable-magic
make
make install
cd yara-python/
python setup.py install
cd ~
rm -rf yara

wget $VOLATILITY_ARCHIVE
tar xvf volatility-2.4.tar.gz
cd volatility-2.4
python setup.py build
python setup.py install
cd ~
rm -rf volatility-2.4

echo "* Cloning Cuckoo and additional modules..."

cd /opt
git clone $CUCKOO_REPO cuckoo
git clone $CUCKOO_MODULE_REPO
cp -R community-modified/modules cuckoo

echo "* Patching Django..."

python -c "import django; from distutils.version import LooseVersion; import sys; sys.exit(LooseVersion(django.get_version()) <= LooseVersion('1.5'))" && { 
    egrep -i "templates = \(.*\)" cuckoo/web/web/settings.py || $SUDO sed -i '/TEMPLATE_DIRS/{ N; s/.*/TEMPLATE_DIRS = \( \("templates"\),/; }' cuckoo/web/web/settings.py
}

echo "* Setting up networking..."

vboxmanage hostonlyif create
iptables -A FORWARD -o eth0 -i vboxnet0 -s 192.168.56.0/24 -m conntrack --ctstate NEW -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A POSTROUTING -t nat -j MASQUERADE
sysctl -w net.ipv4.ip_forward=1
/bin/bash -c 'setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump' 2>&/dev/null

echo "* Creating a Windows 7 VM..."

vmcloak init -d --win7x86 --iso-mount $WIN7_LOCATION --serial-key $WIN7_SERIAL
vmcloak install win7 adobe9 wic pillow dotnet40 firefox_41 java7 silverlight5 pil chrome iexplore removetooltips windows_cleanup winrar
vmcloak install win7 office2007 office2007.isopath=$OFFICE2007_ISO office2007.serialkey=$OFFICE2007_SERIAL
vmcloak clone win7 win7a1

echo "* 'win7' is now your working template. DO NOT snapshot it."

vmcloak snapshot win7a1 cuckoo1 192.168.56.101

echo "* Manually start the 'win7a1' VM and:"
echo "* - Double Check networking."
echo "* - Configure Office macro security."
echo "* - Apply any other modifications you wish."
echo "* - Take a snapshot named 'Snapshot1'."

echo "* Complete the setup by tweaking the Suricata and Cuckoo configuration files. Refer to readme.txt for more information."

echo "* Finished!"