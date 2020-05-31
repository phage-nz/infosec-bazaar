#!/bin/bash

# Install must be done as root.
if [ "$EUID" -ne 0 ]
  then echo "Please run as root!"
  exit 1
fi

# Install main dependencies.
echo "Updating server..."
apt update
apt upgrade -y

echo "Installing main dependencies..."
apt install build-essential flex libewf-dev libssl-dev python-pip python-distorm3 python-openpyxl python-pil python-ujson python-yara yara -y
pip install --upgrade pip
pip install pycrypto pytz

# Install Volatility.
echo "Installing Volatility..."
cd /opt
git clone https://github.com/volatilityfoundation/volatility.git python-volatility
cd python-volatility
python setup.py build
python setup.py install
cd /tmp
wget http://downloads.volatilityfoundation.org/releases/2.6/volatility_2.6_lin64_standalone.zip
unzip volatility_2.6_lin64_standalone.zip
cd volatility_2.6_lin64_standalone
mv volatility_2.6_lin64_standalone /usr/bin/volatility
cd ..
rm -rf volatility_2.6_lin64_standalone

# Install bulk_extractor.
echo "Installing bulk_extractor..."
git clone https://github.com/simsong/bulk_extractor
cd bulk_extractor
chmod +x bootstrap.sh
./bootstrap.sh
./configure
make
make install

# Fetch Crowd Strike's vshot script.
echo "Fetching vshot script..."
cd /opt
mkdir vshot
cd vshot
wget https://raw.githubusercontent.com/CrowdStrike/Forensics/master/vshot -O vshot.sh
chmod +x vshot.sh
cd ..

echo "Volatility install complete! You can run 'volatility' direct from the command line, or 'vshot.sh' in /opt/vshot"
