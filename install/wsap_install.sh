#!/bin/sh

#Install Python3 and Required Modules
echo "Installing Python3 and Required Modules"
sudo apt-get install python3 -y
sudo apt-get install python3-pip -y
python3 -m pip install -U pip
sudo apt-get install python3-setuptools -y
pip install python-owasp-zap-v2.4

echo "Creating the work enviroment"
#Installing DAST_ZAP
echo "Installing DAST_ZAP"
TMPDIR=$(mktemp -d)
if [ ! -e $TMPDIR ]; then
    >&2 echo "Failed to create temp directory"
    exit 1
fi
trap "exit 1"           HUP INT PIPE QUIT TERM
trap 'rm -rf "$TMPDIR"' EXIT

wget -P $TMPDIR "https://github.com/zaproxy/zaproxy/releases/download/v2.10.0/ZAP_2_10_0_unix.sh"

chmod 555 "$TMPDIR/ZAP_2_10_0_unix.sh"
cd "$TMPDIR"
sudo "./ZAP_2_10_0_unix.sh"
sudo "./ZAP_2_10_0_unix.sh" #Running twice to create symblink

#Installing SQLMAP EXTENSION: SQLLITE FOR DAST_ZAP
echo "Installing SQLMAP EXTENSION: SQLLITE FOR DAST_ZAP"
zap.sh -addoninstall sqliplugin 

#Installing DAST_WAPITI
cd ~
git clone https://github.com/wapiti-scanner/wapiti.git
chmod 555 wapiti/*
cd wapiti
sudo python3 setup.py install

#Installing SAST_INSIDER
cd ~
wget https://github.com/insidersec/insider/releases/download/3.0.0/insider_3.0.0_linux_x86_64.tar.gz -O insider.tar
mkdir insider && tar xf insider.tar -C insider
chmod 555 insider
cd $HOME/insider
cp insider $HOME/.local/bin/


