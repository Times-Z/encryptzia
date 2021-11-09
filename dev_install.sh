#!/bin/bash

sudo mkdir -p /tmp/app/var/lib/encryptzia
sudo cp -R ./app/* /tmp/app/var/lib/encryptzia
sudo mkdir -p /tmp/app/usr/local/bin
sudo mkdir -p /tmp/app/usr/share/icons
sudo mkdir -p /tmp/app/usr/share/applications
sudo cp ./build/Encryptzia.desktop /tmp/app/usr/share/applications/Encryptzia.desktop
sudo cp ./build/encryptzia.png /tmp/app/usr/share/icons/encryptzia.png
sudo cp ./build/launcher.sh /tmp/app/usr/local/bin/encryptzia
sudo cp -R ./build/DEBIAN /tmp/app
sudo chmod 755 -R /tmp/app
sudo dpkg-deb -b /tmp/app /tmp/encryptzia.deb
echo 'sudo apt install /tmp/encryptzia.deb'