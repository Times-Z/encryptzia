#!/bin/bash

sudo mkdir -p /tmp/app/var/lib/sshmanager
sudo cp -R ./app/* /tmp/app/var/lib/sshmanager
sudo mkdir -p /tmp/app/usr/local/bin
sudo cp ./build/launcher.sh /tmp/app/usr/local/bin/sshmanager
sudo cp -R ./build/DEBIAN /tmp/app
sudo chmod 755 -R /tmp/app
sudo dpkg-deb -b /tmp/app /tmp/game.deb
echo 'sudo apt install /tmp/game.deb'