#!/bin/bash

function __launch() {
    python3 /var/lib/sshmanager/main.py $*
}

__launch $*