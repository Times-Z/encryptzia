#!/bin/bash

function __launch() {
    python3 /var/lib/encryptzia/main.py $*
}

__launch $*