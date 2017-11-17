#!/usr/bin/env bash

cd /opt/home/$1/dev/network_monitor
. .env
nmap -sn 10.0.1.0/24 | python3 run.py
