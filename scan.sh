#!/usr/bin/env bash

cd $(dirname -- "$0")
. .env
nmap -sn 10.0.1.0/24 | python3 run.py
