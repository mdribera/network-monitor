#!/usr/bin/env bash

cd $(dirname -- "$0")
export $(cat .env | grep -v ^# | xargs)
nmap -sn $1 | python3 run.py
