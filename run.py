#!/usr/bin/env python

import os
import sys
from datetime import datetime

import requests
import mysql.connector

GET_DEVICES = 'select e.mac, e.vendor, e.ip, e.status ' \
              'from nm_device_events e ' \
              'inner join (select mac, max(created_at) as latest from nm_device_events group by mac) d ' \
              'on e.mac = d.mac and e.created_at = d.latest;'

INSERT_EVENT = 'insert into nm_device_events (mac, vendor, ip, status, created_at) ' \
               'values (%(mac)s, %(vendor)s, %(ip)s, %(status)s, now());'

IFTTT_MAKER_URL = 'https://maker.ifttt.com/trigger/network_event/with/key/%s' % os.environ['IFTTT_API_KEY']
MACVENDOR_URL = 'https://api.macvendors.com/'


def create_device_event(data):
    cursor.execute(INSERT_EVENT, data)
    cnx.commit()


def get_known_devices():
    cursor.execute(GET_DEVICES)
    devices = cursor.fetchall()
    cnx.commit()

    return devices


def get_database_connection():
    return mysql.connector.connect(
        host=os.environ['NM_HOST'],
        user=os.environ['NM_USER'],
        password=os.environ['NM_PASSWORD'],
        database=os.environ['NM_DATABASE'],
        port=os.environ['NM_PORT'],
    )


def send_telegram_notification(payload):
    resp = requests.post(IFTTT_MAKER_URL, json=payload)
    if resp.status_code is 200:
        print('notification sent!')
    else:
        print('notification error :(')


def main():
    known_devices = {}
    known_macs = []
    devices = get_known_devices()
    for device in devices:
        mac = device['mac']
        known_devices[mac] = device
        known_macs.append(mac)

    seen_devices = []

    # loop through nmap output
    for scanned_device in scan.split('Nmap scan'):
        ip = 'x.x.x.x'
        for i, line in enumerate(scanned_device.splitlines()):
            if i is 0 and 'report for 10.' in line:
                ip = line.split()[-1]
            elif i is 2 and 'MAC Address:' in line:
                mac_addr = line.split()[2]
                seen_devices.append(mac_addr)
                vendor = ' '.join(line.split()[3:])[1:-1]

                device_data = {'mac': mac_addr, 'vendor': vendor, 'ip': ip, 'status': 1}
                prev_event = known_devices[mac_addr] if mac_addr in known_devices else None

                # we've never seen this device before
                if prev_event is None:
                    print('NEW DEVICE CONNECTED: %s' % mac_addr)
                    create_device_event(device_data)
                    send_telegram_notification({'value1': str(vendor), 'value2': str(ip), 'value3': str(mac_addr)})
                # this is a known device but it just reconnected
                elif not prev_event['status']:
                    print('reconnected device: %s' % mac_addr)
                    create_device_event(device_data)

    # now loop through known devices to check for disconnection
    for known_mac, known_device in known_devices.items():
        if known_device['status'] is 1 and known_mac not in seen_devices:
            print('disconnected device: %s' % known_device['mac'])

            known_device['status'] = 0
            create_device_event(known_device)


if __name__ == '__main__':
    print('starting scan at %s' % datetime.now())

    # this expects `nmap -sn 10.0.1.0/24` to be run as a superuser and piped in
    scan = sys.stdin.read()

    cnx = get_database_connection()
    cursor = cnx.cursor(dictionary=True)

    main()

    cursor.close()
