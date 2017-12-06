#!/usr/bin/env python

import os
import sys
from datetime import (datetime, timedelta)

import requests
import mysql.connector

GET_DEVICES = 'select e.id, e.mac, e.vendor, e.ip, e.last_seen_at ' \
              'from nm_device_events e ' \
              'inner join (select mac, max(connected_at) as latest from nm_device_events group by mac) d ' \
              'on e.mac = d.mac and e.connected_at = d.latest;'

INSERT_EVENT = 'insert into nm_device_events (mac, vendor, ip, connected_at) ' \
               'values (%(mac)s, %(vendor)s, %(ip)s, now());'

UPDATE_SEEN_AT = 'update nm_device_events set last_seen_at = now() where id in (%s);'

IFTTT_MAKER_URL = 'https://maker.ifttt.com/trigger/network_event/with/key/%s' % os.environ['IFTTT_API_KEY']
MACVENDOR_URL = 'https://api.macvendors.com/'


def create_device_event(data):
    cursor.execute(INSERT_EVENT, data)
    cnx.commit()


def update_seen_at(rows_to_update):
    enough_blanks = ', '.join(['%s'] * len(rows_to_update))
    cursor.execute(UPDATE_SEEN_AT % enough_blanks, rows_to_update)
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
        print('notification error: %s' % str(resp))


def main():
    known_devices = {device['mac']: device for device in get_known_devices()}

    seen_devices = []

    # loop through nmap output
    for scanned_device in scan.split('Nmap scan'):
        ip = 'x.x.x.x'
        for i, line in enumerate(scanned_device.splitlines()):
            if i is 0 and 'report for ' in line:
                ip = line.split()[-1]
            elif i is 2 and 'MAC Address:' in line:
                mac_addr = line.split()[2]
                vendor = ' '.join(line.split()[3:])[1:-1]

                device_data = {'mac': mac_addr, 'vendor': vendor, 'ip': ip}
                prev_event = known_devices[mac_addr] if mac_addr in known_devices else None

                if prev_event is None:
                    # we've never seen this device before
                    print('new device connected: %s' % mac_addr)
                    create_device_event(device_data)
                    send_telegram_notification({'value1': str(vendor), 'value2': str(ip), 'value3': str(mac_addr)})
                elif prev_event['last_seen_at'] < dt_stale or prev_event['ip'] != ip:
                    # this is a known device that has reconnected
                    create_device_event(device_data)
                else:
                    # this is a known device that's still connected
                    seen_devices.append(prev_event['id'])

    # update last_seen_at on all still-connected devices
    if seen_devices:
        update_seen_at(seen_devices)


if __name__ == '__main__':
    dt_now = datetime.now()
    dt_stale = dt_now - timedelta(minutes=2)
    print('starting scan at %s' % dt_now)

    # this expects `nmap -sn 10.0.1.0/24` to be run as a superuser and piped in
    scan = sys.stdin.read()

    cnx = get_database_connection()
    cursor = cnx.cursor(dictionary=True)

    main()

    cursor.close()
