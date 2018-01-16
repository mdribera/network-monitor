# network-monitor
**Periodically scan hosts on local network and report unknown devices**

### SETUP
- Install pip dependencies: `pip install -r requirement.txt`
- Install command line utility [nmap](https://nmap.org/download.html)
- Put database and notification secrets in a `/.env` file (which will be utilized by `/scan.sh` and `/docker-compose.yml`)
- Create a database with table schema found in `/database` (you can use Docker `docker-compose up`)
- Run `/scan.sh` through crontab or other execution scheduler on home server:
```
*/1 * * * * /bin/sh /path/to/network-monitor/scan.sh 10.0.1.0/24
```
- Profit $$$
