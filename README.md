# ClearOS API
Since [ClearOS](https://www.clearos.com/) own API in its current state (ClearOS 7.9) is completely useless, I decided to make a 3rd-party one to be able to control at least some parts of configuration with easy to use API. For now only firewall module is supported with the following functionality:
 - get the list of firewall rules (incoming allow, incoming block, outgoing block, port forwarding)
 - add a rule (incoming allow, incoming block, outgoing block, port forwarding)
 - remove a rule (incoming allow, incoming block, outgoing block, port forwarding)

The API is completely separated from the main system and designed to be as non-intrusive as possible.

## Installation
First of all, install required dependencies:
```bash
yum install gcc python3-devel
pip3 install fastapi
pip3 install uvicorn[standard]
```

Then clone this repo (there are no releases as of now):
```bash
cd /opt
git clone https://github.com/deseven/clearos-api.git
cd clearos-api
```

Edit `config.py` to set up api key and header (if needed). Also edit `systemd/clearos-api.service` if you want to change the port and/or binding address (by default it listens on port 1999 on all interfaces).

Finally, add the api to systemd, enable autostart and launch it:
```bash
cp systemd/clearos-api.service /etc/systemd/system
systemctl daemon-reload
systemctl enable clearos-api
systemctl start clearos-api
```

## Usage
Go to http://your-clearos-installation:1025 and read the docs there.  
Don't forget to check that the port is opened in ClearOS itself. By the way you can open it from the api on ClearOS host, just perform this simple request (change the api key and port according to your configuration):
```bash
curl http://localhost:1999/firewall/incoming-allow \
  -d '{"name":"clearos-api","proto":6,"port":"1999","enabled":true}' \
  -X POST -H 'x-api-key: 1234567asdfgh' -H "Content-Type: application/json"
```
Keep in mind that there's little to no checks of what you're doing with firewall configuration, don't lock yourself out!