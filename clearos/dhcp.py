DHCP_ETHERS_PATH = '/etc/ethers'
DHCP_LEASES_PATH = '/var/lib/dnsmasq/dnsmasq.leases'

def getLeases():
    leases = []

    with open(DHCP_LEASES_PATH,'r') as f:
        for line in f.readlines():
            line = line.strip('\t\r\n ')
            if not (len(line) == 0 or line.startswith("#")) and ' ' in line:
                time, mac, ip, hostname, client_id = line.split(' ',4)
                leases.append({
                    "mac":       mac,
                    "ip":        ip,
                    "time":      int(time),
                    "hostname":  hostname,
                    "client_id": client_id,
                    "static":    False
                })

    with open(DHCP_ETHERS_PATH,'r') as f:
        for line in f.readlines():
            lease_found = False
            line = line.strip('\t\r\n ')
            if not (len(line) == 0 or line.startswith("#")) and ' ' in line:
                mac, ip = line.split(' ',1)
                for i,lease in enumerate(leases):
                    if lease['mac'] == mac and lease['ip'] == ip:
                        leases[i]['static'] = True
                        lease_found = True
                        break
                if not lease_found:
                    leases.append({
                        "mac":       mac,
                        "ip":        ip,
                        "time":      0,
                        "hostname":  '',
                        "client_id": '',
                        "static":    True
                    })

    return leases

def insertLease(mac,ip):
    with open(DHCP_ETHERS_PATH,'a') as f:
        f.write(mac + ' ' + ip + "\n")

def deleteLease(mac,ip):
    with open(DHCP_ETHERS_PATH,'r') as f:
        lines = f.readlines()

    lease = mac + ' ' + ip
    success = False
    i = 0
    for line in lines:
        if line == lease or line == lease + "\n": # TODO: make more checks
            success = True
            break
        i += 1

    if success:
        lines.pop(i)

    with open(DHCP_ETHERS_PATH,'w') as f:
        lines = "".join(lines)
        f.write(lines)

    return success

def existsLease(mac):
    for lease in getLeases():
        if lease['mac'] == mac and lease['static'] == True:
            return True