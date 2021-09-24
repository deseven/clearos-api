FIREWALL_FORWARDING = 1
FIREWALL_INCOMING_ALLOW = 2
FIREWALL_INCOMING_BLOCK = 3
FIREWALL_OUTGOING_BLOCK = 4
FIREWALL_CFG_PATH = '/etc/clearos/firewall.conf'

def getFirewall(fw_type):
    with open(FIREWALL_CFG_PATH,'r') as f:
        lines = f.readlines()
        lines = [line.strip('\t\r\n\\ ') for line in lines]

    rules = []
    rules_started = False
    for line in lines:
        if rules_started and line == '"':
            break
        if rules_started:
            rule = line.split('|')
            if fw_type == FIREWALL_INCOMING_ALLOW and rule[2].endswith('1'):
                rules.append({
                    "name":    rule[0],
                    "group":   rule[1],
                    "proto":   int(rule[3]),
                    "port":    rule[5],
                    "enabled": (True if rule[2][2] == '1' else False)
                })
            if fw_type == FIREWALL_INCOMING_BLOCK and rule[2].endswith('2'):
                rules.append({
                    "name":    rule[0],
                    "group":   rule[1],
                    "ip":      rule[4],
                    "enabled": (True if rule[2][2] == '1' else False)
                })
            if fw_type == FIREWALL_OUTGOING_BLOCK and rule[2].endswith('4'):
                rules.append({
                    "name":    rule[0],
                    "group":   rule[1],
                    "proto":   int(rule[3]),
                    "ip":      rule[4],
                    "port":    rule[5],
                    "enabled": (True if rule[2][2] == '1' else False)
                })
            if fw_type == FIREWALL_FORWARDING and rule[2].endswith('8'):
                rules.append({
                    "name":     rule[0],
                    "group":    rule[1],
                    "proto":    int(rule[3]),
                    "dst_ip":   rule[4],
                    "dst_port": rule[5],
                    "src_port": rule[6],
                    "enabled":  (True if rule[2][2] == '1' else False)
                })
        if line == 'RULES="':
            rules_started = True
    return rules

def deleteFirewall(rule):
    with open(FIREWALL_CFG_PATH,'r') as f:
        lines = f.readlines()

    success = False
    i = 0
    for line in lines:
        if line == "\t" + rule + " \\\n": # TODO: make more checks
            success = True
            break
        i += 1

    if success:
        lines.pop(i)

    with open(FIREWALL_CFG_PATH,'w') as f:
        lines = "".join(lines)
        f.write(lines)

    return success

def insertFirewall(rule):
    with open(FIREWALL_CFG_PATH,'r') as f:
        lines = f.readlines()

    success = False
    i = 0
    for line in lines:
        i += 1
        if line.startswith('RULES="'):
            success = True
            break

    if success:
        lines.insert(i,"\t" + rule + " \\\n")
    
    with open(FIREWALL_CFG_PATH,'w') as f:
        lines = "".join(lines)
        f.write(lines)

    return success

def generateFirewall(rule,fw_type):
    fw_rule = ""

    if fw_type == FIREWALL_INCOMING_ALLOW:
        fw_rule = "|".join([
            rule.name,
            (rule.group if rule.group else ""),
            ("0x10000001" if rule.enabled else "0x00000001"),
            str(rule.proto),
            "",
            rule.port,
            ""
        ])

    if fw_type == FIREWALL_INCOMING_BLOCK:
        fw_rule = "|".join([
            rule.name,
            (rule.group if rule.group else ""),
            ("0x10000002" if rule.enabled else "0x00000002"),
            "0",
            rule.ip,
            "",
            ""
        ])

    if fw_type == FIREWALL_OUTGOING_BLOCK:
        fw_rule = "|".join([
            rule.name,
            (rule.group if rule.group else ""),
            ("0x10000004" if rule.enabled else "0x00000004"),
            str(rule.proto),
            rule.ip,
            rule.port,
            ""
        ])

    if fw_type == FIREWALL_FORWARDING:
        fw_rule = "|".join([
            rule.name,
            (rule.group if rule.group else ""),
            ("0x10000008" if rule.enabled else "0x00000008"),
            str(rule.proto),
            rule.dst_ip,
            (rule.dst_port if rule.dst_port else ""),
            rule.src_port
        ])

    return fw_rule

def existsFirewall(name,fw_type):
    for rule in getFirewall(fw_type):
        if rule['name'] == name:
            return True