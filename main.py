from typing import Optional
from fastapi import FastAPI, Security, HTTPException
from fastapi.responses import HTMLResponse
from starlette import status

# api
from api.security import *
from api.models import *

# clearos
from clearos.firewall import *
from clearos.dhcp import *

CLEAROS_API_VER = "0.1.0"

app = FastAPI(
    title="ClearOS API",
    description="API for ClearOS 7",
    version=CLEAROS_API_VER,
    contact={
        "name": "deseven",
        "url": "https://github.com/deseven/clearos-api/",
        "email": "github@d7.wtf",
    },
    license_info={
        "name": "Unlicense",
        "url": "https://github.com/deseven/clearos-api/blob/master/LICENSE",
    }
)

@app.get("/",response_class=HTMLResponse)
def read_root():
    return (
        "Welcome to ClearOS API ver. " + 
        CLEAROS_API_VER + '!<br>' +
        'Browse docs at <a href="/docs">/docs</a>, visit <a href="https://github.com/deseven/clearos-api">github</a> for more info.'
    )


### ClearOS Firewall - incoming allow ###

@app.get('/firewall/incoming-allow',dependencies=[Security(get_api_key)],response_model=FW_IncomingAllows,tags=['firewall'])
def incoming_allow():
    return {"incoming_allow": getFirewall(FIREWALL_INCOMING_ALLOW)}

@app.post('/firewall/incoming-allow',dependencies=[Security(get_api_key)],response_model=FW_IncomingAllow,tags=['firewall'])
def incoming_allow_post(rule: FW_IncomingAllow):
    if existsFirewall(rule.name,FIREWALL_INCOMING_ALLOW):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Rule with name '" + rule.name + "' already exists"
        )

    fw_rule = generateFirewall(rule,FIREWALL_INCOMING_ALLOW)
    if insertFirewall(fw_rule):
        return rule
    else:
        raise HTTPException(
            status_code=status.HTTP_418_IM_A_TEAPOT,
            detail="Failed inserting rule (unsupported or broken firewall config?)"
        )

@app.delete('/firewall/incoming-allow',dependencies=[Security(get_api_key)],response_model=FW_IncomingAllow,tags=['firewall'])
def incoming_allow_delete(rule: FW_IncomingAllow):
    fw_rule = generateFirewall(rule,FIREWALL_INCOMING_ALLOW)
    if deleteFirewall(fw_rule):
        return rule
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found (" + fw_rule + ")"
        )


### ClearOS Firewall - incoming block ###

@app.get('/firewall/incoming-block',dependencies=[Security(get_api_key)],response_model=FW_IncomingBlocks,tags=['firewall'])
def incoming_block():
    return {"incoming_block": getFirewall(FIREWALL_INCOMING_BLOCK)}

@app.post('/firewall/incoming-block',dependencies=[Security(get_api_key)],response_model=FW_IncomingBlock,tags=['firewall'])
def incoming_block_post(rule: FW_IncomingBlock):
    if existsFirewall(rule.name,FIREWALL_INCOMING_BLOCK):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Rule with name '" + rule.name + "' already exists"
        )

    fw_rule = generateFirewall(rule,FIREWALL_INCOMING_BLOCK)
    if insertFirewall(fw_rule):
        return rule
    else:
        raise HTTPException(
            status_code=status.HTTP_418_IM_A_TEAPOT,
            detail="Failed inserting rule (unsupported or broken firewall config?)"
        )

@app.delete('/firewall/incoming-block',dependencies=[Security(get_api_key)],response_model=FW_IncomingBlock,tags=['firewall'])
def incoming_block_delete(rule: FW_IncomingBlock):
    fw_rule = generateFirewall(rule,FIREWALL_INCOMING_BLOCK)
    if deleteFirewall(fw_rule):
        return rule
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found (" + fw_rule + ")"
        )


### ClearOS Firewall - outgoing block ###

@app.get('/firewall/outgoing-block',dependencies=[Security(get_api_key)],response_model=FW_OutgoingBlocks,tags=['firewall'])
def outgoing_block():
    return {"outgoing_block": getFirewall(FIREWALL_OUTGOING_BLOCK)}

@app.post('/firewall/outgoing-block',dependencies=[Security(get_api_key)],response_model=FW_OutgoingBlock,tags=['firewall'])
def outgoing_block_post(rule: FW_OutgoingBlock):
    if existsFirewall(rule.name,FIREWALL_OUTGOING_BLOCK):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Rule with name '" + rule.name + "' already exists"
        )

    fw_rule = generateFirewall(rule,FIREWALL_OUTGOING_BLOCK)
    if insertFirewall(fw_rule):
        return rule
    else:
        raise HTTPException(
            status_code=status.HTTP_418_IM_A_TEAPOT,
            detail="Failed inserting rule (unsupported or broken firewall config?)"
        )

@app.delete('/firewall/outgoing-block',dependencies=[Security(get_api_key)],response_model=FW_OutgoingBlock,tags=['firewall'])
def outgoing_block_delete(rule: FW_OutgoingBlock):
    fw_rule = generateFirewall(rule,FIREWALL_OUTGOING_BLOCK)
    if deleteFirewall(fw_rule):
        return rule
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found (" + fw_rule + ")"
        )


### ClearOS Firewall - port forwarding ###

@app.get('/firewall/port-forwarding',dependencies=[Security(get_api_key)],response_model=FW_PortForwardings,tags=['firewall'])
def port_forwarding():
    return {"port_forwarding": getFirewall(FIREWALL_FORWARDING)}

@app.post('/firewall/port-forwarding',dependencies=[Security(get_api_key)],response_model=FW_PortForwarding,tags=['firewall'])
def port_forwarding_post(rule: FW_PortForwarding):
    if existsFirewall(rule.name,FIREWALL_FORWARDING):
        raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Rule with name '" + rule.name + "' already exists"
        )
    
    fw_rule = generateFirewall(rule,FIREWALL_FORWARDING)
    if insertFirewall(fw_rule):
        return rule
    else:
        raise HTTPException(
            status_code=status.HTTP_418_IM_A_TEAPOT,
            detail="Failed inserting rule (unsupported or broken firewall config?)"
        )

@app.delete('/firewall/port-forwarding',dependencies=[Security(get_api_key)],response_model=FW_PortForwarding,tags=['firewall'])
def port_forwarding_delete(rule: FW_PortForwarding):
    fw_rule = generateFirewall(rule,FIREWALL_FORWARDING)
    if deleteFirewall(fw_rule):
        return rule
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found (" + fw_rule + ")"
        )


### ClearOS DHCP - leases ###

@app.get('/dhcp/leases',dependencies=[Security(get_api_key)],response_model=DHCP_Leases,tags=['dhcp'])
def leases():
    return {"leases": getLeases()}

@app.post('/dhcp/static-lease',dependencies=[Security(get_api_key)],response_model=DHCP_StaticLease,tags=['dhcp'])
def static_lease(lease: DHCP_StaticLease):
    if existsLease(lease.mac):
        raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Static lease for mac '" + lease.mac + "' already exists"
        )

    insertLease(lease.mac,lease.ip)
    return lease

@app.delete('/dhcp/static-lease',dependencies=[Security(get_api_key)],response_model=DHCP_StaticLease,tags=['dhcp'])
def static_lease_delete(lease: DHCP_StaticLease):
    if deleteLease(lease.mac,lease.ip):
        return lease
    else:
        raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Static lease for mac '" + lease.mac + "' not found"
        )