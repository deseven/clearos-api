from typing import Optional
from fastapi import FastAPI, Security, HTTPException
from fastapi.responses import HTMLResponse
from starlette import status
from security import *
from models import *
from clearos_firewall import *

CLEAROS_API_VER = "0.1.0"

app = FastAPI()

@app.get("/",response_class=HTMLResponse)
def read_root():
    return (
        "Welcome to ClearOS API ver. " + 
        CLEAROS_API_VER + '!<br>' +
        'Browse docs at <a href="/docs">/docs</a>, visit <a href="https://github.com/deseven/clearos-api">github</a> for more info.'
    )

### ClearOS Firewall - incoming allow ###

@app.get('/firewall/incoming-allow',dependencies=[Security(get_api_key)])
def incoming_allow():
    return {"incoming-allow": getFirewall(TYPE_INCOMING_ALLOW)}

@app.post('/firewall/incoming-allow',dependencies=[Security(get_api_key)])
def incoming_allow_post(rule: incoming_allow_rule):
    if existsFirewall(rule.name,TYPE_INCOMING_ALLOW):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Rule with name '" + rule.name + "' already exists"
        )

    fw_rule = generateFirewall(rule,TYPE_INCOMING_ALLOW)
    if insertFirewall(fw_rule):
        return rule
    else:
        raise HTTPException(
            status_code=status.HTTP_418_IM_A_TEAPOT,
            detail="Failed inserting rule (unsupported or broken firewall config?)"
        )

@app.delete('/firewall/incoming-allow',dependencies=[Security(get_api_key)])
def incoming_allow_delete(rule: incoming_allow_rule):
    fw_rule = generateFirewall(rule,TYPE_INCOMING_ALLOW)
    if deleteFirewall(fw_rule):
        return rule
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found (" + fw_rule + ")"
        )


### ClearOS Firewall - incoming block ###

@app.get('/firewall/incoming-block',dependencies=[Security(get_api_key)])
def incoming_block():
    return {"incoming-block": getFirewall(TYPE_INCOMING_BLOCK)}

@app.post('/firewall/incoming-block',dependencies=[Security(get_api_key)])
def incoming_block_post(rule: incoming_block_rule):
    if existsFirewall(rule.name,TYPE_INCOMING_BLOCK):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Rule with name '" + rule.name + "' already exists"
        )

    fw_rule = generateFirewall(rule,TYPE_INCOMING_BLOCK)
    if insertFirewall(fw_rule):
        return rule
    else:
        raise HTTPException(
            status_code=status.HTTP_418_IM_A_TEAPOT,
            detail="Failed inserting rule (unsupported or broken firewall config?)"
        )

@app.delete('/firewall/incoming-block',dependencies=[Security(get_api_key)])
def incoming_block_delete(rule: incoming_block_rule):
    fw_rule = generateFirewall(rule,TYPE_INCOMING_BLOCK)
    if deleteFirewall(fw_rule):
        return rule
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found (" + fw_rule + ")"
        )


### ClearOS Firewall - outgoing block ###

@app.get('/firewall/outgoing-block',dependencies=[Security(get_api_key)])
def outgoing_block():
    return {"outgoing-block": getFirewall(TYPE_OUTGOING_BLOCK)}

@app.post('/firewall/outgoing-block',dependencies=[Security(get_api_key)])
def outgoing_block_post(rule: outgoing_block_rule):
    if existsFirewall(rule.name,TYPE_OUTGOING_BLOCK):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Rule with name '" + rule.name + "' already exists"
        )

    fw_rule = generateFirewall(rule,TYPE_OUTGOING_BLOCK)
    if insertFirewall(fw_rule):
        return rule
    else:
        raise HTTPException(
            status_code=status.HTTP_418_IM_A_TEAPOT,
            detail="Failed inserting rule (unsupported or broken firewall config?)"
        )

@app.delete('/firewall/outgoing-block',dependencies=[Security(get_api_key)])
def outgoing_block_delete(rule: outgoing_block_rule):
    fw_rule = generateFirewall(rule,TYPE_OUTGOING_BLOCK)
    if deleteFirewall(fw_rule):
        return rule
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found (" + fw_rule + ")"
        )


### ClearOS Firewall - port forwarding ###

@app.get('/firewall/port-forwarding',dependencies=[Security(get_api_key)])
def port_forwarding():
    return {"port-forwarding": getFirewall(TYPE_FORWARDING)}

@app.post('/firewall/port-forwarding',dependencies=[Security(get_api_key)])
def port_forwarding_post(rule: port_forwarding_rule):
    if existsFirewall(rule.name,TYPE_FORWARDING):
        raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Rule with name '" + rule.name + "' already exists"
        )
    
    fw_rule = generateFirewall(rule,TYPE_FORWARDING)
    if insertFirewall(fw_rule):
        return rule
    else:
        raise HTTPException(
            status_code=status.HTTP_418_IM_A_TEAPOT,
            detail="Failed inserting rule (unsupported or broken firewall config?)"
        )

@app.delete('/firewall/port-forwarding',dependencies=[Security(get_api_key)])
def port_forwarding_delete(rule: port_forwarding_rule):
    fw_rule = generateFirewall(rule,TYPE_FORWARDING)
    if deleteFirewall(fw_rule):
        return rule
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found (" + fw_rule + ")"
        )
