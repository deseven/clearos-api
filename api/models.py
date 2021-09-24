from typing import Optional,List
from pydantic import BaseModel


### Firewall models ###

class FW_IncomingAllow(BaseModel):
    name:    str
    group:   Optional[str] = None
    proto:   int
    port:    str
    enabled: bool

class FW_IncomingAllows(BaseModel):
    incoming_allow: List[FW_IncomingAllow]

class FW_IncomingBlock(BaseModel):
    name:    str
    group:   Optional[str] = None
    ip:      str
    enabled: bool

class FW_IncomingBlocks(BaseModel):
    incoming_block: List[FW_IncomingBlock]

class FW_OutgoingBlock(BaseModel):
    name:    str
    group:   Optional[str] = None
    proto:   int
    ip:      str
    port:    str
    enabled: bool

class FW_OutgoingBlocks(BaseModel):
    outgoing_block: List[FW_OutgoingBlock]

class FW_PortForwarding(BaseModel):
    name:     str
    group:    Optional[str] = None
    proto:    int
    dst_ip:   str
    dst_port: Optional[str] = None
    src_port: str
    enabled:  bool

class FW_PortForwardings(BaseModel):
    port_forwarding: List[FW_PortForwarding]


### DHCP models ###

class DHCP_Lease(BaseModel):
    mac:       str
    ip:        str
    time:      Optional[int] = 0
    hostname:  Optional[str] = None
    client_id: Optional[str] = None
    static:    bool

class DHCP_Leases(BaseModel):
    leases: List[DHCP_Lease]

class DHCP_StaticLease(BaseModel):
    mac: str
    ip:  str