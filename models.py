from typing import Optional
from pydantic import BaseModel

class port_forwarding_rule(BaseModel):
    name: str
    group: Optional[str] = None
    proto: int
    dst_ip: str
    dst_port: Optional[str] = None
    src_port: str
    enabled: bool

class incoming_allow_rule(BaseModel):
    name: str
    group: Optional[str] = None
    proto: int
    port: str
    enabled: bool

class incoming_block_rule(BaseModel):
    name: str
    group: Optional[str] = None
    ip: str
    enabled: bool

class outgoing_block_rule(BaseModel):
    name: str
    group: Optional[str] = None
    proto: int
    ip: str
    port: str
    enabled: bool
