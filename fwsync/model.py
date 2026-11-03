"""Vendor-neutral firewall model. Every adapter fills a Config; the compare engine only reads Config."""
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from .netset import IPSet, Service


@dataclass
class Interface:
    name: str                 # physical / logical name, e.g. Port-channel1.46
    nameif: str = ''
    ip: str = ''
    mask: str = ''
    vlan: Optional[int] = None
    shutdown: bool = False
    standby: str = ''
    security_level: Optional[int] = None
    planned: bool = False      # what-if: interface to be created on B
    management_only: bool = False


@dataclass
class Route:
    ifc: str
    network: str
    mask: str
    nexthop: str
    distance: int = 1
    track: Optional[int] = None


@dataclass
class NetObject:
    name: str
    kind: str                 # host | subnet | range | fqdn | group
    value: str                # text as configured
    addrs: IPSet = field(default_factory=IPSet)
    members: List[str] = field(default_factory=list)   # groups: member object names and literals
    description: str = ''


@dataclass
class SvcObject:
    name: str
    kind: str                 # service | group | port-group
    value: str
    svc: Service = field(default_factory=Service)
    members: List[str] = field(default_factory=list)


@dataclass
class Rule:
    seq: int
    acl: str
    action: str               # permit | deny | trust
    src_ifc: Optional[str]    # None = any
    dst_ifc: Optional[str]
    src: IPSet
    dst: IPSet
    svc: Service
    src_ref: str = ''         # text of the source as configured (object names)
    dst_ref: str = ''
    svc_ref: str = ''
    rule_id: str = ''
    policy: str = ''
    rule_name: str = ''
    inactive: bool = False
    line: str = ''


@dataclass
class Nat:
    seq: int
    section: str              # manual-before | auto | manual-after
    real_ifc: str
    mapped_ifc: str
    kind: str                 # static | dynamic
    pat: bool
    real: IPSet
    mapped: Optional[IPSet]   # None for interface PAT
    real_ref: str = ''
    mapped_ref: str = ''
    mapped_interface: bool = False
    dst_real: Optional[IPSet] = None
    dst_mapped: Optional[IPSet] = None
    service: str = ''
    inactive: bool = False
    description: str = ''
    obj: str = ''             # object NAT: owning object
    line: str = ''


@dataclass
class Config:
    name: str
    vendor: str
    hostname: str = ''
    interfaces: Dict[str, Interface] = field(default_factory=dict)   # by nameif
    routes: List[Route] = field(default_factory=list)
    objects: Dict[str, NetObject] = field(default_factory=dict)
    services: Dict[str, SvcObject] = field(default_factory=dict)
    rules: List[Rule] = field(default_factory=list)
    nats: List[Nat] = field(default_factory=list)
    access_groups: Dict[str, str] = field(default_factory=dict)      # acl -> 'global' | 'in <ifc>' ...
    warnings: List[str] = field(default_factory=list)
    dynamic_routing: List[str] = field(default_factory=list)          # e.g. 'router bgp 64512'
    route_fn: Optional[object] = None
    ignored: set = field(default_factory=set)                         # nameifs mapped to "ignore"                                 # combined (2:1) configs: custom route lookup

    def summary(self):
        return {'name': self.name, 'vendor': self.vendor, 'hostname': self.hostname,
                'interfaces': len(self.interfaces), 'routes': len(self.routes), 'objects': len(self.objects),
                'service_objects': len(self.services), 'rules': len(self.rules), 'nats': len(self.nats),
                'warnings': len(self.warnings)}
