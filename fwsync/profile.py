"""Comparison profile (JSON / YAML). Optional: every empty field is auto-detected from the configs (fwsync.detect)."""
import json
import re
from dataclasses import dataclass, field
from typing import Dict, List
from .netset import IPSet


@dataclass
class Profile:
    name: str = 'default'
    type: str = 'auto'                   # auto | standard | shared-edge (one public subnet on both sides: mapped IPs must match)
    scope: List[str] = field(default_factory=list)
    scope_names: Dict[str, str] = field(default_factory=dict)   # prefix -> label (e.g. VLAN 10)
    interface_map: Dict[str, str] = field(default_factory=dict)  # A nameif -> B nameif
    outside_a: List[str] = field(default_factory=list)          # A internet-facing nameifs
    outside_b: List[str] = field(default_factory=list)
    public_a: List[str] = field(default_factory=list)            # A public ranges; empty = derive from A config
    public_b: List[str] = field(default_factory=list)            # B public ranges; empty = derive from B config
    public_map: Dict[str, str] = field(default_factory=dict)     # A public IP -> B public IP
    public_pool_b: List[str] = field(default_factory=list)       # auto-assign B public IPs from here
    rename: List[Dict[str, str]] = field(default_factory=list)   # [{"pattern": "...", "replace": "..."}]
    zone_map: Dict[str, str] = field(default_factory=dict)       # B nameif -> FMC security zone (payloads)
    fmc: Dict[str, str] = field(default_factory=dict)            # access_policy, nat_policy names (payloads)
    scope_add: Dict[str, str] = field(default_factory=dict)      # prefix -> name, added to the scope (auto or given)
    roles_a: Dict[str, str] = field(default_factory=dict)        # A nameif -> outside | inside | chain link | ignore
    whatif: Dict[str, list] = field(default_factory=dict)        # planned on B: routes, public, interfaces, nat_pools
    rule_actions: Dict[str, str] = field(default_factory=dict)   # rule name -> permit | block | ignore
    l7_suspect: str = r'(?i)\b(block|blocklist|blocked|deny|denied|drop|reject|unwanted)\b|trojan|stratum miner'
    row_state: Dict[str, Dict[str, str]] = field(default_factory=dict)
    names: Dict[str, str] = field(default_factory=dict)          # A / B / A1 / A2 display names, e.g. "Edge (FW-A)"
    finding_state: Dict[str, Dict[str, str]] = field(default_factory=dict)   # finding key -> {state: fix|not needed|later, reason}
    decision_state: Dict[str, Dict[str, str]] = field(default_factory=dict)  # decision id -> {choice, rule|finding|pool}   # row key -> {state: exclude|not needed, reason}

    @classmethod
    def load(cls, path):
        """JSON (.json) or YAML (.yaml / .yml, needs PyYAML: pip install fwsync[yaml])"""
        from .osutil import read_text
        text = read_text(path)
        if str(path).lower().endswith(('.yaml', '.yml')):
            import yaml
            d = yaml.safe_load(text) or {}
        else:
            d = json.loads(text)
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})

    def _parsed(self):
        key = tuple(self.scope)
        if getattr(self, '_pc', (None,))[0] != key:
            self._pc = (key, [(p, IPSet.parse(p)) for p in self.scope])
        return self._pc[1]

    def scope_set(self):
        s = IPSet()
        for p, x in self._parsed():
            s = s | x
        return s

    def scope_keys(self, ipset):
        return [p for p, x in self._parsed() if ipset.overlaps(x)]

    def scope_label(self, ipset):
        return ', '.join(self.scope_names.get(p, p) for p in self.scope_keys(ipset))

    def to_dict(self):
        return {k: getattr(self, k) for k in self.__dataclass_fields__}

    def map_ifc(self, name):
        if name is None:
            return None
        return self.interface_map.get(name, name)

    def rename_obj(self, name):
        for r in self.rename:
            name = re.sub(r['pattern'], r['replace'], name)
        return name

    def reversed(self):
        p = Profile(**self.to_dict())
        p.interface_map = {v: k for k, v in self.interface_map.items()}
        p.outside_a, p.outside_b = self.outside_b, self.outside_a
        p.public_map = {v: k for k, v in self.public_map.items()}
        p.public_a, p.public_b = self.public_b, self.public_a
        p.public_pool_b = []
        p.name = self.name + ' (reversed)'
        return p
