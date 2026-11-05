"""0.3.0 user controls applied around the compare: rule action overrides (L7), what-if items on B,
row states (exclude / not needed), scope prefix checks."""
import hashlib
import ipaddress
import re

from .model import Interface, Nat, Route
from .netset import IPSet
from .compare import block_name, scope_split

UNKNOWN = 'unknown'          # L7 rule whose real action is not visible (suspect block name, not confirmed)
L7BLOCK = 'l7block'          # L7 rule confirmed as block: permits nothing, denies nothing (its L7 condition is unknown)
DROPPED = 'ignore'
NOT_PERMIT = (UNKNOWN, L7BLOCK, DROPPED)
STATUS = {UNKNOWN: 'action unknown (L7)', L7BLOCK: 'blocked (L7)'}


def apply_rule_actions(cfg, prof, tag=''):
    """per-rule action override by rule name ('Name' or '<tag>:Name'); L7 rules whose name looks like a block
    become 'unknown' until confirmed. Returns the list of rules with a changed action."""
    acts = {k: v.lower() for k, v in (prof.rule_actions or {}).items()}
    out = []
    for r in cfg.rules:
        name = r.rule_name or ''
        a = acts.get('%s:%s' % (tag, name)) if tag else None
        a = a or acts.get(name)
        r.orig_action = r.action
        if a == 'permit':
            r.action, r.override = 'permit', 'permit'
        elif a == 'block':
            r.action, r.override = (L7BLOCK if getattr(r, 'l7', False) else 'deny'), 'block'
        elif a == 'ignore':
            r.action, r.override = DROPPED, 'ignore'
        elif prof.l7_suspect and getattr(r, 'l7', False) and r.action == 'permit' and block_name(name, prof.l7_suspect):
            r.action, r.override = UNKNOWN, 'suspect block name'
        else:
            continue
        out.append(r)
    return out


def held_rows(cfgs, prof, scope):
    """rules tab rows for rules whose action is unknown / L7 block (they take no part in the compare)"""
    rows = []
    for cfg, tag in cfgs:
        for r in cfg.rules:
            if r.action not in STATUS or not (r.src.overlaps(scope) or r.dst.overlaps(scope)):
                continue
            name = ('%s:%s' % (tag, r.rule_name)) if tag else r.rule_name
            rows.append({'id': 'H%s%d' % (tag, r.seq), 'key': 'held|%s|%s' % (tag, _h(r.line)), 'path': tag or 'A',
                         'policy': r.policy, 'rule': name, 'rule_id': r.rule_id, 'action': r.orig_action,
                         'src_ifc': r.src_ifc or 'any', 'dst_ifc': r.dst_ifc or 'any', 'src': r.src_ref, 'dst': r.dst_ref,
                         'service': r.svc_ref, 'scope': prof.scope_label(r.src | r.dst),
                         'scopes': scope_split(prof, r.src, r.dst)[0], 'scopes_any': scope_split(prof, r.src, r.dst)[1],
                         'status': STATUS[r.action], 'detail': 'override: %s' % getattr(r, 'override', ''), 'l7': True,
                         'b_rules': [], 'line': r.line})
    return rows


def _h(text):
    return hashlib.sha1((text or '').encode()).hexdigest()[:12]


def apply_whatif(B, prof):
    """add planned interfaces, routes, NAT pools to B; returns change items"""
    w = prof.whatif or {}
    changes = []
    for i in w.get('interfaces', []):
        name = i['name'] if isinstance(i, dict) else str(i)
        role = i.get('role', 'inside') if isinstance(i, dict) else 'inside'
        if name not in B.interfaces:
            B.interfaces[name] = Interface(name='planned', nameif=name, planned=True)
            changes.append({'kind': 'interface', 'item': name, 'detail': 'create interface %s (%s) on B' % (name, role)})
        if role == 'outside' and prof.outside_b and name not in prof.outside_b:
            prof.outside_b.append(name)
    for r in w.get('routes', []):
        n = ipaddress.IPv4Network(r['prefix'], strict=False)
        nh = r.get('nexthop', '') or 'planned'
        B.routes.append(Route(ifc=r['ifc'], network=str(n.network_address), mask=str(n.netmask), nexthop=nh,
                              distance=int(r.get('distance', 1))))
        changes.append({'kind': 'route', 'item': '%s -> %s' % (n, r['ifc']),
                        'detail': 'route %s %s %s %s' % (r['ifc'], n.network_address, n.netmask, nh)})
    for p in w.get('public', []):
        changes.append({'kind': 'public range', 'item': p, 'detail': 'B public range %s (assumed available)' % p})
    for i, p in enumerate(w.get('nat_pools', [])):
        real = IPSet.parse(p['real'])
        iface = p.get('mapped', 'interface') in ('', 'interface')
        mapped = None if iface else IPSet.parse(p['mapped'])
        B.nats.append(Nat(seq=9000 + i, section='manual-after', real_ifc=p.get('in_ifc', 'INSIDE'),
                          mapped_ifc=p.get('out_ifc', 'OUTSIDE'), kind='dynamic', pat=True, real=real, mapped=mapped,
                          real_ref=p['real'], mapped_ref=p.get('mapped', 'interface') or 'interface',
                          mapped_interface=iface, description='planned', line='planned nat pool %s' % p['real']))
        changes.append({'kind': 'nat pool', 'item': p['real'],
                        'detail': 'nat (%s,%s) after-auto source dynamic %s %s' % (
                            p.get('in_ifc', 'INSIDE'), p.get('out_ifc', 'OUTSIDE'), p['real'], p.get('mapped') or 'interface')})
    if hasattr(B, '_rt'):
        del B._rt
    return changes


def row_keys(res):
    """stable key per row (survives re-runs with other scopes / settings)"""
    for k in ('rules', 'b_rules', 'nat', 'b_nat', 'inbound', 'routing', 'objects', 'b_objects', 'dns', 'public', 'pat',
              'held_rules'):
        for r in res.get(k, []):
            if 'key' in r:
                continue
            if k == 'rules':
                rule = r.get('_rule')
                origin = getattr(rule, 'origin', None) if rule is not None else None
                r['key'] = 'rule|%s|%s' % (r.get('path', ''), origin or _h(r.get('line', '')))
            elif k in ('nat', 'b_nat', 'b_rules'):
                r['key'] = '%s|%s' % (k, _h(r.get('line', '')))
            elif k == 'inbound':
                r['key'] = 'inbound|%s' % r['object']
            elif k == 'routing':
                r['key'] = 'routing|%s' % r['subnet']
            elif k in ('objects', 'b_objects'):
                r['key'] = '%s|%s' % (k, r['name'])
            elif k == 'dns':
                r['key'] = 'dns|%s' % r['host']
            else:
                r['key'] = '%s|%s' % (k, r.get('id', ''))


def apply_row_state(res, prof):
    """exclude / not needed: the row stays listed with its state, and leaves the counts and the summary"""
    st = prof.row_state or {}
    n = 0
    for k in ('rules', 'b_rules', 'nat', 'b_nat', 'inbound', 'routing', 'objects', 'b_objects', 'dns', 'public', 'pat',
              'held_rules'):
        for r in res.get(k, []):
            s = st.get(r.get('key'))
            if s:
                r['row_state'] = s.get('state', 'exclude')
                r['row_reason'] = s.get('reason', '')
                n += 1
    return n


def scope_checks(prof, prefix_sources):
    """warn when a scope prefix overlaps a known connected/static/object prefix of another length with the same
    network address or that contains it; offer that prefix. prefix_sources: [(cidr, where)]"""
    out = []
    for p in prof.scope:
        net = ipaddress.IPv4Network(p, strict=False)
        seen = set()
        for cidr, where in prefix_sources:
            other = ipaddress.IPv4Network(cidr, strict=False)
            if other == net or other.prefixlen == 0 or (cidr, where) in seen:
                continue
            if (other.supernet_of(net) or other.subnet_of(net)) and other.network_address == net.network_address \
                    and 'connected' in where:
                seen.add((cidr, where))
                out.append({'prefix': p, 'other': cidr, 'where': where, 'suggest': cidr,
                            'message': '%s is %s; scope has %s' % (cidr, where, p)})
    return out
