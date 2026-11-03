"""fwsync command line.
  fwsync compare A.txt B.txt --out DIR [--prefix NAME]              1:1, everything auto-detected
  fwsync compare A1.txt A2.txt B.txt --out DIR                      2:1 (edge + inner firewall -> B)
        [--profile p.yaml] [--scope 10.0.0.0/8,...] [--ignore-ifc vpn1,A1:vpn2] [--public-b 192.0.2.0/24]
        [--reverse] [--parts rules,nat,objects,routing,reverse]
  fwsync detect A.txt [A2.txt] B.txt [--save-profile p.json]        show what was inferred
  fwsync web [--port N] [--no-browser]                              127.0.0.1 only, first free port from 8765
  fwsync push PLAN.json --fmc https://192.0.2.10 --user admin [--apply] --allow-push   (experimental, not in the UI)
FMC REST API (read-only user for reading; nothing is ever deployed):
  fwsync fmc-read --fmc URL --user RO --device NAME | --policy ACP [--nat NAT] --out snap.json
  fwsync compare fmc:device:NAME fmc:device:NAME2 --fmc URL --user RO --out DIR      (or snapshot files, or a mix)
  fwsync fmc-copy --fmc URL --user RO --from device:A --to device:B [--write-user W] [--parts objects,routes,nat,rules]
        [--rules NAME,..] [--map AIFC=BIFC] --out DIR [--apply --allow-push]   (dry run unless --apply)
  fwsync fmc-undo UNDO.json --fmc URL --write-user W --out DIR [--apply --allow-push]
Passwords: env FWSYNC_FMC_PASSWORD / FWSYNC_FMC_WRITE_PASSWORD, --cred FILE (JSON user/password, owner-only) or a prompt.
TLS: verified by default; --ca-bundle FILE (or profile fmc.ca_bundle, or env FWSYNC_CA_BUNDLE) for an FMC / corporate CA;
--insecure turns verification off (isolated lab only). HTTPS_PROXY / NO_PROXY are honoured."""
import argparse
import getpass
import json
import os
import sys
import time
from pathlib import Path

from .pipeline import read, run
from . import gaps
from .osutil import console_utf8, read_text, write_text
from .profile import Profile
from .report import write_all


def _prof(args):
    prof = Profile.load(args.profile) if args.profile else Profile()
    if args.scope:
        prof.scope = args.scope.split(',')
    for n in (args.ignore_ifc or '').split(','):
        if n.strip():
            prof.interface_map[n.strip()] = 'ignore'
    if args.public_b:
        prof.public_b = args.public_b.split(',')
    for kv in args.map or []:
        a, b = _kv(kv)
        prof.interface_map[a] = b
    for kv in args.role or []:
        a, b = _kv(kv)
        prof.roles_a[a] = b
    for kv in args.scope_add or []:
        p, n = (kv.split('=', 1) + [''])[:2]
        prof.scope_add[p] = n
    w = prof.whatif
    for kv in args.whatif_route or []:
        p, rest = _kv(kv)
        ifc, nh = (rest.split('@', 1) + [''])[:2]
        w.setdefault('routes', []).append({'prefix': p, 'ifc': ifc, 'nexthop': nh})
    for p in args.whatif_public or []:
        w.setdefault('public', []).append(p)
    for kv in args.whatif_ifc or []:
        n, role = (kv.split('=', 1) + ['inside'])[:2]
        w.setdefault('interfaces', []).append({'name': n, 'role': role})
    for kv in args.whatif_nat or []:
        real, rest = _kv(kv)
        mapped, ifs = (rest.split('@', 1) + ['INSIDE,OUTSIDE'])[:2]
        i, o = (ifs.split(',') + ['OUTSIDE'])[:2]
        w.setdefault('nat_pools', []).append({'real': real, 'mapped': mapped, 'in_ifc': i, 'out_ifc': o})
    for state, items in (('exclude', args.exclude), ('not needed', args.not_needed)):
        for kv in items or []:
            k, why = (kv.split('=', 1) + [''])[:2]
            prof.row_state[k] = {'state': state, 'reason': why}
    for kv in args.name or []:
        k, v = kv.split('=', 1)
        prof.names[k.strip()] = v.strip()
    for kv in args.finding or []:
        k, v = kv.split('=', 1)
        st, why = (v.split(':', 1) + [''])[:2]
        if st == 'not needed' and not why:
            sys.exit('--finding %s: "not needed" needs a reason (not needed:REASON)' % kv)
        prof.finding_state[k] = {'state': st, 'reason': why}
    for kv in args.decision or []:
        k, v = kv.split('=', 1)
        prof.decision_state[k] = {'choice': v}
    for kv in args.rule_action or []:
        n, a = _kv(kv)
        if a not in ('permit', 'block', 'ignore'):
            sys.exit('--rule-action %s: action must be permit, block or ignore' % kv)
        prof.rule_actions[n] = a
    return prof


def _kv(text):
    if '=' not in text:
        sys.exit('expected NAME=VALUE, got %r' % text)
    a, b = text.rsplit('=', 1)
    return a.strip(), b.strip()


def print_detected(res, out=sys.stdout):
    d = res['detected']
    w = out.write
    w('mode %s, site type %s, %d scope subnets\n' % (d['mode'], res['profile_used']['type'], len(res['scope'])))
    w('interface map (A -> B):\n')
    for r in d['interface_map']:
        w('  %-22s %-7s -> %-14s %-22s %s\n' % (r['a'], r['a_role'], r['b'] or '-', r['how'],
                                               ' '.join(x for x in (r['flag'], r.get('note', '')) if x)))
    w('B roles: %s\n' % ', '.join('%s=%s (%s)' % (k, v[0], v[1]) for k, v in d['roles_b'].items()))
    for side in ('a', 'b'):
        p = d['public_' + side]
        w('public %s: %s  (interfaces %s; %d mapped addresses)\n' % (side.upper(), ', '.join(p['ranges']) or '-',
                                                                    ', '.join(p['interfaces']) or '-', p['mapped_count']))
    c = d.get('chain')
    if c:
        w('chain: edge A1 = %s, inner A2 = %s, A1 -> A2 via %s, A2 uplink %s %s\n' % (
            c['edge'], c['inner'], c['a1_toward_a2'], c['a2_uplink'], c.get('note', '')))
        for p in c['paths']:
            w('  %s (A2 %s, A1 via %s): %s\n' % (p['subnets'], p['a2_ifc'], p['a1_ifc'], p['path']))
        for k, v in c['regions'].items():
            w('  region %s: %s\n' % (k, v))
        w('  combined rules %d (%d intersections)\n' % (c['rules'], c['chain_rules']))


def main(argv=None):
    ap = argparse.ArgumentParser(prog='fwsync')
    sub = ap.add_subparsers(dest='cmd', required=True)
    for name in ('compare', 'detect'):
        c = sub.add_parser(name)
        c.add_argument('configs', nargs='+', help='A B (1:1) or A1 A2 B (2:1); B is always last')
        c.add_argument('--profile', help='optional; empty fields are auto-detected')
        c.add_argument('--scope', help='comma separated prefixes (default: every inside subnet of A)')
        c.add_argument('--ignore-ifc', help='A interfaces to drop (rules and NAT on them); 2:1: A1:<nameif> / A2:<nameif>')
        c.add_argument('--public-b', help='B public ranges, comma separated (default: guessed from B config)')
        g = c.add_argument_group('granular control (repeatable; same keys as the profile and the UI)')
        g.add_argument('--map', action='append', metavar='AIFC=BIFC', help='interface map; BIFC may be ignore or a new B name')
        g.add_argument('--role', action='append', metavar='AIFC=ROLE', help='outside | inside | chain link | ignore')
        g.add_argument('--scope-add', action='append', metavar='PREFIX[=NAME]', help='add a scope prefix with a name')
        g.add_argument('--whatif-route', action='append', metavar='PREFIX=BIFC[@NEXTHOP]', help='planned route on B')
        g.add_argument('--whatif-public', action='append', metavar='PREFIX', help='planned B public range')
        g.add_argument('--whatif-ifc', action='append', metavar='NAME[=ROLE]', help='planned B interface')
        g.add_argument('--whatif-nat', action='append', metavar='REAL=MAPPED[@IN,OUT]', help='planned B PAT (MAPPED = interface or an IP)')
        g.add_argument('--exclude', action='append', metavar='ROWKEY[=REASON]', help='exclude a row (key from the JSON report)')
        g.add_argument('--not-needed', action='append', metavar='ROWKEY[=REASON]', help='mark a row not needed')
        g.add_argument('--rule-action', action='append', metavar='RULE=ACTION', help='permit | block | ignore (rule name or A1:/A2:name)')
        g.add_argument('--name', action='append', metavar='SIDE=NAME', help='display name: A, B, A1, A2 (e.g. B="Backup site (FW-B)")')
        g.add_argument('--finding', action='append', metavar='KEY=STATE[:REASON]', help='fix | later | not needed:REASON (key from the report)')
        g.add_argument('--decision', action='append', metavar='ID=CHOICE', help='decision choice (id from the report)')
        g.add_argument('--fix-all', action='store_true', help='mark every open finding as Fix (builds the full plan)')
        if name == 'compare':
            c.add_argument('--reverse', action='store_true', help='swap A and B (1:1 only)')
            c.add_argument('--parts', default='rules,nat,objects,routing,reverse')
            c.add_argument('--out', required=True)
            c.add_argument('--prefix', default='fwsync')
        c.add_argument('--save-profile', help='write the profile used (detected + overrides; JSON or YAML by extension)')
    w = sub.add_parser('web')
    w.add_argument('--port', type=int, help='default: the first free port from 8765')
    w.add_argument('--no-browser', action='store_true', help='do not open the default browser')
    w.add_argument('--allow-push', action='store_true', help=argparse.SUPPRESS)
    p = sub.add_parser('push')
    p.add_argument('plan')
    p.add_argument('--fmc', required=True)
    p.add_argument('--user', default='admin')
    p.add_argument('--allow-push', action='store_true')
    p.add_argument('--apply', action='store_true', help='without it only the dry run is shown')
    _tls_args(p)
    for name in ('compare', 'detect'):
        sub.choices[name].add_argument('--fmc', help='FMC URL for fmc:device:NAME / fmc:policy:NAME arguments')
        sub.choices[name].add_argument('--user', help='FMC user (read-only role is enough)')
        sub.choices[name].add_argument('--cred', help='JSON file with user and password (owner-only)')
        _tls_args(sub.choices[name])
    r = sub.add_parser('fmc-read')
    _fmc_args(r)
    r.add_argument('--device')
    r.add_argument('--policy', help='access control policy name (no device: zones stand in for interfaces)')
    r.add_argument('--nat', help='FTD NAT policy name (default: the one assigned to the device)')
    r.add_argument('--out', required=True, help='snapshot JSON path (written mode 600)')
    r.add_argument('--lina', action='store_true', help='also write the rendered LINA view next to it')
    cp = sub.add_parser('fmc-copy')
    _fmc_args(cp)
    cp.add_argument('--from', dest='src', required=True, help='device:NAME | policy:NAME | snapshot.json')
    cp.add_argument('--to', dest='dst', required=True, help='device:NAME | policy:NAME[,nat:NAME]')
    cp.add_argument('--parts', default='objects,routes,nat,rules')
    cp.add_argument('--rules', help='only these A rule names (comma separated)')
    cp.add_argument('--map', action='append', metavar='AIFC=BIFC', help='route interface map')
    cp.add_argument('--write-user', help='FMC user that may write (only with --apply)')
    cp.add_argument('--write-cred', help='JSON file with the write user and password')
    cp.add_argument('--out', required=True)
    cp.add_argument('--prefix', default='fwsync_copy')
    cp.add_argument('--apply', action='store_true', help='make the changes (default: dry run only)')
    cp.add_argument('--allow-push', action='store_true')
    ud = sub.add_parser('fmc-undo')
    ud.add_argument('undo')
    _fmc_args(ud)
    ud.add_argument('--write-user')
    ud.add_argument('--write-cred')
    ud.add_argument('--out', required=True)
    ud.add_argument('--apply', action='store_true')
    ud.add_argument('--allow-push', action='store_true')
    args = ap.parse_args(argv)
    console_utf8()
    if args.cmd == 'fmc-read':
        return fmc_read(args)
    if args.cmd == 'fmc-copy':
        return fmc_copy(args)
    if args.cmd == 'fmc-undo':
        return fmc_undo(args)
    if args.cmd in ('compare', 'detect'):
        if len(args.configs) not in (2, 3):
            sys.exit('give A B (1:1) or A1 A2 B (2:1)')
        files = [_source(x, args) for x in args.configs]
        a_list, b = files[:-1], files[-1]
        if args.cmd == 'compare' and args.reverse:
            if len(a_list) != 1:
                sys.exit('--reverse needs 1:1')
            a_list, b = [b], a_list[0]
        parts = args.parts.split(',') if args.cmd == 'compare' else ['routing']
        res, A, B, prof = run(a_list, b, _prof(args), parts=parts)
        if args.cmd == 'compare' and args.fix_all:
            from . import findings
            for f in res['findings']:
                if f['state'] == 'open':
                    prof.finding_state[f['key']] = {'state': 'fix', 'reason': ''}
            findings.build(res, prof, A, B, res['detected'])
        print_detected(res)
        if args.cmd == 'detect':
            if args.save_profile:
                save_profile(prof, args.save_profile)
                print('saved', args.save_profile)
            return
        if args.save_profile:
            save_profile(prof, args.save_profile)
            print('saved', args.save_profile)
        paths = write_all(res, Path(args.out).expanduser(), args.prefix)
        print(json.dumps(res['counts'], indent=1))
        for x in A.warnings[:5] + B.warnings[:5]:
            print('warning:', x)
        print('\n'.join(paths))
    elif args.cmd == 'web':
        from .web import serve
        serve(args.port, args.allow_push, browser=not args.no_browser)
    elif args.cmd == 'push':
        from .push import run as push_run
        plan = json.loads(read_text(args.plan))
        plan = plan.get('plan', plan)
        pw = os.environ.get('FWSYNC_FMC_PASSWORD') or getpass.getpass('FMC password: ')
        v = _verify(args)
        push_run(plan, args.fmc, args.user, pw, allow_push=args.allow_push, dry_run=True, verify=v)
        if args.apply:
            push_run(plan, args.fmc, args.user, pw, allow_push=args.allow_push, dry_run=False, verify=v)


def _tls_args(p):
    p.add_argument('--ca-bundle', help='CA file (PEM) that signed the FMC certificate, e.g. the corporate CA')
    p.add_argument('--insecure', action='store_true', help='do not verify the FMC certificate (isolated lab only)')


def _fmc_args(p):
    p.add_argument('--fmc', required=True, help='FMC URL, e.g. https://192.0.2.10')
    p.add_argument('--user', help='read-only FMC user')
    p.add_argument('--cred', help='JSON file with user and password (owner-only)')
    p.add_argument('--profile', help='profile with fmc.ca_bundle (optional)')
    _tls_args(p)


def _verify(args):
    """TLS verify setting: --insecure > --ca-bundle > profile fmc.ca_bundle > env FWSYNC_CA_BUNDLE > system default"""
    if getattr(args, 'insecure', False):
        return False
    ca = getattr(args, 'ca_bundle', None)
    if not ca and getattr(args, 'profile', None):
        ca = (Profile.load(args.profile).fmc or {}).get('ca_bundle')
    ca = ca or os.environ.get('FWSYNC_CA_BUNDLE')
    return str(Path(ca).expanduser()) if ca else True


def _login(url, user, cred, env='FWSYNC_FMC_PASSWORD', write=False, verify=True):
    from .fmc import Client
    if cred:
        c = json.loads(read_text(cred))
        user, pw = user or c['user'], c['password']
    else:
        if not user:
            sys.exit('give --user or --cred')
        pw = os.environ.get(env) or getpass.getpass('FMC password for %s: ' % user)
    try:
        return Client(url, user, pw, write=write, verify=verify)
    except FileNotFoundError as e:
        sys.exit(str(e))
    except Exception as e:
        if type(e).__name__ == 'SSLError':
            sys.exit('TLS verification of %s failed: %s\nGive the CA that signed the FMC certificate with --ca-bundle '
                     'FILE (or profile fmc.ca_bundle / env FWSYNC_CA_BUNDLE). --insecure only on an isolated lab.' % (url, e))
        raise


_ro = {}


def _reader(args):
    if 'c' not in _ro:
        if not getattr(args, 'fmc', None):
            sys.exit('fmc: arguments need --fmc')
        _ro['c'] = _login(args.fmc, args.user, args.cred, verify=_verify(args))
    return _ro['c']


def _snap_of(spec, args):
    """device:NAME | policy:NAME[,nat:NAME] | snapshot file -> snapshot dict"""
    from .fmc import snapshot
    if Path(spec).expanduser().is_file():
        return json.loads(read_text(spec))
    kind, _, rest = spec.partition(':')
    if kind not in ('device', 'policy') or not rest:
        sys.exit('%s: not a file and not device:NAME / policy:NAME[,nat:NAME]' % spec)
    parts = dict(p.split(':', 1) for p in ('%s:%s' % (kind, rest)).split(',') if ':' in p)
    return snapshot(_reader(args), device=parts.get('device'), policy=parts.get('policy'), nat_policy=parts.get('nat'))


def _source(x, args):
    """a compare argument: a file, or fmc:device:NAME / fmc:policy:NAME read live (snapshot kept in --out)"""
    if not x.startswith('fmc:'):
        return read(x)
    from .fmc import save
    snap = _snap_of(x[4:], args)
    label = x[4:].replace(':', '_').replace('/', '_').replace(' ', '_')
    out = getattr(args, 'out', None)
    if out:
        Path(out).expanduser().mkdir(parents=True, exist_ok=True)
        save(snap, Path(out).expanduser() / ('fmc_%s.json' % label))
    return json.dumps(snap), label


def fmc_read(args):
    from .fmc import snapshot, save, render
    if not (args.device or args.policy):
        sys.exit('give --device or --policy')
    snap = snapshot(_reader(args), device=args.device, policy=args.policy, nat_policy=args.nat)
    save(snap, args.out)
    text, warns = render(snap)
    if args.lina:
        write_text(Path(args.out).with_suffix('.lina.txt'), text)
    ap_ = snap.get('access_policy') or {}
    print('snapshot %s: device %s, ACP %s (%d rules, default %s), NAT %s, %d interfaces, %d routes' % (
        args.out, (snap.get('device') or {}).get('name', '-'), ap_.get('name', '-'), len(ap_.get('rules', [])),
        ap_.get('default_action', '-'), (snap.get('nat_policy') or {}).get('name', '-'), len(snap['interfaces']),
        len(snap['routes'])))
    for w in warns[:20]:
        print('note:', w)
    print(gaps.text('fmc'))


def _writer(args):
    if not args.apply:
        return None
    if not args.allow_push:
        sys.exit('--apply changes FMC: add --allow-push (and put the FMC host in the allowlist)')
    return _login(args.fmc, args.write_user, args.write_cred, env='FWSYNC_FMC_WRITE_PASSWORD', write=True,
                  verify=_verify(args))


def fmc_copy(args):
    from .fmc import plan_copy, apply_copy
    outdir = Path(args.out).expanduser()
    outdir.mkdir(parents=True, exist_ok=True)
    a, b = _snap_of(args.src, args), _snap_of(args.dst, args)
    ifc_map = dict(_kv(m) for m in args.map or [])
    plan, skips = plan_copy(a, b, parts=args.parts.split(','),
                            only_rules=set(x.strip() for x in args.rules.split(',')) if args.rules else None,
                            ifc_map=ifc_map)
    base = str(outdir / ('%s_%s' % (args.prefix, time.strftime('%Y%m%d-%H%M%S'))))
    doc = {'from': args.src, 'to': args.dst, 'plan': plan, 'skipped': skips, 'known_gaps': gaps.ranked('fmc')}
    write_text(base + '_plan.json', json.dumps(doc, indent=1))
    lines = ['# fwsync FMC copy %s -> %s (%s)' % (args.src, args.dst, 'APPLY' if args.apply else 'dry run'), '',
             'Order: objects -> routes -> NAT -> rules. Access rules are created disabled in category "fwsync-staged", '
             'NAT rules disabled; nothing is deployed.', '', '| # | Step | Item | Note |', '|---|---|---|---|']
    lines += ['| %d | %s | %s | %s |' % (o['n'], o['step'], o['name'], o.get('note', '')) for o in plan]
    lines += ['', '## Not copied', '', '| Kind | Item | Reason |', '|---|---|---|']
    lines += ['| %s | %s | %s |' % s for s in skips]
    w = _writer(args)
    out = []
    if w:
        res, undo = apply_copy(w, plan, b, base + '_undo.json', log=out.append, dry_run=False, allow_push=True)
    else:
        res, undo = apply_copy(_reader(args), plan, b, base + '_undo.json', log=out.append, dry_run=True)
    lines += ['', '## Result', '', '```'] + out + ['```']
    if w:
        if undo.get('stopped_at'):
            lines += ['', '**Stopped at step %d (%s): %s**' % (undo['stopped_at']['n'], undo['stopped_at']['name'],
                                                            undo['stopped_at']['error'])]
        lines += ['', 'Undo: `fwsync fmc-undo %s --fmc %s --write-user ... --out %s --apply --allow-push`' %
                  (base + '_undo.json', args.fmc, args.out)]
    lines += ['', gaps.markdown('fmc')]
    write_text(base + '.md', '\n'.join(lines) + '\n')
    print('\n'.join(out))
    print('%d planned, %d not copied; report %s' % (len(plan), len(skips), base + '.md'))
    return res


def fmc_undo(args):
    from .fmc import undo
    doc = json.loads(read_text(args.undo))
    w = _writer(args)
    out = []
    if w:
        undo(w, doc, log=out.append, dry_run=False, allow_push=True)
    else:
        undo(None, doc, log=out.append, dry_run=True)
    outdir = Path(args.out).expanduser()
    outdir.mkdir(parents=True, exist_ok=True)
    p = outdir / Path(args.undo).name.replace('_undo.json', '_undo_result.md')
    write_text(p, '# fwsync undo %s (%s)\n\n```\n%s\n```\n\n%s\n' % (args.undo, 'APPLY' if w else 'dry run',
                                                                      '\n'.join(out), gaps.markdown('fmc')))
    print('\n'.join(out))
    print('report', p)


def save_profile(prof, path):
    d = prof.to_dict()
    if str(path).lower().endswith(('.yaml', '.yml')):
        import yaml
        write_text(path, yaml.safe_dump(d, sort_keys=False))
    else:
        write_text(path, json.dumps(d, indent=1))


if __name__ == '__main__':
    main()
