"""HTML / CSV / JSON output."""
import csv
import html
import json
from pathlib import Path

from .osutil import protect

SECTIONS = [('rules', 'Access rules A -> B', ['id', 'path', 'scope', 'status', 'action_check', 'policy', 'rule', 'intersected_with', 'src_ifc',
                                            'dst_ifc', 'b_src_ifc', 'b_dst_ifc', 'src', 'dst', 'service', 'direction', 'detail',
                                            'b_rules']),
            ('firewide', 'Whole-firewall checks (not limited to the scope)', ['id', 'check', 'status', 'item', 'detail', 'line']),
            ('settings', 'Settings that differ, after translation', ['id', 'category', 'impact', 'side', 'stanza', 'line']),
            ('objects_all', 'Every A object', ['id', 'status', 'kind', 'in_use', 'name', 'a_value', 'translated', 'b_name', 'b_value']),
            ('coverage', 'Coverage: where every config line was compared', ['category', 'a_lines', 'b_lines', 'how', 'differences', 'impact', 'why']),
            ('held_rules', 'Rules held out of the compare (L7 action unknown by name, or marked block)',
             ['id', 'path', 'scope', 'status', 'rule', 'src_ifc', 'dst_ifc', 'src', 'dst', 'service', 'detail']),
            ('b_rules', 'Access rules B -> A (where B allows more than A)',
             ['id', 'scope', 'status', 'policy', 'rule', 'src_ifc', 'dst_ifc', 'src', 'dst', 'service', 'a_rules']),
            ('nat', 'NAT A -> B', ['id', 'scope', 'status', 'section', 'kind', 'a_ifc', 'real_ref', 'real', 'a_mapped', 'a_dst',
                                   'a_inactive', 'b_nat', 'b_mapped', 'proposed_b_mapped', 'description', 'detail']),
            ('b_nat', 'NAT B -> A', ['id', 'scope', 'status', 'kind', 'b_ifc', 'real_ref', 'real', 'b_mapped', 'b_inactive', 'a_nat']),
            ('pat', 'PAT coverage per scope subnet', ['id', 'scope', 'side', 'firewall', 'subnet', 'status', 'nat', 'section']),
            ('pat_detail', 'NAT first match per scope subnet (effective translation, never-hit rules)',
             ['id', 'scope', 'side', 'firewall', 'subnet', 'order', 'line', 'status', 'kind', 'object', 'addresses', 'count',
              'mapped', 'section']),
            ('public', 'B public IP budget', ['id', 'scope', 'subnet', 'a_static_active', 'b_missing', 'b_inactive',
                                              'pub_a', 'pub_b', 'pub_b_nats', 'b_public_needed', 'b_public_new',
                                              'b_public_available', 'status']),
            ('inbound', 'Inbound readiness', ['id', 'scope', 'status', 'object', 'real', 'a_public', 'b_public', 'ports',
                                              'a_rules', 'b_rules']),
            ('dns', 'DNS failover sheet', ['scope', 'host', 'description', 'real_ip', 'a_public_ip', 'b_public_ip', 'ports',
                                           'b_status']),
            ('routing', 'Routing readiness on B', ['id', 'scope', 'subnet', 'status', 'a_ifc', 'a_role', 'expected_b_ifc',
                                                   'b_route', 'b_next_hop', 'detail']),
            ('objects', 'Objects A -> B', ['id', 'scope', 'status', 'name', 'b_name', 'kind', 'value', 'b_value_or_names',
                                           'description']),
            ('b_objects', 'Objects B -> A', ['id', 'scope', 'status', 'name', 'kind', 'value', 'description'])]
SUMMARY_COLS = ['rules', 'rules_any', 'b_rules', 'b_rules_any', 'nat', 'b_nat', 'inbound', 'routing', 'objects', 'b_objects']


def clean(res):
    def c(v):
        if isinstance(v, dict):
            return {k: c(x) for k, x in v.items() if not k.startswith('_')}
        if isinstance(v, list):
            return [c(x) for x in v]
        return v
    return c(res)


def write_json(res, path):
    with open(path, 'w', encoding='utf-8') as fh:
        json.dump(clean(res), fh, indent=1, default=str)


def write_csv(res, outdir, prefix):
    paths = []
    for key, title, cols in SECTIONS:
        p = str(Path(outdir) / ('%s_%s.csv' % (prefix, key)))
        with open(p, 'w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow(cols)
            for r in res.get(key, []):
                w.writerow([', '.join(r.get(c)) if isinstance(r.get(c), list) else r.get(c, '') for c in cols])
        paths.append(p)
    return paths


CSS = """body{font:13px system-ui,sans-serif;margin:16px;color:#1d2330;background:#fff;max-width:1400px}
.verdict{font-size:15px;font-weight:600;margin:4px 0}.verdict.ok{color:#17663a}.verdict.no{color:#a3141f}
.cards{display:flex;flex-wrap:wrap;gap:12px}.card{border:1px solid #d6dae2;border-radius:6px;padding:8px 12px;min-width:min(300px,100%);box-sizing:border-box}
.card table td{border:none;padding:2px 8px 2px 0}.st.ok{color:#17663a}.st.act{color:#8a5a00;font-weight:600}.st.dec{color:#a3141f;font-weight:600}.st.chk{color:#1f5fbf;font-weight:600}
.finding,.item{border:1px solid #d6dae2;border-radius:6px;padding:6px 10px;margin:8px 0}.finding .what{font-weight:600;margin:4px 0}
.fnum{color:#5b6474}.cat{background:#eef1f6;padding:1px 6px;border-radius:3px}.part{margin:4px 0}.part b{display:inline-block;min-width:110px}
.state{float:right}.state.fix{color:#17663a}.state.not-needed{color:#5b6474}.state.later{color:#8a5a00}
.ev{font-size:12px}.decision{border-left:3px solid #a3141f;padding:2px 10px;margin:8px 0}pre{background:#f6f8fa;padding:6px;white-space:pre-wrap;overflow-x:auto}
h1{font-size:20px}h2{font-size:16px;margin-top:28px}table{border-collapse:collapse;width:100%}.wrap{overflow-x:auto;max-width:100%}
th,td{border:1px solid #d6dae2;padding:3px 6px;text-align:left;vertical-align:top}th{background:#eef1f6;position:sticky;top:0}
.s-covered,.s-match,.s-same,.s-ready{color:#17663a}.s-partial{color:#8a5a00}
.s-missing,.s-denied,.s-shadowed,.s-wrong,.s-over-permitted,.s-mapped,.s-no{color:#a3141f;font-weight:600}
.det td,.det th{font-size:12px}.flag{color:#a3141f}.small{color:#5b6474}.counts td{border:none;padding:1px 10px 1px 0}
.map{background:#eef1f6;padding:6px 10px;border-radius:6px}.howto dt{font-weight:600}.howto dd{margin:0 0 6px 16px}
.g-before{border-left:4px solid #a3141f}.g-during{border-left:4px solid #8a5a00}.g-check{border-left:4px solid #1f5fbf}
.g-later,.g-unprovable{border-left:4px solid #9aa3b2}.reason{color:#5b6474;margin:2px 0 0}
input.f{width:100%;box-sizing:border-box}
@media (max-width:700px){body{margin:8px}.part b{display:block}}"""


def lab(res, v):
    """user-facing text for an internal status value"""
    from .findings import label
    return label(v, res.get('names') or {'A': 'A', 'B': 'B'})


def table(head, rows, cls=''):
    """a table that scrolls sideways on a small screen instead of widening the page"""
    e = html.escape
    return ('<div class=wrap><table%s><tr>%s</tr>%s</table></div>' % (
        ' class=%s' % cls if cls else '', ''.join('<th>%s</th>' % e(h) for h in head),
        ''.join('<tr>%s</tr>' % ''.join('<td>%s</td>' % e(str(c)) for c in r) for r in rows)))


def write_html(res, path, title='fwsync report'):
    e = html.escape
    n = res.get('names', {'A': res['a']['name'], 'B': res['b']['name']})
    gl = res.get('glossary', {})
    out = ['<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">'
           '<title>%s</title><style>%s</style>' % (e(title), CSS),
           '<h1>%s</h1>' % e(title),
           '<p class=map>In this report <b>A = %s</b> (%s, the site that fails) and <b>B = %s</b> (%s, the site that '
           'takes over). Everywhere below they are called by these names. %d networks checked, mode %s.</p>' % (
               e(n['A']), e(res['a']['name']), e(n['B']), e(res['b']['name']), len(res['scope']), e(res.get('mode', '1:1')))]
    out += howto_html(res)
    out += runbook_html(res)
    out += readiness_html(res)
    out += findings_html(res)
    out += decisions_html(res)
    out += plan_html(res)
    from . import gaps
    out.append(gaps.html(res.get('gaps_area', 'all')))
    out.append('<details class=adv><summary><h2 style="display:inline">Details (advanced)</h2></summary>'
               '<p class=small>Raw tables behind the runbook. Status values are shown in plain words; the CSV files '
               'keep the internal values.</p>')
    out += areas_html(res)
    out += firewide_html(res)
    out += detected_html(res)
    out.append('<h3>Summary per network (rules counted only where they name the network; *_any = via any)</h3>')
    rows = [[r['subnet'], r['scope']] + [', '.join('%s %d' % (lab(res, k), c) for k, c in sorted(r.get(col, {}).items()))
                                         for col in SUMMARY_COLS]
            for r in res.get('summary', []) if any(r.get(c) for c in SUMMARY_COLS)]
    out.append(table(['subnet', 'name'] + SUMMARY_COLS, rows))
    for key, t, cols in SECTIONS:
        rows = res.get(key, [])
        out.append('<details><summary>%s (%d)</summary><div class=wrap><table data-t=%s><tr>%s</tr>' % (
            e(named_title(t, n)), len(rows), key, ''.join('<th>%s</th>' % e(c) for c in cols)))
        out.append('<tr>%s</tr>' % ''.join('<th><input class=f oninput="flt(this)"></th>' for c in cols))
        for r in rows:
            cells = []
            for c in cols:
                v = r.get(c, '')
                v = ', '.join(v) if isinstance(v, list) else str(v)
                tip = ' title="%s"' % e(gl.get(v, '')) if c == 'status' and gl.get(v) else ''
                cls = ' class="s-%s"' % e(v.split()[0].rstrip(',')) if c == 'status' and v else ''
                cells.append('<td%s%s>%s</td>' % (cls, tip, e(lab(res, v) if c == 'status' else v)))
            out.append('<tr>%s</tr>' % ''.join(cells))
        out.append('</table></div></details>')
    out.append('</details>')
    out.append("""<script>function flt(i){const t=i.closest('table'),c=[...t.rows[1].cells].map(x=>x.firstChild.value.toLowerCase());
for(const r of [...t.rows].slice(2)){r.style.display=c.every((v,k)=>!v||r.cells[k].textContent.toLowerCase().includes(v))?'':'none'}}</script>""")
    Path(path).write_text('\n'.join(out), encoding='utf-8')


def named_title(t, n):
    from .findings import named
    return named(t, n)


def howto_html(res):
    e = html.escape
    h = res.get('how_to_read', [])
    if not h:
        return []
    return ['<details open><summary><b>How to read this report</b></summary><dl class=howto>%s</dl></details>' % ''.join(
        '<dt>%s</dt><dd>%s</dd>' % (e(x['term']), e(x['meaning'])) for x in h)]


def item_html(it):
    """one runbook item or finding: What's wrong / Why it matters / What to do (FMC path + CLI) / How to verify"""
    e = html.escape
    return ('<div class=part><b>What\'s wrong</b> %s</div><div class=part><b>Why it matters</b> %s</div>'
            '<div class=part><b>What to do</b><ol>%s</ol><pre>%s</pre></div><div class=part><b>How to verify</b>'
            '<pre>%s</pre></div>' % (e(it['what']), e(it['why']), ''.join('<li>%s</li>' % e(x) for x in it['fmc']),
                                     e('\n'.join(it['cli'])), e('\n'.join(it['verify']))))


def runbook_html(res):
    e = html.escape
    rb, v = res.get('runbook'), res.get('verdict')
    if not rb:
        return []
    out = ['<h2>Takeover runbook</h2>']
    if v:
        out.append('<p class="verdict %s">%s</p>' % ('ok' if v['ready'] else 'no', e(v['text'])))
    for g in rb:
        out.append('<h3>%s (%d)</h3>' % (e(g['title']), g['count']))
        if not g['items']:
            out.append('<p class=small>Nothing here.</p>')
        for i, it in enumerate(g['items'], 1):
            out.append('<details class="item g-%s"><summary><b>%d. %s</b> &middot; %s <span class=small>(%s)</span>'
                       '</summary>%s</details>' % (e(g['key']), i, e(it['subject']), e(it['reason']), e(it['kind']),
                                                   item_html(it)))
    return out


def areas_html(res):
    v = res.get('verdict') or {}
    if not v.get('areas'):
        return []
    return ['<h3>Open items per area</h3>', table(['area', 'open'], [[a['area'], a['open']] for a in v['areas']])]


def firewide_html(res):
    rows = res.get('firewide', [])
    if not rows:
        return []
    return ['<h3>Whole-firewall checks (%d)</h3><p class=small>Not limited to the scope; each one is also in the '
            'runbook.</p>' % len(rows), table(['check', 'item', 'detail'], [[lab(res, r['check']), r['item'], r['detail']]
                                                                            for r in rows])]


def readiness_html(res):
    e = html.escape
    cards = res.get('readiness', [])
    if not cards:
        return []
    out = ['<h2>Readiness per network</h2>']
    for c in cards:
        out.append('<p class="verdict %s">%s</p><p class=reason>%s</p>' % (
            'ok' if c['ready'] else 'no', e(c['verdict']), e(c.get('reason', ''))))
    out.append('<details><summary>Per area</summary><div class=cards>')
    for c in cards:
        out.append('<div class=card><h3>%s</h3><table>' % e(c.get('title', c['subnet'])))
        for l in c['lines']:
            cnt = ', '.join(x for x in (
                l['actions'] and ('%d to fix' % l['actions']), l['decisions'] and (
                    '%d choice%s needed' % (l['decisions'], '' if l['decisions'] == 1 else 's')),
                l.get('checks') and ('%d to verify' % l['checks'])) if x)
            cnt = (' (%s)' % cnt) if cnt else ''
            out.append('<tr><td>%s</td><td class="st %s">%s%s</td><td class=small>%s</td></tr>' % (
                e(l['name']), {'Ready': 'ok', 'Action needed': 'act', 'Decision needed': 'dec', 'Check first': 'chk',
                                 'During failover': 'chk'}[l['state']],
                e(l.get('label', l['state'])), cnt, e(l.get('note', ''))))
        out.append('</table></div>')
    out.append('</div></details>')
    return out


def findings_html(res):
    e = html.escape
    fs = res.get('findings', [])
    out = ['<h2>Findings (%d)</h2><p class=small>Order of work: routing, outbound PAT, published servers, rules, objects.'
           '</p>' % len(fs)]
    lv = {'fix': 'thing to fix', 'choice': 'your choice needed', 'check': 'check on firewall', 'review': 'review later'}
    for f in fs:
        evid = ''.join('<div class=ev><b>%s</b> line %s: <code>%s</code></div>' % (e(x['device']), x['line'] or '-', e(x['text']))
                       for x in f['evidence'])
        objs = ''.join('<li><code>%s</code> = %s</li>' % (e(o['name']), e(o['value'])) for o in f['fix']['objects'])
        it = {'what': f['what'], 'why': f['why'], 'fmc': f['fix']['fmc'], 'verify': f['verify'],
              'cli': [c for o in f['fix']['objects'] for c in o['cli']] + f['fix']['cli']}
        out.append('<div class="finding st-%s" id="%s"><div class=fh><span class=fnum>#%d</span> <span class=cat>%s</span> '
                   '<span class=cat>%s</span> <span class=small>%s</span> <span class="state %s">%s</span></div>%s%s'
                   '<details><summary>Evidence</summary>%s</details></div>' % (
                       e(f['state'].replace(' ', '-')), e(f['id']), f['n'], e(f['category']), e(lv.get(f.get('level'), '')),
                       e(f['scope']), e(f['state'].replace(' ', '-')), e(f['state'] + (': ' + f['reason'] if f['reason'] else '')),
                       ('<p>Objects to create first:</p><ul>%s</ul>' % objs) if objs else '', item_html(it), evid))
    return out


def decisions_html(res):
    e = html.escape
    ds = res.get('decisions', [])
    out = ['<h2>Your choices (%d)</h2>' % len(ds)]
    for d in ds:
        out.append('<div class=decision><b>%s</b> &middot; %s<p>%s</p>%s<p class=small>Options: %s%s</p></div>' % (
            e(d['kind']), e(d['title']), e(d['text']),
            ('<ul>%s</ul>' % ''.join('<li>%s</li>' % e(m) for m in d['math'])) if d.get('math') else '',
            e(' / '.join(d['options'])), (' &middot; chosen: <b>%s</b>' % e(d['choice'])) if d.get('choice') else ''))
    return out


def plan_html(res, standalone=False):
    e = html.escape
    p = res.get('plan')
    if not p:
        return []
    out = ['<h2>Remediation plan (%d changes from %d findings marked Fix)</h2><p class=small>Nothing is pushed. '
           'Apply in FMC in this order.</p><p><b>%s</b></p>' % (p['total'], p['findings'], e(p.get('public_text', '')))]
    for g in p['groups']:
        out.append('<h3>%s (%d)</h3><ol>' % (e(g['name']), g['count']))
        for it in g['items']:
            out.append('<li>%s%s%s%s</li>' % (e(it['fmc']), ('<div class=small>%s</div>' % e(it['finding'])) if it['finding'] else '',
                                              ('<pre>%s</pre>' % e('\n'.join(it['cli']))) if it['cli'] else '',
                                              ('<div class=small>Verify:</div><pre>%s</pre>' % e('\n'.join(it['verify']))) if it['verify'] else ''))
        out.append('</ol>')
    return out


def detected_html(res):
    e = html.escape
    d = res.get('detected')
    if not d:
        return []
    out = ['<h2>Auto-detected (mode %s, site type %s)</h2>' % (e(d.get('mode', '')), e(res.get('profile_used', {}).get('type', '')))]
    out.append('<table class=det><tr><th>A interface</th><th>role</th><th>why</th><th>B interface</th><th>how</th><th>flag / note</th></tr>')
    for r in d['interface_map']:
        out.append('<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td class=flag>%s</td></tr>' % tuple(
            e(str(x)) for x in (r['a'], r['a_role'], r['a_reason'], r['b'] or '-', r['how'], ' '.join(x for x in (r['flag'], r.get('note', '')) if x))))
    out.append('</table>')
    out.append('<p>B roles: %s</p>' % e(', '.join('%s=%s' % (k, v[0]) for k, v in d['roles_b'].items())))
    for side in ('a', 'b'):
        p = d['public_' + side]
        out.append('<p>Public %s: ranges <b>%s</b> (interfaces %s; mapped %d addresses)</p>' % (
            side.upper(), e(', '.join(p['ranges']) or '-'), e(', '.join(p['interfaces']) or '-'), p['mapped_count']))
    c = d.get('chain')
    if c:
        out.append('<p>Chain: edge (A1) <b>%s</b>, inner (A2) <b>%s</b>; A1 reaches A2 via %s, A2 uplink %s. %s</p>' % (
            e(c['edge']), e(c['inner']), e(c['a1_toward_a2']), e(c['a2_uplink']), e(c.get('note', ''))))
        out.append('<table class=det><tr><th>A2 inside subnets</th><th>A2 ifc</th><th>A1 routes via</th><th>path</th></tr>')
        for p in c['paths']:
            out.append('<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>' % tuple(e(str(p[k])) for k in ('subnets', 'a2_ifc', 'a1_ifc', 'path')))
        out.append('</table><p class=small>%s</p>' % e('; '.join('%s: %s' % kv for kv in c['regions'].items())))
    return out


def write_all(res, outdir, prefix, mode=0o600):
    Path(outdir).mkdir(parents=True, exist_ok=True)
    paths = [str(Path(outdir) / (prefix + '.json')), str(Path(outdir) / (prefix + '.html'))]
    write_json(res, paths[0])
    write_html(res, paths[1], 'fwsync %s' % prefix)
    paths += write_csv(res, outdir, prefix)
    from .findings import plan_markdown, plan_csv_rows
    from . import gaps
    area = res.get('gaps_area', 'all')
    for ext, body in (('md', plan_markdown(res) + '\n\n' + gaps.markdown(area) if res.get('plan') else ''),):
        if body:
            pp = str(Path(outdir) / ('%s_plan.md' % prefix))
            Path(pp).write_text(encoding='utf-8', data=body)
            paths.append(pp)
    if res.get('plan'):
        pp = str(Path(outdir) / ('%s_plan.csv' % prefix))
        with open(pp, 'w', newline='', encoding='utf-8') as f:
            csv.writer(f).writerows(plan_csv_rows(res))
        paths.append(pp)
        pp = str(Path(outdir) / ('%s_plan.html' % prefix))
        Path(pp).write_text(encoding='utf-8', data='<!doctype html><meta charset=utf-8><title>change plan</title><style>%s</style>%s' % (
            CSS, '\n'.join(plan_html(res)) + gaps.html(area)))
        paths.append(pp)
        pp = str(Path(outdir) / ('%s_findings.csv' % prefix))
        with open(pp, 'w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow(['n', 'category', 'scope', 'state', 'reason', 'what', 'why', 'fmc', 'cli', 'verify', 'evidence'])
            for x in res.get('findings', []):
                w.writerow([x['n'], x['category'], x['scope'], x['state'], x['reason'], x['what'], x['why'],
                            ' | '.join(x['fix']['fmc']), ' | '.join(x['fix']['cli']), ' | '.join(x['verify']),
                            ' | '.join('%s:%s %s' % (v['device'], v['line'], v['text']) for v in x['evidence'])])
        paths.append(pp)
    p = str(Path(outdir) / ('%s_gaps.csv' % prefix))
    with open(p, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['rank', 'area', 'gap', 'impact', 'workaround'])
        for g in gaps.ranked(area):
            w.writerow([g['rank'], g['area'], g['gap'], g['impact'], g['workaround']])
    paths.append(p)
    p = str(Path(outdir) / ('%s_summary.csv' % prefix))
    with open(p, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['scope', 'subnet'] + SUMMARY_COLS)
        for r in res.get('summary', []):
            w.writerow([r['scope'], r['subnet']] + ['; '.join('%s %d' % x for x in sorted(r.get(c, {}).items())) for c in SUMMARY_COLS])
    paths.append(p)
    for p in paths:
        protect(p)
    return paths
