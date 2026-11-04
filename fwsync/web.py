"""Local web UI (FastAPI, plain HTML/JS). Bound to 127.0.0.1 only. Load the backups, press Compare."""
import json
import signal
import sys
import threading
import uuid
import webbrowser
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse

from .generate import generate
from .osutil import WEB_HOST, WEB_PORT, decode, free_port, port_free
from .pipeline import read, run
from .profile import Profile
from .report import clean, write_all, write_html

app = FastAPI(title='fwsync')
STATE = {'sessions': {}}


def _text(upload, path):
    if upload is not None and upload.filename:
        return decode(upload.file.read()), upload.filename
    if path:
        return read(path)
    return None


@app.post('/api/compare')
async def api_compare(mode: str = Form('1:1'), a1: UploadFile = File(None), a2: UploadFile = File(None),
                      b: UploadFile = File(None), a1_path: str = Form(''), a2_path: str = Form(''), b_path: str = Form(''),
                      session: str = Form(''), overrides: str = Form('{}'), profile_path: str = Form('')):
    old = STATE['sessions'].get(session, {})
    texts = old.get('texts', {})
    for k, up, pth in (('a1', a1, a1_path), ('a2', a2, a2_path), ('b', b, b_path)):
        t = _text(up, pth)
        if t is not None:
            texts[k] = t
    need = ['a1', 'b'] + (['a2'] if mode == '2:1' else [])
    miss = [k for k in need if k not in texts]
    if miss:
        raise HTTPException(400, 'load config(s): %s' % ', '.join(miss))
    prof = Profile.load(profile_path) if profile_path else Profile()
    for k, v in json.loads(overrides or '{}').items():
        if k in Profile.__dataclass_fields__ and v not in (None, '', [], {}):
            setattr(prof, k, v)
    a_list = [texts['a1']] + ([texts['a2']] if mode == '2:1' else [])
    try:
        res, A, B, prof = run(a_list, texts['b'], prof)
    except ValueError as e:
        raise HTTPException(400, str(e))
    sid = session if session in STATE['sessions'] else uuid.uuid4().hex[:12]
    STATE['sessions'][sid] = {'res': res, 'prof': prof, 'A': A, 'B': B, 'texts': texts}
    out = clean(res)
    out['session'] = sid
    out['b_ifcs'] = [n for n, i in B.interfaces.items() if not i.planned]
    return JSONResponse(json.loads(json.dumps(out, default=str)))


@app.post('/api/state')
async def api_state(body: dict):
    """finding / decision states changed in the UI: rebuild findings, readiness, decisions and plan (no re-compare)"""
    from . import findings, runbook
    s = STATE['sessions'].get(body.get('session'))
    if not s:
        raise HTTPException(404, 'session')
    prof = s['prof']
    if 'finding_state' in body:
        prof.finding_state = body['finding_state'] or {}
    if 'decision_state' in body:
        prof.decision_state = body['decision_state'] or {}
    findings.build(s['res'], prof, s['A'], s['B'], s['res']['detected'])
    runbook.build(s['res'])
    out = clean({k: s['res'][k] for k in ('findings', 'decisions', 'readiness', 'plan', 'known_gaps', 'runbook', 'verdict')})
    return JSONResponse(json.loads(json.dumps(out, default=str)))


@app.get('/api/plan/{sid}.{fmt}')
async def api_plan(sid: str, fmt: str):
    from fastapi.responses import PlainTextResponse
    from .findings import plan_markdown, plan_csv_rows
    from .report import plan_html, CSS
    import csv
    import io
    s = STATE['sessions'].get(sid)
    if not s:
        raise HTTPException(404, 'session')
    res = s['res']
    from . import gaps
    area = res.get('gaps_area', 'all')
    if fmt == 'md':
        return PlainTextResponse(plan_markdown(res) + '\n\n' + gaps.markdown(area), media_type='text/markdown')
    if fmt == 'csv':
        buf = io.StringIO()
        csv.writer(buf).writerows(plan_csv_rows(res))
        return PlainTextResponse(buf.getvalue(), media_type='text/csv')
    return HTMLResponse('<!doctype html><meta charset=utf-8><title>change plan</title><style>%s</style>%s' % (
        CSS, '\n'.join(plan_html(res)) + gaps.html(area)))


@app.post('/api/generate')
async def api_generate(body: dict):
    s = STATE['sessions'].get(body.get('session'))
    if not s:
        raise HTTPException(404, 'session')
    g = generate(s['res'], body.get('ids', []), s['prof'], s['B'])
    return {'cli': g['cli'], 'changes': g['changes']}


@app.post('/api/report')
async def api_report(body: dict):
    s = STATE['sessions'].get(body.get('session'))
    if not s:
        raise HTTPException(404, 'session')
    return {'files': write_all(s['res'], Path(body['outdir']).expanduser(), body.get('prefix', 'fwsync'))}


@app.get('/api/report/{sid}.html', response_class=HTMLResponse)
async def api_report_html(sid: str):
    s = STATE['sessions'].get(sid)
    if not s:
        raise HTTPException(404, 'session')
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / 'r.html'
        write_html(s['res'], p, 'fwsync report')
        return p.read_text(encoding='utf-8')


@app.get('/', response_class=HTMLResponse)
async def index():
    return PAGE


def _break_to_interrupt(signum, frame):
    """Windows Ctrl-Break / console close: uvicorn shuts down and then re-raises the signal; make that a
    KeyboardInterrupt like Ctrl-C instead of the default handler killing the process"""
    raise KeyboardInterrupt


def serve(port=None, allow_push=False, browser=True):
    """127.0.0.1 only. port None: the first free port from 8765. Ctrl-C (Ctrl-Break on Windows) stops it cleanly;
    no fork, no POSIX-only signals, no reload workers."""
    import uvicorn
    if port is None:
        port = free_port(WEB_PORT)
    elif not port_free(port):
        sys.exit('port %d on %s is in use: close the other fwsync window, or start without --port to take the next '
                 'free one' % (port, WEB_HOST))
    url = 'http://%s:%d/' % (WEB_HOST, port)
    print('fwsync web UI: %s  (Ctrl-C to stop)' % url, flush=True)
    if browser:
        threading.Timer(1.0, webbrowser.open, (url,)).start()
    if hasattr(signal, 'SIGBREAK'):
        signal.signal(signal.SIGBREAK, _break_to_interrupt)
    try:
        uvicorn.run(app, host=WEB_HOST, port=port, log_level='warning', workers=1, reload=False)
    except KeyboardInterrupt:
        pass
    print('fwsync web UI stopped', flush=True)


PAGE = r"""<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>fwsync</title><style>
:root{--bg:#fff;--fg:#1d2330;--mut:#5b6474;--line:#d6dae2;--head:#eef1f6;--ok:#17663a;--warn:#8a5a00;--bad:#a3141f;--acc:#1f5fbf}
@media (prefers-color-scheme:dark){:root{--bg:#14171c;--fg:#e4e7ec;--mut:#9aa3b2;--line:#343a45;--head:#1e232b;--ok:#5cc489;--warn:#e0b04a;--bad:#ff7b84;--acc:#7aa7ff}}
body{font:13px system-ui,sans-serif;margin:16px;background:var(--bg);color:var(--fg)}
fieldset{border:1px solid var(--line);margin:0 0 12px;padding:8px}legend{font-weight:600}label{margin-right:12px}
input[type=text],textarea,select{background:var(--bg);color:var(--fg);border:1px solid var(--line)}
button{background:var(--acc);color:#fff;border:0;padding:5px 12px;border-radius:4px;cursor:pointer;margin:0 6px 4px 0}
button.sec{background:var(--head);color:var(--fg)}button.x{background:none;color:var(--bad);padding:0 4px}
table{border-collapse:collapse;width:100%}th,td{border:1px solid var(--line);padding:3px 6px;text-align:left;vertical-align:top}
th{background:var(--head);position:sticky;top:0}.tabs button{background:var(--head);color:var(--fg)}.tabs button.on{background:var(--acc);color:#fff}
.s-covered,.s-match,.s-same,.s-ready,.s-ok,.s-also{color:var(--ok)}.s-partial,.s-other,.s-differs,.s-action,.s-blocked{color:var(--warn)}
.s-missing,.s-denied,.s-shadowed,.s-inactive,.s-nat,.s-mapped,.s-wrong,.s-no,.s-over-permitted{color:var(--bad);font-weight:600}
pre{white-space:pre-wrap;border:1px solid var(--line);padding:8px;max-height:420px;overflow:auto}.mut{color:var(--mut)}.flag{color:var(--bad)}
.wrap{overflow-x:auto}.box{max-height:300px;overflow:auto;border:1px solid var(--line)}.hide{display:none}tr.st td{opacity:.55}
.warn{color:var(--warn)}.kids{background:var(--head)}
.verdict{font-size:15px;font-weight:600;margin:6px 0}.verdict.ok{color:var(--ok)}.verdict.no{color:var(--bad)}
.cards{display:flex;flex-wrap:wrap;gap:12px}.card{border:1px solid var(--line);border-radius:6px;padding:8px 12px;min-width:320px}
.card h3{margin:2px 0 6px}.card td{border:none;padding:3px 8px 3px 0}.card tr.link{cursor:pointer}.card tr.link:hover td{text-decoration:underline}
.st-ok{color:var(--ok)}.st-act{color:var(--warn);font-weight:600}.st-dec{color:var(--bad);font-weight:600}
.finding{border:1px solid var(--line);border-radius:6px;padding:6px 10px;margin:8px 0}.finding .what{font-weight:600;margin:4px 0}
.finding .why{margin:2px 0 6px;color:var(--mut)}.cat{background:var(--head);padding:1px 6px;border-radius:3px}
.finding.state-fix{border-left:4px solid var(--ok)}.finding.state-not-needed{opacity:.6}.finding.state-later{border-left:4px solid var(--warn)}
.fb{float:right}.fb button{padding:3px 9px}.ev{font-size:12px;margin:2px 0}.flag{color:var(--warn)}
.decision{border-left:3px solid var(--bad);padding:4px 10px;margin:10px 0}.decision.done{border-color:var(--ok)}
[title]{text-decoration-style:dotted}
.map{background:var(--head);padding:6px 10px;border-radius:6px}.howto dt{font-weight:600}.howto dd{margin:0 0 6px 16px}
.item{border:1px solid var(--line);border-radius:6px;padding:6px 10px;margin:6px 0}.part{margin:4px 0}.part b{display:inline-block;min-width:110px}
.g-before{border-left:4px solid var(--bad)}.g-during{border-left:4px solid var(--warn)}.g-check{border-left:4px solid var(--acc)}
.g-later,.g-unprovable{border-left:4px solid var(--mut)}.st-chk{color:var(--acc);font-weight:600}.reason{color:var(--mut);margin:0 0 8px}
.card{min-width:min(320px,100%);box-sizing:border-box}
@media (max-width:700px){body{margin:8px}.part b{display:block}.fb{float:none;display:block}}
</style></head><body>
<h1>fwsync</h1>
<form id=f><fieldset><legend>Configs (show running-config text)</legend>
<label><input type=radio name=mode value="1:1" checked> 1:1 &nbsp;A &rarr; B</label>
<label><input type=radio name=mode value="2:1"> 2:1 &nbsp;A1 (edge) + A2 (inner) &rarr; B</label><br><br>
<label><span id=a1l>A</span> <input type=file name=a1></label>
<label id=a2box class=hide>A2 <input type=file name=a2></label>
<label>B <input type=file name=b></label>
<label>Profile (optional) <input type=file id=proffile accept=".json"></label>
<details><summary class=mut>or paths on this machine</summary>
A1 <input type=text name=a1_path size=34> A2 <input type=text name=a2_path size=34> B <input type=text name=b_path size=34><br>
Profile path (JSON or YAML) <input type=text name=profile_path size=50></details>
</fieldset><button type=submit>Compare</button> <span id=busy class=mut></span></form>

<nav id=nav class="tabs hide"><button data-v=takeover class=on>Takeover</button><button data-v=readiness>Readiness</button><button data-v=findings>Findings</button>
<button data-v=decisions>Your choices</button><button data-v=plan>Remediation plan</button><button data-v=setup>Setup</button>
<button data-v=details>Details (advanced)</button></nav>
<section id=v-takeover class=view></section>
<section id=v-readiness class="view hide"></section>
<section id=v-findings class="view hide"><p><select id=fcat><option value="">all categories</option><option>routing</option><option>pat</option>
<option>inbound</option><option>rules</option><option>objects</option></select> <select id=fscope><option value="">all subnets</option></select>
<select id=fstate><option value="">open + fix + later</option><option>open</option><option>fix</option><option>later</option><option>not needed</option></select>
<input type=text id=ftext placeholder="search (host, IP, rule)" size=26> <span id=fcount class=mut></span>
<button type=button class=sec id=fallfix>mark shown as Fix</button></p><div id=flist></div></section>
<section id=v-decisions class="view hide"></section>
<section id=v-plan class="view hide"></section>
<section id=v-setup class="view hide">
<div id=det class=hide>
<fieldset><legend>Interfaces</legend><div id=chain></div><div class=wrap><table id=imap></table></div>
<p><span id=boutl>B outside:</span> <span id=broles></span></p></fieldset>
<fieldset><legend>Scope</legend>
<p><button type=button class=sec id=sall>all</button><button type=button class=sec id=snone>none</button><button type=button class=sec id=sinv>invert</button>
<input type=text id=sflt placeholder=filter size=18> <span id=scnt class=mut></span></p>
<div class=box><table id=scope></table></div>
<p>Add <input type=text id=newp placeholder="prefix e.g. 192.0.2.0/24" size=22> <input type=text id=newn placeholder="name e.g. VLAN 20" size=16>
<button type=button class=sec id=addp>add</button></p></fieldset>
<fieldset><legend>Public ranges and site type</legend>
<p>Public A <input type=text id=puba size=70><br>Public B <input type=text id=pubb size=70> <span class=mut id=pubnote></span></p>
<p>Site type <select id=site><option value=standard>separate sites (B uses its own public IPs)</option><option value=shared-edge>shared public subnet (same IPs)</option></select></p></fieldset>
<fieldset><legend>What-if on B (planned changes, treated as already on B)</legend>
<table id=wi><tr><th>kind</th><th>value</th><th>B interface / mapped</th><th>next hop / out</th><th></th></tr></table>
<p><select id=wik><option value=routes>route</option><option value=public>public range</option><option value=interfaces>interface</option><option value=nat_pools>NAT pool (PAT)</option></select>
<input type=text id=wiv placeholder="prefix / name" size=20> <input type=text id=wia placeholder="ifc / role / mapped" size=16 list=bifs> <input type=text id=wib placeholder="next hop / in,out ifc" size=16>
<button type=button class=sec id=wiadd>add</button><datalist id=bifs></datalist></p></fieldset>
<p><button type=button id=rerun>Compare again</button> <button type=button class=sec id=saveprof>Save profile</button>
<button type=button class=sec id=dl>Download HTML report</button></p>
</div>

</section>
<section id=v-details class="view hide">
<div id=summary></div>
<div class=tabs id=tabs></div>
<p id=rowctl class=hide>Rows shown: <select id=bstate><option value="">include</option><option value=exclude>exclude</option><option value="not needed">not needed</option></select>
reason <input type=text id=breason size=20> <button type=button class=sec id=bapply>apply to all shown rows</button>
<label><input type=checkbox id=showhidden> show "not needed" rows</label>
<span id=l7ctl> | rule names matching <input type=text id=l7f size=16 placeholder="e.g. block"> <button type=button class=sec id=l7block>mark as block</button></span></p>
<div class=wrap id=tbl></div>
<p><button id=gen>Generate CLI + change list from checked items</button></p>
<h3>LINA / ASA CLI (reference)</h3><pre id=cli></pre><h3>Change list</h3><pre id=chg></pre>
</section>
<script>
const COLS={settings:['id','category','impact','side','stanza','line'],objects_all:['id','status','kind','in_use','name','a_value','translated','b_name','b_value'],firewide:['id','check','status','item','detail'],rules:['id','path','scope','status','action_check','rule','intersected_with','src_ifc','dst_ifc','src','dst','service','detail'],
held_rules:['id','path','scope','status','rule','src_ifc','dst_ifc','src','dst','service','detail'],
b_rules:['id','scope','status','rule','src_ifc','dst_ifc','src','dst','service','a_rules'],
nat:['id','scope','status','kind','a_ifc','real_ref','real','a_mapped','a_dst','b_mapped','proposed_b_mapped','detail'],
b_nat:['id','scope','status','kind','b_ifc','real_ref','real','b_mapped','a_nat'],
inbound:['id','scope','status','object','real','a_public','b_public','ports','a_rules'],
dns:['scope','host','real_ip','a_public_ip','b_public_ip','ports','b_status'],
public:['scope','subnet','a_static_active','b_missing','b_inactive','b_public_needed','b_public_available','status'],
routing:['scope','subnet','status','a_ifc','expected_b_ifc','b_route','b_next_hop','detail'],
pat:['id','scope','side','subnet','status','nat'],pat_detail:['scope','side','subnet','order','line','status','kind','object','addresses','count','mapped'],
objects:['id','scope','status','name','kind','value','b_value_or_names'],b_objects:['id','scope','status','name','kind','value'],
planned:['kind','item','detail']};
const SUMC=['rules','b_rules','nat','b_nat','inbound','routing','objects','b_objects'];
let R=null,cur='rules',P={},LOADED=null;const sel=new Set();const $=id=>document.getElementById(id);
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const mode=()=>document.querySelector('input[name=mode]:checked').value;
document.querySelectorAll('input[name=mode]').forEach(x=>x.onchange=()=>{$('a2box').classList.toggle('hide',mode()!='2:1');$('a1l').textContent=mode()=='2:1'?'A1':'A'});
$('proffile').onchange=async e=>{const f=e.target.files[0];if(!f)return;try{LOADED=JSON.parse(await f.text());$('busy').textContent='profile loaded: '+f.name}catch(x){alert('profile must be JSON: '+x)}};
async function go(withEdits){const fd=new FormData($('f'));if(R)fd.append('session',R.session);
fd.append('overrides',JSON.stringify(withEdits?edits():(LOADED||{})));
$('busy').textContent='comparing...';const r=await fetch('/api/compare',{method:'POST',body:fd});$('busy').textContent='';
if(!r.ok){alert(await r.text());return}R=await r.json();R.planned=R.planned||[];P=JSON.parse(JSON.stringify(R.profile_used));sel.clear();showDet();showSum();tabs();draw();renderAll()}
$('f').onsubmit=e=>{e.preventDefault();go(false)};$('rerun').onclick=()=>go(true);
let VIEW='takeover';
document.querySelectorAll('#nav button').forEach(b=>b.onclick=()=>show(b.dataset.v));
function show(v){VIEW=v;document.querySelectorAll('#nav button').forEach(x=>x.classList.toggle('on',x.dataset.v==v));
document.querySelectorAll('.view').forEach(s=>s.classList.toggle('hide',s.id!='v-'+v))}
function tbl(cols,rows){return '<div class=wrap><table><tr>'+cols.map(c=>`<th>${esc(c)}</th>`).join('')+'</tr>'+rows.map(r=>'<tr>'+cols.map(c=>`<td>${esc(String(r[c]??''))}</td>`).join('')+'</tr>').join('')+'</table></div>'}
const L=s=>(R&&R.labels&&R.labels[s])||s;
function howto(){return (R.how_to_read||[]).length?'<details open><summary><b>How to read this</b></summary><dl class=howto>'+R.how_to_read.map(x=>`<dt>${esc(x.term)}</dt><dd>${esc(x.meaning)}</dd>`).join('')+'</dl></details>':''}
function parts(it){return `<div class=part><b>What's wrong</b> ${esc(it.what)}</div><div class=part><b>Why it matters</b> ${esc(it.why)}</div>
<div class=part><b>What to do</b><ol>${it.fmc.map(x=>`<li>${esc(x)}</li>`).join('')}</ol><pre>${esc(it.cli.join('\n'))}</pre></div><div class=part><b>How to verify</b><pre>${esc(it.verify.join('\n'))}</pre></div>`}
function takeoverView(){const v=R.verdict,n=R.names;
let h=`<p class=map>A = <b>${esc(n.A)}</b> (the site that fails), B = <b>${esc(n.B)}</b> (the site that takes over). Below they are called by these names.</p>`+howto();
if(v)h+=`<h2>Can ${esc(n.B)} take over?</h2><p class="verdict ${v.ready?'ok':'no'}">${esc(v.text)}</p>`;
h+=(R.runbook||[]).map(g=>`<h3>${esc(g.title)} (${g.count})</h3>`+(g.items.length?g.items.map((it,i)=>`<details class="item g-${g.key}"><summary><b>${i+1}. ${esc(it.subject)}</b> &middot; ${esc(it.reason)} <span class=mut>(${esc(it.kind)})</span></summary>${parts(it)}</details>`).join(''):'<p class=mut>Nothing here.</p>')).join('');
h+='<details><summary>Details: open items per area, whole-firewall checks, coverage</summary>'+(v&&v.areas&&v.areas.length?'<h3>Open items per area</h3>'+tbl(['area','open'],v.areas):'');
h+=`<h3>Whole-firewall checks (${(R.firewide||[]).length})</h3>`+tbl(['check','item','detail'],(R.firewide||[]).map(r=>Object.assign({},r,{check:L(r.check)})));
h+='<h3>Coverage: where every config line was compared</h3>'+tbl(['category','a_lines','b_lines','how','differences','impact','why'],R.coverage||[])+'</details>';
$('v-takeover').innerHTML=h}
function renderAll(){$('nav').classList.remove('hide');takeoverView();readinessView();fillScopes();findingsView();decisionsView();planView();show(VIEW)}
const STC={'Ready':'st-ok','Action needed':'st-act','Decision needed':'st-dec','Check first':'st-chk','During failover':'st-chk'};
const CATS={'Routing':['routing'],'Outbound internet (PAT)':['pat'],'Published servers (inbound)':['inbound'],'Access rules':['rules','objects'],'DNS changes':['inbound'],'Public IPs':[]};
function readinessView(){const n=R.names;let h=`<h2>Readiness per network</h2><p class=mut>${esc(n.A)} &rarr; ${esc(n.B)}</p>`+R.readiness.map(c=>`<p class="verdict ${c.ready?'ok':'no'}">${esc(c.verdict)}</p><p class=reason>${esc(c.reason||'')}</p>`).join('');
const cnt=l=>[l.actions?l.actions+' to fix':'',l.decisions?l.decisions+(l.decisions>1?' choices':' choice')+' needed':'',l.checks?l.checks+' to verify':''].filter(x=>x).join(', ');
h+='<details><summary>Per area (click a line to open its findings)</summary><div class=cards>'+R.readiness.map(c=>`<div class=card><h3>${esc(c.title||c.subnet)}</h3><table>`+c.lines.map(l=>
`<tr class=link data-s="${esc(c.subnet)}" data-l="${esc(l.name)}"><td>${esc(l.name)}</td><td class="${STC[l.state]}">${esc(l.label||l.state)}${cnt(l)?' ('+cnt(l)+')':''}</td><td class=mut>${esc(l.note||'')}</td></tr>`).join('')+'</table></div>').join('')+'</div></details>';
h+='<p class=mut>Public IPs and choices open the Your choices tab.</p>';
$('v-readiness').innerHTML=h;
document.querySelectorAll('#v-readiness tr.link').forEach(tr=>tr.onclick=()=>{const c=CATS[tr.dataset.l]||[];
if(!c.length||tr.querySelector('.st-dec')&&tr.dataset.l!='Access rules'&&tr.dataset.l!='Published servers (inbound)'){show('decisions');return}
$('fcat').value=c[0];$('fscope').value=tr.dataset.s;$('fstate').value='';$('ftext').value=tr.dataset.l=='DNS changes'?'DNS:':'';findingsView();show('findings')})}
function fillScopes(){$('fscope').innerHTML='<option value="">all subnets</option>'+R.readiness.map(c=>`<option value="${esc(c.subnet)}">${esc(c.scope)}</option>`).join('')}
['fcat','fscope','fstate'].forEach(i=>$(i).onchange=findingsView);$('ftext').oninput=findingsView;
function shownFindings(){const c=$('fcat').value,s=$('fscope').value,st=$('fstate').value,t=$('ftext').value.toLowerCase();
return R.findings.filter(f=>(!c||f.category==c)&&(!s||f.scopes.includes(s))&&(st?f.state==st:f.state!='not needed')&&
(!t||(f.what+' '+f.fix.fmc.join(' ')+' '+f.evidence.map(e=>e.text).join(' ')).toLowerCase().includes(t)))}
function findingsView(){const fs=shownFindings();$('fcount').textContent=fs.length+' of '+R.findings.length+' findings';
const lim=fs.slice(0,200);$('flist').innerHTML=lim.map(f=>`<div class="finding state-${f.state.replace(' ','-')}" data-k="${f.key}">
<span class=fb><button class=sec data-a=fix>Fix</button><button class=sec data-a="not needed">Not needed</button><button class=sec data-a=later>Later</button>${f.state!='open'?'<button class=sec data-a=open>Reset</button>':''}</span>
<span class=mut>#${f.n}</span> <span class=cat>${esc(f.category)}</span> <span class=cat>${esc(LV[f.level]||'')}</span> <span class=mut>${esc(f.scope)}</span> <b class="${f.state=='fix'?'st-ok':''}">${f.state!='open'?esc(f.state+(f.reason?': '+f.reason:'')):''}</b>
${(f.flags||[]).map(x=>`<div class=flag>&#9888; ${esc(x)}</div>`).join('')}${f.suggest?`<div class=flag>Suggested: ${esc(f.suggest)}</div>`:''}
${f.fix.objects.length?'<p>Objects to create first:</p><ul>'+f.fix.objects.map(o=>`<li><code>${esc(o.name)}</code> = ${esc(o.value)}</li>`).join('')+'</ul>':''}
${parts({what:f.what,why:f.why,fmc:f.fix.fmc,cli:f.fix.objects.flatMap(o=>o.cli).concat(f.fix.cli),verify:f.verify})}
<details><summary>Evidence (${f.evidence.length})</summary>${f.evidence.map(e=>`<div class=ev><b>${esc(e.device)}</b> line ${e.line||'-'}: <code>${esc(e.text)}</code></div>`).join('')}</details></div>`).join('')+(fs.length>200?`<p class=mut>first 200 of ${fs.length}: narrow the filter</p>`:'');
document.querySelectorAll('#flist .fb button').forEach(b=>b.onclick=()=>setState([b.closest('.finding').dataset.k],b.dataset.a))}
const LV={fix:'thing to fix',choice:'your choice needed',check:'check on firewall',review:'review later'};
async function setState(keys,a){let why='';if(a=='not needed'){why=prompt('Reason (required)');if(!why)return}
P.finding_state=P.finding_state||{};keys.forEach(k=>{if(a=='open')delete P.finding_state[k];else P.finding_state[k]={state:a,reason:why}});await pushState()}
$('fallfix').onclick=()=>{const fs=shownFindings();if(fs.length&&confirm('Mark '+fs.length+' shown findings as Fix?'))setState(fs.map(f=>f.key),'fix')};
async function pushState(){const r=await fetch('/api/state',{method:'POST',headers:{'Content-Type':'application/json'},
body:JSON.stringify({session:R.session,finding_state:P.finding_state||{},decision_state:P.decision_state||{}})});
if(!r.ok){alert(await r.text());return}Object.assign(R,await r.json());takeoverView();readinessView();findingsView();decisionsView();planView()}
function decisionsView(){const ds=R.decisions;let h=`<h2>Your choices (${ds.filter(d=>d.open).length} open)</h2><p class=mut>Things the tool cannot decide. Your choice is saved in the profile.</p>`;
h+=ds.map(d=>`<div class="decision ${d.open?'':'done'}" data-id="${esc(d.id)}"><b>${esc(d.kind)}</b> &middot; ${esc(d.title)}<p>${esc(d.text)}</p>
${(d.evidence||[]).map(e=>`<div class=ev><b>${esc(e.device)}</b> line ${e.line||'-'}: <code>${esc(e.text)}</code></div>`).join('')}
${d.math?'<ul class=math>'+d.math.map(m=>`<li>${esc(m)}</li>`).join('')+'</ul>':''}
${d.kind=='public pool'?`<p>Extra pool <input type=text class=pool placeholder="e.g. 192.0.2.0/24" size=22> needed ${d.needed}, free ${d.available}</p>`:''}
<p>${d.options.map(o=>`<button class=sec data-o="${esc(o)}">${esc(o)}</button>`).join('')} ${d.choice?(d.default&&d.choice==d.default&&!(P.decision_state||{})[d.id]?'default applied: <b>':'chosen: <b>')+esc(d.choice)+'</b>':''}</p></div>`).join('');
$('v-decisions').innerHTML=h;
document.querySelectorAll('#v-decisions .decision button').forEach(b=>b.onclick=()=>decide(b.closest('.decision').dataset.id,b.dataset.o,b.closest('.decision')))}
async function decide(id,o,el){const d=R.decisions.find(x=>x.id==id);P.decision_state=P.decision_state||{};const e={choice:o};
if(d.rule)e.rule=d.rule;if(d.finding)e.finding=d.finding;
if(d.kind=='public pool'&&o.startsWith('enter')){const v=el.querySelector('.pool').value.trim();if(!v){alert('enter the extra pool first');return}e.pool=v;
P.whatif=P.whatif||{};P.whatif.public=[...(P.whatif.public||[]),...v.split(',').map(x=>x.trim())]}
if(d.kind=='L7 action'){P.rule_actions=P.rule_actions||{};P.rule_actions[d.rule]=o}
if((d.kind=='test server'||d.kind=='rule to verify')&&d.finding){P.finding_state=P.finding_state||{};
P.finding_state[d.finding]=o.startsWith('not needed')?{state:'not needed',reason:o}:(o.startsWith('replicate')?{state:'fix',reason:''}:{state:'open',reason:''})}
P.decision_state[id]=e;
if(d.kind=='L7 action'||d.kind=='public pool'){await go(true);show('decisions')}else await pushState()}
function planView(){const p=R.plan;let h=`<h2>Remediation plan</h2><p>${p.total} changes from ${p.findings} findings marked Fix, grouped by FMC page. Nothing is pushed.</p>${p.public_text?'<p><b>'+esc(p.public_text)+'</b></p>':''}
<p><a href="/api/plan/${R.session}.md" download="change-plan.md"><button class=sec>Markdown</button></a><a href="/api/plan/${R.session}.csv" download="change-plan.csv"><button class=sec>CSV</button></a>
<a href="/api/plan/${R.session}.html" download="change-plan.html"><button class=sec>HTML</button></a></p>`;
h+=p.groups.map(g=>`<h3>${esc(g.name)} (${g.count})</h3><ol>`+g.items.map(it=>`<li>${esc(it.fmc)}${it.finding?'<div class=mut>'+esc(it.finding)+'</div>':''}
${it.cli.length?'<pre>'+esc(it.cli.join('\n'))+'</pre>':''}${it.verify.length?'<div class=mut>Verify</div><pre>'+esc(it.verify.join('\n'))+'</pre>':''}</li>`).join('')+'</ol>').join('');
if(!p.findings)h+='<p class=mut>Mark findings as Fix in the Findings tab to build the plan.</p>';
if(R.known_gaps&&R.known_gaps.length)h+='<h3>Known gaps (ranked)</h3><table><tr><th>#</th><th>Gap</th><th>Impact</th><th>Workaround</th></tr>'+R.known_gaps.map(g=>`<tr><td>${g.rank}</td><td>${esc(g.gap)}</td><td>${esc(g.impact)}</td><td>${esc(g.workaround)}</td></tr>`).join('')+'</table>';
$('v-plan').innerHTML=h}
function tabs(){$('tabs').innerHTML=Object.keys(COLS).map(k=>`<button class="${k==cur?'on':''}" data-k=${k}>${k} (${(R[k]||[]).filter(r=>!r.row_state).length})</button>`).join('');
document.querySelectorAll('#tabs button').forEach(b=>b.onclick=()=>{cur=b.dataset.k;tabs();draw()});$('rowctl').classList.remove('hide');$('l7ctl').classList.toggle('hide',cur!='rules')}
// ---------- interfaces
function showDet(){const d=R.detected;$('det').classList.remove('hide');
let c='';if(d.chain){const k=d.chain;c=`<p>Chain: edge A1 <b>${esc(k.edge)}</b>, inner A2 <b>${esc(k.inner)}</b>, A1&rarr;A2 via ${esc(k.a1_toward_a2)}, A2 uplink ${esc(k.a2_uplink)} <span class=flag>${esc(k.note)}</span></p><table><tr><th>A2 inside</th><th>A2 ifc</th><th>A1 via</th><th>path</th></tr>`+
k.paths.map(x=>`<tr><td>${esc(x.subnets)}</td><td>${esc(x.a2_ifc)}</td><td>${esc(x.a1_ifc)}</td><td>${esc(x.path)}</td></tr>`).join('')+'</table>'}
$('chain').innerHTML=c;$('bifs').innerHTML=R.b_ifcs.map(x=>`<option value="${esc(x)}">`).join('');
const newb=Object.values(P.interface_map).filter(v=>v&&v!='ignore'&&!R.b_ifcs.includes(v));
$('imap').innerHTML='<tr><th>include</th><th>A interface</th><th>role</th><th>B interface</th><th>how</th><th>flag / note</th></tr>'+d.interface_map.map(m=>{
const ign=P.interface_map[m.a]=='ignore'||P.roles_a[m.a]=='ignore';const role=P.roles_a[m.a]||(m.a_role=='ignored'?'ignore':(P.outside_a.includes(m.a)?'outside':(m.a_role=='chain link'?'chain link':'inside')));
const b=P.interface_map[m.a]||'';const opts=[...R.b_ifcs,...newb.filter((x,i,a)=>a.indexOf(x)==i)];
return `<tr data-a="${esc(m.a)}"><td><input type=checkbox class=inc ${ign?'':'checked'}></td><td>${esc(m.a)}<div class=mut>${esc(m.a_reason)}</div></td>
<td><select class=role>${['outside','inside','chain link','ignore'].map(x=>`<option ${x==role?'selected':''}>${x}</option>`).join('')}</select></td>
<td><select class=bif><option value="">-</option><option ${b=='ignore'?'selected':''}>ignore</option>${opts.map(x=>`<option ${x==b?'selected':''}>${esc(x)}</option>`).join('')}<option value="__new">new on B...</option></select></td>
<td>${esc(m.how)}</td><td class=flag>${esc([m.flag,m.note].filter(x=>x).join(' '))}</td></tr>`}).join('');
document.querySelectorAll('#imap .bif').forEach(s=>s.onchange=()=>{if(s.value=='__new'){const n=prompt('Name of the new interface on B (e.g. RESEARCH, OUTSIDE2)');
if(n){const o=document.createElement('option');o.textContent=n;s.insertBefore(o,s.lastChild);s.value=n}else s.value=''}});
$('boutl').textContent=R.names.B_short+' outside interfaces:';$('broles').innerHTML=Object.keys(d.roles_b).map(k=>`<label><input type=checkbox class=bout value="${esc(k)}" ${P.outside_b.includes(k)?'checked':''}> ${esc(k)}</label>`).join(' ');
$('puba').value=P.public_a.join(', ');$('pubb').value=P.public_b.join(', ');$('pubnote').textContent='mapped: A '+d.public_a.mapped_count+', B '+d.public_b.mapped_count+' addresses (per-/24 ranges are a guess)';
$('site').value=P.type;scopeInit();whatifDraw()}
// ---------- scope
let SC=[];
function scopeInit(){const on=new Set(P.scope);const seen=new Set();SC=[];
for(const p of P.scope){SC.push({p,n:P.scope_names[p]||'',on:true});seen.add(p)}
for(const c of R.detected.scope_candidates){if(!seen.has(c.subnet)){SC.push({p:c.subnet,n:c.name,on:false});seen.add(c.subnet)}}scopeDraw()}
const ip2n=s=>s.split('.').reduce((a,b)=>a*256+(+b),0);
function rng(p){const [a,l]=p.split('/');const n=ip2n(a),sz=2**(32-(+l||32));const s=n-(n%sz);return [s,s+sz-1]}
function inside(c,p){try{const [a,b]=rng(c),[x,y]=rng(p);return a>=x&&b<=y&&c!=p}catch(e){return false}}
function scopeDraw(){const W=R.detected.scope_warnings||[];const f=$('sflt').value.toLowerCase();
$('scope').innerHTML='<tr><th>on</th><th>prefix</th><th>name</th><th></th></tr>'+SC.map((s,i)=>{const hid=f&&!(s.p+' '+s.n).toLowerCase().includes(f);
const w=W.filter(x=>x.prefix==s.p);const kids=(R.detected.prefixes||[]).filter(x=>inside(x.prefix,s.p));
return `<tr class="${hid?'hide':''}" data-i=${i}><td><input type=checkbox class=son ${s.on?'checked':''}></td><td><input type=text class=sp value="${esc(s.p)}" size=18></td>
<td><input type=text class=sn value="${esc(s.n)}" size=24>${w.map(x=>`<div class=warn>${esc(x.message)} <button type=button class=sec data-use="${esc(x.suggest)}">use ${esc(x.suggest)}</button></div>`).join('')}</td>
<td>${kids.length?`<button type=button class=sec data-exp=${i}>expand (${kids.length})</button>`:''}<button type=button class=x data-rm=${i}>remove</button></td></tr>
<tr class="kids hide" id=k${i}><td></td><td colspan=3>${kids.map(k=>`<label><input type=checkbox class=kid value="${esc(k.prefix)}" data-n="${esc(k.where)}"> ${esc(k.prefix)} <span class=mut>${esc(k.where)}</span></label><br>`).join('')}
<button type=button class=sec data-addk=${i}>add ticked, untick ${esc(s.p)}</button></td></tr>`}).join('');
$('scnt').textContent=SC.filter(s=>s.on).length+' of '+SC.length+' on';
document.querySelectorAll('#scope tr[data-i]').forEach(tr=>{const s=SC[+tr.dataset.i];tr.querySelector('.son').onchange=e=>{s.on=e.target.checked;$('scnt').textContent=SC.filter(s=>s.on).length+' of '+SC.length+' on'};
tr.querySelector('.sp').onchange=e=>s.p=e.target.value.trim();tr.querySelector('.sn').onchange=e=>s.n=e.target.value});
document.querySelectorAll('[data-rm]').forEach(b=>b.onclick=()=>{SC.splice(+b.dataset.rm,1);scopeDraw()});
document.querySelectorAll('[data-exp]').forEach(b=>b.onclick=()=>$('k'+b.dataset.exp).classList.toggle('hide'));
document.querySelectorAll('[data-use]').forEach(b=>b.onclick=()=>{const i=+b.closest('tr').dataset.i;SC[i].p=b.dataset.use;scopeDraw()});
document.querySelectorAll('[data-addk]').forEach(b=>b.onclick=()=>{const i=+b.dataset.addk;const ks=[...$('k'+i).querySelectorAll('.kid:checked')];
for(const k of ks){if(!SC.find(s=>s.p==k.value))SC.push({p:k.value,n:'',on:true});else SC.find(s=>s.p==k.value).on=true}if(ks.length)SC[i].on=false;scopeDraw()})}
$('sflt').oninput=scopeDraw;
const vis=()=>[...document.querySelectorAll('#scope tr[data-i]:not(.hide)')].map(tr=>SC[+tr.dataset.i]);
$('sall').onclick=()=>{vis().forEach(s=>s.on=true);scopeDraw()};$('snone').onclick=()=>{vis().forEach(s=>s.on=false);scopeDraw()};$('sinv').onclick=()=>{vis().forEach(s=>s.on=!s.on);scopeDraw()};
$('addp').onclick=()=>{const p=$('newp').value.trim();if(!/^\d+\.\d+\.\d+\.\d+(\/\d+)?$/.test(p)){alert('prefix like 10.1.0.0/16');return}
SC.unshift({p:p.includes('/')?p:p+'/32',n:$('newn').value.trim(),on:true});$('newp').value=$('newn').value='';scopeDraw()};
// ---------- what-if
function whatifDraw(){const w=P.whatif||{};const rows=[];
(w.routes||[]).forEach((r,i)=>rows.push(['routes',i,r.prefix,r.ifc,r.nexthop||'']));(w.public||[]).forEach((r,i)=>rows.push(['public',i,r,'','']));
(w.interfaces||[]).forEach((r,i)=>rows.push(['interfaces',i,r.name||r,r.role||'inside','']));(w.nat_pools||[]).forEach((r,i)=>rows.push(['nat_pools',i,r.real,r.mapped||'interface',(r.in_ifc||'')+','+(r.out_ifc||'')]));
$('wi').innerHTML='<tr><th>kind</th><th>value</th><th>B interface / role / mapped</th><th>next hop / in,out</th><th></th></tr>'+rows.map(r=>`<tr><td>${r[0]}</td><td>${esc(r[2])}</td><td>${esc(r[3])}</td><td>${esc(r[4])}</td><td><button type=button class=x data-wk=${r[0]} data-wi=${r[1]}>remove</button></td></tr>`).join('');
document.querySelectorAll('[data-wk]').forEach(b=>b.onclick=()=>{P.whatif[b.dataset.wk].splice(+b.dataset.wi,1);whatifDraw()})}
$('wiadd').onclick=()=>{const k=$('wik').value,v=$('wiv').value.trim(),a=$('wia').value.trim(),b=$('wib').value.trim();if(!v)return;P.whatif=P.whatif||{};const L=P.whatif[k]=P.whatif[k]||[];
if(k=='routes'){if(!a){alert('give the B interface');return}L.push({prefix:v,ifc:a,nexthop:b})}else if(k=='public')L.push(v);else if(k=='interfaces')L.push({name:v,role:a||'inside'});
else{const [i,o]=(b||'INSIDE,OUTSIDE').split(',');L.push({real:v,mapped:a||'interface',in_ifc:i,out_ifc:o})}$('wiv').value=$('wia').value=$('wib').value='';whatifDraw()};
// ---------- collect
function edits(){const im={},ra={};document.querySelectorAll('#imap tr[data-a]').forEach(tr=>{const a=tr.dataset.a,b=tr.querySelector('.bif').value,role=tr.querySelector('.role').value;
const inc=tr.querySelector('.inc').checked;if(!inc||role=='ignore')im[a]='ignore';else if(b&&b!='__new')im[a]=b;ra[a]=inc?role:'ignore'});
const sp=s=>s.split(',').map(x=>x.trim()).filter(x=>x);const on=SC.filter(s=>s.on&&s.p);const names={};SC.forEach(s=>{if(s.n)names[s.p]=s.n});
return Object.assign({},P,{interface_map:im,roles_a:ra,outside_a:Object.entries(ra).filter(x=>x[1]=='outside').map(x=>x[0]),
outside_b:[...document.querySelectorAll('.bout:checked')].map(x=>x.value),public_a:sp($('puba').value),public_b:sp($('pubb').value),
type:$('site').value,scope:on.map(s=>s.p),scope_names:names,whatif:P.whatif||{},rule_actions:P.rule_actions||{},row_state:P.row_state||{}})}
$('saveprof').onclick=()=>{const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([JSON.stringify(edits(),null,1)],{type:'application/json'}));a.download='fwsync-profile.json';a.click()};
$('dl').onclick=()=>{const a=document.createElement('a');a.href='/api/report/'+R.session+'.html';a.download='fwsync-report.html';a.click()};
// ---------- summary + tables
function showSum(){const rows=R.summary.filter(r=>SUMC.some(c=>r[c]));
$('summary').innerHTML='<h3>Summary per scope subnet</h3><div class=wrap><table><tr><th>scope</th><th>subnet</th>'+SUMC.map(c=>`<th>${c}</th>`).join('')+'</tr>'+
rows.map(r=>`<tr><td>${esc(r.scope)}</td><td>${esc(r.subnet)}</td>`+SUMC.map(c=>`<td>${esc(Object.entries(r[c]||{}).map(x=>L(x[0])+' '+x[1]).join(', '))}</td>`).join('')+'</tr>').join('')+'</table></div>'+
(R.planned.length?'<p class=warn>What-if items assumed on B: '+R.planned.map(p=>esc(p.item)).join('; ')+'</p>':'')}
function draw(){const c=COLS[cur],rows=R[cur]||[];const showh=$('showhidden').checked;const rc=cur!='planned';
let h='<table><tr><th><input type=checkbox id=all></th>'+(rc?'<th>row</th>':'')+(cur=='rules'||cur=='held_rules'?'<th>action</th>':'')+c.map(x=>`<th>${x}</th>`).join('')+'</tr><tr><th></th>'+(rc?'<th></th>':'')+(cur=='rules'||cur=='held_rules'?'<th></th>':'')+c.map((x,i)=>`<th><input data-i=${i} class=flt size=6></th>`).join('')+'</tr>';
rows.forEach((r,ri)=>{const st=(P.row_state||{})[r.key];if(st&&st.state=='not needed'&&!showh)return;
const rn=(r.rule||'').split(' ∩ ')[0];const act=(P.rule_actions||{})[rn]||'';
h+=`<tr class="${st?'st':''}" data-ri=${ri}><td>${r.id?`<input type=checkbox class=ck value="${esc(r.id)}" ${sel.has(r.id)?'checked':''}>`:''}</td>`+
(rc?`<td><select class=rs><option value="">include</option><option ${st&&st.state=='exclude'?'selected':''}>exclude</option><option ${st&&st.state=='not needed'?'selected':''}>not needed</option></select>${st&&st.reason?'<div class=mut>'+esc(st.reason)+'</div>':''}</td>`:'')+
(cur=='rules'||cur=='held_rules'?`<td>${rn?`<select class=ra><option value="">as config</option>${['permit','block','ignore'].map(x=>`<option ${x==act?'selected':''}>${x}</option>`).join('')}</select>`:''}</td>`:'')+
c.map(x=>`<td ${x=='status'&&R.glossary&&R.glossary[r[x]]?'title="'+esc(R.glossary[r[x]])+'"':''} class="${x=='status'?'s-'+esc(String(r[x]).split(' ')[0].replace(',','')):''}">${esc(Array.isArray(r[x])?r[x].join(', '):(x=='status'?L(r[x]):r[x]))}</td>`).join('')+'</tr>'});
$('tbl').innerHTML=h+'</table>';const off=(rc?1:0)+(cur=='rules'||cur=='held_rules'?1:0)+1;
document.querySelectorAll('.ck').forEach(x=>x.onchange=()=>x.checked?sel.add(x.value):sel.delete(x.value));
document.querySelectorAll('.rs').forEach(s=>s.onchange=()=>{const r=rows[+s.closest('tr').dataset.ri];P.row_state=P.row_state||{};
if(!s.value)delete P.row_state[r.key];else P.row_state[r.key]={state:s.value,reason:s.value=='not needed'?(prompt('Reason (optional)')||''):''};s.closest('tr').classList.toggle('st',!!s.value)});
document.querySelectorAll('.ra').forEach(s=>s.onchange=()=>{const r=rows[+s.closest('tr').dataset.ri];const rn=r.rule.split(' ∩ ')[0];P.rule_actions=P.rule_actions||{};if(s.value)P.rule_actions[rn]=s.value;else delete P.rule_actions[rn]});
$('all').onchange=e=>document.querySelectorAll('#tbl tr:not([style*="none"]) .ck').forEach(x=>{x.checked=e.target.checked;x.onchange()});
document.querySelectorAll('.flt').forEach(i=>i.oninput=()=>{const f=[...document.querySelectorAll('.flt')].map(x=>x.value.toLowerCase());
[...document.querySelectorAll('#tbl tr')].slice(2).forEach(tr=>{tr.style.display=f.every((v,k)=>!v||tr.cells[k+off].textContent.toLowerCase().includes(v))?'':'none'})})}
$('showhidden').onchange=draw;
$('bapply').onclick=()=>{const v=$('bstate').value,why=$('breason').value;const rows=R[cur]||[];P.row_state=P.row_state||{};
document.querySelectorAll('#tbl tr[data-ri]').forEach(tr=>{if(tr.style.display=='none')return;const r=rows[+tr.dataset.ri];if(!v)delete P.row_state[r.key];else P.row_state[r.key]={state:v,reason:why}});draw()};
$('l7block').onclick=()=>{const f=$('l7f').value.trim().toLowerCase();if(!f)return;P.rule_actions=P.rule_actions||{};let n=0;
for(const r of [...R.rules,...(R.held_rules||[])]){const rn=(r.rule||'').split(' ∩ ')[0];if(rn&&rn.toLowerCase().includes(f)){if(P.rule_actions[rn]!='block')n++;P.rule_actions[rn]='block'}}draw();alert(n+' rule names marked as block; press Compare again')};
$('gen').onclick=async()=>{if(!R)return;const r=await fetch('/api/generate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({session:R.session,ids:[...sel]})});
const g=await r.json();$('cli').textContent=g.cli.join('\n');$('chg').textContent=g.changes.map((x,i)=>(i+1)+'. '+x).join('\n')};
</script></body></html>"""
