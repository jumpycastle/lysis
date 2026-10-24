"""Generate an interactive, self-contained threat-model diagram (HTML) from a run.

Layout is computed here in Python (trust zones as nested container boxes, grid-packed); the embedded JS only
handles interaction: select/dim/clear, per-finding triage with localStorage, category filters,
and a prior-assessment overlay. No network, no build step, works offline in any browser.
"""
from __future__ import annotations

import html
import json
import re
from typing import Optional

from .schema import Finding, PriorAssessment, SystemModel

# ---- geometry
NODE_W, NODE_H = 190, 56
V_GAP = 26            # vertical gap between component rows inside a zone
INNER_H_GAP = 26      # horizontal gap between component columns inside a zone
ZONE_PAD_X, ZONE_PAD_Y = 18, 40   # inner padding; ZONE_PAD_Y leaves room for the zone label
ZONE_GAP = 34         # gap between zone boxes
MARGIN = 16

# zones are ordered left-to-right by this priority, then first-seen
ZONE_ORDER = ["actor", "internet", "edge", "dmz", "app", "application", "service", "compute",
              "data", "storage", "internal", "dev", "third", "external", "vendor", "saas"]


def _zone_rank(label: str) -> int:
    l = label.lower()
    for i, key in enumerate(ZONE_ORDER):
        if key in l:
            return i
    return len(ZONE_ORDER)


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (s or "").lower())


def _wrap(s: str, width: int) -> list[str]:
    out, line = [], ""
    for w in (s or "").split():
        if len(line) + len(w) + 1 > width and line:
            out.append(line)
            line = w
        else:
            line = (line + " " + w) if line else w
    if line:
        out.append(line)
    return out[:3]


def _layout(model: SystemModel):
    """Return (nodes dict keyed by id, zones list, width, height, name->id map)."""
    # build node list from components + external data-flow endpoints + users
    comps = list(model.components)
    comp_names = {_norm(c.name) for c in comps}
    nodes: dict[str, dict] = {}
    name_to_id: dict[str, str] = {}

    def add(name, kind, techs, zone):
        nid = "n%d" % len(nodes)
        sub = ", ".join(techs) if techs else kind
        nodes[nid] = {"id": nid, "label": name, "sub": sub, "zone": zone or "System", "kind": kind or ""}
        name_to_id[_norm(name)] = nid
        return nid

    for c in comps:
        add(c.name, c.kind or "component", c.technologies, c.trust_zone or "System")
    # external endpoints referenced by flows but not modeled as components
    for fl in model.data_flows:
        for ep in (fl.source, fl.destination):
            if ep and _norm(ep) not in comp_names and _norm(ep) not in name_to_id:
                add(ep, "external", [], "External")
    # users as actors, if not already present
    for u in model.users:
        if _norm(u.name) not in name_to_id:
            add(u.name, "actor", [], "Actors")

    if not nodes:  # nothing to draw
        return {}, [], 400, 200, {}

    # group by zone
    zmap: dict[str, list[str]] = {}
    for nid, n in nodes.items():
        zmap.setdefault(n["zone"], []).append(nid)
    zones_sorted = sorted(zmap, key=lambda z: (_zone_rank(z), z.lower()))

    # each zone is a container box; its components sit in a small inner grid so a busy
    # zone grows into a block rather than a tall single column.
    def inner_cols(n: int) -> int:
        return 1 if n <= 3 else 2 if n <= 6 else 3

    zinfo: dict[str, dict] = {}
    for z in zones_sorted:
        members = zmap[z]
        cols = inner_cols(len(members))
        rows = (len(members) + cols - 1) // cols
        zw = cols * NODE_W + (cols - 1) * INNER_H_GAP + 2 * ZONE_PAD_X
        zh = ZONE_PAD_Y + rows * NODE_H + (rows - 1) * V_GAP + ZONE_PAD_X
        zinfo[z] = {"members": members, "cols": cols, "rows": rows, "w": zw, "h": zh}

    # pack the zone boxes into a 2-D grid (shelves), preserving the actor->data flow order
    # left-to-right then wrapping down, so the result reads like an architecture diagram.
    nz = len(zones_sorted)
    per_row = nz if nz <= 3 else 2 if nz == 4 else 3 if nz <= 9 else 4

    zones = []
    y = MARGIN
    max_right = 0
    for i in range(0, nz, per_row):
        row = zones_sorted[i:i + per_row]
        row_h = max(zinfo[z]["h"] for z in row)
        x = MARGIN
        for z in row:
            zi = zinfo[z]
            for k, nid in enumerate(zi["members"]):
                col, r = k % zi["cols"], k // zi["cols"]
                nodes[nid].update(
                    x=x + ZONE_PAD_X + col * (NODE_W + INNER_H_GAP),
                    y=y + ZONE_PAD_Y + r * (NODE_H + V_GAP),
                    w=NODE_W, h=NODE_H)
            zones.append({"label": z, "x": x, "y": y, "w": zi["w"], "h": zi["h"]})
            x += zi["w"] + ZONE_GAP
            max_right = max(max_right, x - ZONE_GAP)
        y += row_h + ZONE_GAP

    width = max_right + MARGIN
    height = (y - ZONE_GAP) + MARGIN
    return nodes, zones, width, height, name_to_id


def _anchor(finding_component: str, title: str, name_to_id: dict, nodes: dict) -> Optional[str]:
    """Best-effort map a finding to a node id."""
    if finding_component:
        nid = name_to_id.get(_norm(finding_component))
        if nid:
            return nid
        # substring match
        fn = _norm(finding_component)
        for name, nid in name_to_id.items():
            if name and (name in fn or fn in name):
                return nid
    # fall back to scanning the title for a component name
    t = _norm(title)
    best = None
    for name, nid in name_to_id.items():
        if len(name) >= 4 and name in t:
            if best is None or len(name) > best[0]:
                best = (len(name), nid)
    return best[1] if best else None


_SEV_FILL = {"Critical": "#c5221f", "High": "#e8710a", "Medium": "#f9ab00",
             "Low": "#1a73e8", "Informational": "#80868b"}
_OVL_RING = {"none": "#137333", "": "#137333", "partial": "#b06000", "duplicate": "#c5221f"}
_CONF_PIP = {"High": "#137333", "Medium": "#f9ab00", "Low": "#c5221f"}


def build_diagram(model: SystemModel, findings: list[Finding], meta: dict,
                  prior: Optional[PriorAssessment] = None, chains: Optional[list] = None) -> str:
    nodes, zones, W, H, name_to_id = _layout(model)

    # edges from data flows
    edges = []
    for fl in model.data_flows:
        a = name_to_id.get(_norm(fl.source))
        b = name_to_id.get(_norm(fl.destination))
        if a and b and a != b:
            edges.append({"a": a, "b": b, "l": (fl.data or "")[:40],
                          "dash": bool(fl.crosses_trust_boundary)})

    tray = []  # findings with no anchor
    fdata = []
    for i, f in enumerate(findings, 1):
        nid = _anchor(f.component, f.title, name_to_id, nodes)
        if nid is None:
            tray.append(i)
        fdata.append({
            "n": i, "id": f.id, "sev": f.severity, "conf": f.confidence,
            "ovl": (f.prior_overlap or ("" if prior is None else "none")),
            "at": nid, "title": f.title, "cat": f.category,
            "owner": f.suggested_owner, "action": "", "prior_refs": f.prior_refs,
            "stride": f.stride_category,
        })

    pdata = []
    if prior and prior.findings:
        for j, pf in enumerate(prior.findings, 1):
            nid = _anchor(pf.component, pf.title, name_to_id, nodes)
            pdata.append({"n": str(j), "id": pf.id, "sev": pf.severity, "status": pf.status,
                          "at": nid, "title": pf.title})

    # resolve attack-chain steps to marker references (tm finding number or prior id)
    tm_by_id = {f.id: i for i, f in enumerate(findings, 1)}
    prior_ids = {pf.id for pf in (prior.findings if prior else [])}
    cdata = []
    for c in (chains or []):
        steps = []
        for sid in getattr(c, "steps", []):
            if sid in tm_by_id:
                steps.append({"k": "tm", "ref": tm_by_id[sid]})
            elif sid in prior_ids:
                steps.append({"k": "pt", "ref": sid})
        # keep only chains with at least two resolvable, placed steps
        if len(steps) >= 2:
            cdata.append({"id": c.id, "name": c.name, "narrative": getattr(c, "narrative", ""),
                          "sev": getattr(c, "severity", "High"), "steps": steps})

    data = {
        "system": model.system_name, "W": W, "H": H,
        "zones": zones, "nodes": list(nodes.values()), "edges": edges,
        "findings": fdata, "prior": pdata, "tray": tray, "chains": cdata,
        "sevFill": _SEV_FILL, "ovlRing": _OVL_RING, "confPip": _CONF_PIP,
        "priorKind": (prior.source_kind if prior else ""),
        "meta": {"created": meta.get("created_utc", ""), "version": meta.get("tool_version", "")},
    }
    return _TEMPLATE.replace("/*__DATA__*/null", json.dumps(data)).replace(
        "__TITLE__", html.escape(model.system_name or "System"))


_TEMPLATE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>__TITLE__ — Threat Model</title>
<style>
:root{--bg:#fff;--fg:#202124;--muted:#5f6368;--line:#80868b;--zone:#f1f3f4;--box:#fff;--boxb:#9aa0a6;--card:#f8f9fa;--chain:#d93025}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#1f1f1f;--fg:#e8eaed;--muted:#9aa0a6;--line:#9aa0a6;--zone:#2a2a2a;--box:#303134;--boxb:#5f6368;--card:#2a2a2a}}
:root[data-theme="dark"]{--bg:#1f1f1f;--fg:#e8eaed;--muted:#9aa0a6;--line:#9aa0a6;--zone:#2a2a2a;--box:#303134;--boxb:#5f6368;--card:#2a2a2a}
body{margin:0;background:var(--bg);color:var(--fg);font-family:Arial,Helvetica,sans-serif}
header{padding:12px 16px 4px}h1{font-size:17px;margin:0 0 3px}p.sub{margin:0;color:var(--muted);font-size:12px;max-width:1100px}
.bar{display:flex;flex-wrap:wrap;gap:8px;padding:8px 16px}
.bar button{font:inherit;font-size:12px;padding:6px 10px;border-radius:14px;border:1px solid var(--boxb);background:var(--box);color:var(--fg);cursor:pointer}
.bar button.on{background:var(--chain);color:#fff;border-color:var(--chain)}
#triagebar #tcount{font-size:12px;color:var(--muted);align-self:center;margin-right:4px}
.wrap{display:grid;grid-template-columns:minmax(0,1fr) 340px;gap:12px;padding:0 16px 16px}
@media (max-width:1000px){.wrap{grid-template-columns:1fr}}
.canvas{overflow:hidden;position:relative;border:1px solid var(--boxb);border-radius:8px;background:var(--bg)}
svg{display:block;width:100%;height:78vh;cursor:grab;touch-action:none}svg.panning{cursor:grabbing}
.zoomctl{position:absolute;top:8px;right:8px;display:flex;gap:4px;z-index:5}
.zoomctl button{font:inherit;font-size:15px;line-height:1;width:30px;height:30px;border-radius:6px;border:1px solid var(--boxb);background:var(--box);color:var(--fg);cursor:pointer}
.zoomctl button.wide{width:auto;padding:0 9px;font-size:12px}
.hint{position:absolute;left:8px;bottom:8px;font-size:11px;color:var(--muted);background:var(--box);border:1px solid var(--boxb);border-radius:6px;padding:3px 7px;opacity:.85;z-index:5}
.panel{border:1px solid var(--boxb);border-radius:8px;background:var(--card);padding:12px;font-size:12px;max-height:88vh;overflow:auto}
.panel h2{font-size:14px;margin:2px 0 8px}
.f{padding:6px 4px;border-bottom:1px solid var(--boxb);cursor:pointer;display:flex;gap:8px}
.f:hover,.f.sel{background:rgba(128,128,128,.12)}
.dot{flex:0 0 22px;height:22px;border-radius:50%;color:#fff;font-weight:bold;display:flex;align-items:center;justify-content:center;font-size:11px}
.tag{font-size:10px;color:var(--muted)}
#detail{margin-top:10px;padding:8px;border:1px dashed var(--boxb);border-radius:6px;min-height:48px}
.zone{fill:var(--zone);stroke:var(--boxb);stroke-width:1.1}
.zl{font-size:12px;font-weight:bold;fill:var(--fg)}
.node rect{fill:var(--box)}
.node .t1{font-size:11px;fill:var(--fg);font-weight:bold}.node .t2{font-size:9.5px;fill:var(--muted)}
.edge path{fill:none;stroke:var(--line);stroke-width:1.2;opacity:.5}.edge.cross path{stroke:var(--high);opacity:.95;stroke-dasharray:6 4}
.edge text{font-size:9px;fill:var(--muted);paint-order:stroke;stroke:var(--bg);stroke-width:3px}
.mk{cursor:pointer}.mk text{font-size:11px;font-weight:bold;fill:#fff;text-anchor:middle;dominant-baseline:central;pointer-events:none}
.mk.dim{opacity:.15!important}
.mk.stk-remediated{opacity:.45}.mk.stk-fp{opacity:.16}.mk.stk-accepted{opacity:.55}
.f.stk-remediated{opacity:.6}.f.stk-fp{opacity:.42;text-decoration:line-through}.f.stk-accepted{opacity:.72}
.rowsel{margin-top:5px;font-size:11px;padding:2px 4px;border:1px solid var(--boxb);border-radius:6px;background:var(--box);color:var(--fg)}
.sbtn{font-size:11px;padding:3px 7px;margin:3px 3px 0 0;border:1px solid var(--boxb);background:var(--box);color:var(--fg);border-radius:10px;cursor:pointer}
.sbtn.on{background:#1a73e8;color:#fff;border-color:#1a73e8}
.lg text{font-size:10px;fill:var(--fg)}
.chainpath{animation:dash 1s linear infinite;pointer-events:none}@keyframes dash{to{stroke-dashoffset:-13}}
#chainbar button.on{background:var(--chain);color:#fff;border-color:var(--chain)}
</style></head><body>
<header><h1>__TITLE__ — Threat Model</h1>
<p class="sub" id="sub"></p></header>
<div class="bar" id="chainbar"></div>
<div class="bar" id="triagebar"></div>
<div class="wrap"><div class="canvas"><div class="zoomctl" id="zoomctl"></div><div class="hint">drag to pan · scroll to zoom</div><svg id="svg" role="img" aria-label="Threat model diagram"></svg></div>
<aside class="panel"><h2>Findings</h2><div id="list"></div><div id="detail">Select a finding.</div></aside></div>
<script>
const D=/*__DATA__*/null;
const NS='http://www.w3.org/2000/svg',svg=document.getElementById('svg');
const FULL={x:-12,y:-12,w:D.W+24,h:D.H+170};let VB={...FULL};
function applyVB(){svg.setAttribute('viewBox',VB.x+' '+VB.y+' '+VB.w+' '+VB.h)}
applyVB();
function clientToSvg(cx,cy){const r=svg.getBoundingClientRect();return [VB.x+(cx-r.left)/r.width*VB.w, VB.y+(cy-r.top)/r.height*VB.h]}
function fitTo(x0,y0,x1,y1,pad){pad=pad==null?40:pad;const r=svg.getBoundingClientRect();let w=(x1-x0)+2*pad,h=(y1-y0)+2*pad;const ar=(r.width||1)/(r.height||1);if(w/h<ar){w=h*ar}else{h=w/ar}VB={x:(x0+x1)/2-w/2,y:(y0+y1)/2-h/2,w:w,h:h};applyVB()}
function fitAll(){fitTo(FULL.x,FULL.y,FULL.x+FULL.w,FULL.y+FULL.h,0)}
function zoomBy(k){const cx=VB.x+VB.w/2,cy=VB.y+VB.h/2;VB={x:cx-VB.w*k/2,y:cy-VB.h*k/2,w:VB.w*k,h:VB.h*k};applyVB()}
(function(){const zc=document.getElementById('zoomctl');function zb(t,f,w){const b=document.createElement('button');b.textContent=t;if(w)b.className='wide';b.onclick=f;zc.appendChild(b)}
 zb('+',()=>zoomBy(0.8));zb('\u2212',()=>zoomBy(1.25));zb('Fit',()=>fitAll(),true);})();
svg.addEventListener('wheel',e=>{e.preventDefault();const [mx,my]=clientToSvg(e.clientX,e.clientY);const k=e.deltaY>0?1.12:0.89;VB={x:mx-(mx-VB.x)*k,y:my-(my-VB.y)*k,w:VB.w*k,h:VB.h*k};applyVB()},{passive:false});
let panning=false,justPanned=false,sx=0,sy=0,svb=null;
svg.addEventListener('mousedown',e=>{if(e.button!==0)return;panning=true;justPanned=false;sx=e.clientX;sy=e.clientY;svb={...VB}});
window.addEventListener('mousemove',e=>{if(!panning)return;const r=svg.getBoundingClientRect();if(Math.abs(e.clientX-sx)+Math.abs(e.clientY-sy)>3){justPanned=true;svg.classList.add('panning')}VB={x:svb.x-(e.clientX-sx)/r.width*svb.w,y:svb.y-(e.clientY-sy)/r.height*svb.h,w:svb.w,h:svb.h};applyVB()});
window.addEventListener('mouseup',()=>{panning=false;svg.classList.remove('panning')});
const el=(t,a,p=svg)=>{const e=document.createElementNS(NS,t);for(const k in a)e.setAttribute(k,a[k]);p.appendChild(e);return e};
document.getElementById('sub').textContent='Auto-generated by Lysis v'+D.meta.version+' · '+D.findings.length+' findings'+(D.prior.length?(' + '+D.prior.length+' prior '+(D.priorKind||'assessment')+' findings overlaid'):'')+'. Click a finding to focus (click again or empty space to clear); set each row status and use the filters to present more or fewer.';
const defs=el('defs',{});const mk=(id,c)=>{const m=el('marker',{id,viewBox:'0 0 10 10',refX:9,refY:5,markerWidth:7,markerHeight:7,orient:'auto-start-reverse'},defs);el('path',{d:'M0,0L10,5L0,10z',fill:c},m)};mk('ar','var(--line)');mk('arh','var(--chain)');mk('arX','var(--high)');
const NODE={};D.nodes.forEach(n=>NODE[n.id]=n);
D.zones.forEach(z=>{el('rect',{x:z.x,y:z.y,width:z.w,height:z.h,rx:9,class:'zone','stroke-dasharray':'6 4'});el('text',{x:z.x+10,y:z.y+20,class:'zl'}).textContent=z.label});
const eLayer=el('g',{}),nLayer=el('g',{}),cLayer=el('g',{id:'cLayer'}),mLayer=el('g',{}),pLayer=el('g',{id:'pLayer'});const MPOS={};
function C(id){const n=NODE[id];return[n.x+n.w/2,n.y+n.h/2]}
D.edges.forEach(e=>{const [ax,ay]=C(e.a),[bx,by]=C(e.b);const mx=(ax+bx)/2;const cross=!!e.dash;const g=el('g',{class:'edge'+(cross?' cross':'')},eLayer);
 el('path',{d:'M'+ax+','+ay+' C'+mx+','+ay+' '+mx+','+by+' '+bx+','+by,'marker-end':cross?'url(#arX)':'url(#ar)'},g);
 if(e.l)el('text',{x:mx,y:(ay+by)/2-3,'text-anchor':'middle'},g).textContent=e.l});
function shapeOf(n){const t=((n.kind||'')+' '+(n.label||'')).toLowerCase(),z=(n.zone||'').toLowerCase();
 if(/actor|external|user|client|third|internet|browser/.test(n.kind||'')||/external|actor|internet/.test(z))return 'external';
 if(/store|datastore|\bdb\b|database|sql|bucket|\bs3\b|\brds\b|queue|cache|clickhouse|lake|dynamo|redis|kafka|warehouse|postgres|glue|athena/.test(t))return 'store';
 return 'process'}
D.nodes.forEach(n=>{const g=el('g',{class:'node'},nLayer);const sh=shapeOf(n);
 if(sh==='store'){el('rect',{x:n.x,y:n.y,width:n.w,height:n.h,rx:0,fill:'var(--box)',stroke:'none'},g);
  el('line',{x1:n.x,y1:n.y,x2:n.x+n.w,y2:n.y,stroke:'var(--boxb)','stroke-width':2.4},g);
  el('line',{x1:n.x,y1:n.y+n.h,x2:n.x+n.w,y2:n.y+n.h,stroke:'var(--boxb)','stroke-width':2.4},g);
 } else {el('rect',{x:n.x,y:n.y,width:n.w,height:n.h,rx:(sh==='external'?0:11),fill:'var(--box)',stroke:'var(--boxb)','stroke-width':1.2},g);
  if(sh==='external')el('rect',{x:n.x+3,y:n.y+3,width:n.w-6,height:n.h-6,rx:0,fill:'none',stroke:'var(--boxb)','stroke-width':0.8},g);}
 el('text',{x:n.x+8,y:n.y+18,class:'t1'},g).textContent=n.label.slice(0,30);
 const lines=[];let line='';(n.sub||'').split(' ').forEach(w=>{if((line+' '+w).length>32){lines.push(line);line=w}else line=line?line+' '+w:w});if(line)lines.push(line);
 lines.slice(0,2).forEach((L,i)=>el('text',{x:n.x+8,y:n.y+33+i*12,class:'t2'},g).textContent=L)});
// finding markers (circles); tray items placed in a row under the diagram
const MG={};let trayX=D.W>420?24:24, trayY=D.H+40;
if(D.tray.length){el('text',{x:20,y:D.H+22,class:'zl'}).textContent='Findings not auto-placed (click to view):'}
D.findings.forEach(f=>{let x,y;if(f.at){const n=NODE[f.at];const k=D.findings.filter(o=>o.at===f.at);const idx=k.indexOf(f);x=n.x+n.w-10-idx*24;y=n.y-10}else{x=trayX;y=trayY;trayX+=30}
 const g=el('g',{class:'mk',id:'m'+f.n,tabindex:0},mLayer);MPOS['tm:'+f.n]=[x,y];
 el('circle',{cx:x,cy:y,r:12,fill:D.sevFill[f.sev]||'#888',stroke:D.ovlRing[f.ovl]||'#137333','stroke-width':3},g);
 el('text',{x,y},g).textContent=f.n;
 if(f.conf&&D.confPip[f.conf])el('circle',{cx:x+9,cy:y+9,r:4.5,fill:D.confPip[f.conf],stroke:'var(--bg)','stroke-width':1.4},g);
 el('title',{},g).textContent='#'+f.n+' '+f.title;
 g.onclick=()=>select(f.n);g.onkeydown=ev=>{if(ev.key==='Enter')select(f.n)};MG[f.n]=g});
// prior findings (diamonds)
const PG={};
D.prior.forEach(f=>{if(!f.at)return;const n=NODE[f.at];const k=D.prior.filter(o=>o.at===f.at);const idx=k.indexOf(f);const x=n.x+18+idx*22,y=n.y+n.h+12,r=11;
 const rem=/Remediated/i.test(f.status);const g=el('g',{class:'mk pt',id:'p'+f.id,tabindex:0},pLayer);MPOS['pt:'+f.id]=[x,y];
 el('polygon',{points:[[x,y-r],[x+r,y],[x,y+r],[x-r,y]].map(p=>p.join(',')).join(' '),fill:D.sevFill[f.sev]||'#888',stroke:'#7b1fa2','stroke-width':2.6,'stroke-dasharray':rem?'3 2':'0',opacity:rem?.55:1},g);
 el('text',{x,y},g).textContent=f.n;el('title',{},g).textContent=f.id+' ('+f.sev+', '+f.status+'): '+f.title;
 g.onclick=()=>selectP(f.id);PG[f.id]=g});
// legend
const ly=D.H+ (D.tray.length?70:40);const lg=el('g',{class:'lg',transform:'translate(20,'+ly+')'});
el('rect',{x:0,y:0,width:250,height:116,rx:6,fill:'var(--box)',stroke:'var(--boxb)'},lg);
[['Critical','#c5221f'],['High','#e8710a'],['Medium','#f9ab00'],['Low','#1a73e8']].forEach(([t,c],i)=>{el('circle',{cx:14,cy:16+i*15,r:6,fill:c},lg);el('text',{x:26,y:20+i*15},lg).textContent=t});
el('circle',{cx:120,cy:16,r:6,fill:'#888',stroke:'#137333','stroke-width':3},lg);el('text',{x:132,y:20},lg).textContent='ring: new / partial / dup';
el('circle',{cx:120,cy:34,r:6,fill:'#888'},lg);el('circle',{cx:126,cy:40,r:3.5,fill:'#137333'},lg);el('text',{x:132,y:38},lg).textContent='pip: confidence';
el('polygon',{points:'120,50 128,56 120,62 112,56',fill:'#888',stroke:'#7b1fa2','stroke-width':2.4},lg);el('text',{x:134,y:59},lg).textContent='diamond = prior finding';el('text',{x:8,y:92},lg).textContent='\u25ad process   \u2b1a external   \u2550 data store';el('line',{x1:10,y1:104,x2:36,y2:104,stroke:'var(--high)','stroke-width':2,'stroke-dasharray':'6 4'},lg);el('text',{x:42,y:108},lg).textContent='edge crosses a trust boundary';
// ---------- interaction ----------
let selF=null;let clearChainHook=null;
function clearAll(){document.querySelectorAll('.mk.dim,.f.sel').forEach(x=>x.classList.remove('dim','sel'));if(clearChainHook)clearChainHook()}
function clearSel(){clearAll();selF=null;const d=document.getElementById('detail');if(d)d.textContent='Select a finding.'}
function dimAllExcept(keepG){Object.values(MG).forEach(m=>m.classList.add('dim'));Object.values(PG).forEach(m=>m.classList.add('dim'));if(keepG)keepG.classList.remove('dim')}
function select(n,force){if(!force&&selF==='tm:'+n){clearSel();return}selF='tm:'+n;clearAll();dimAllExcept(MG[n]);const f=D.findings.find(x=>x.n===n);const li=document.getElementById('l'+n);if(li)li.classList.add('sel');
 const d=document.getElementById('detail');d.innerHTML='<b>#'+n+' '+esc(f.title)+'</b><br><span class="tag">'+f.sev+' · confidence '+f.conf+' · '+f.stride+(f.ovl&&f.ovl!=='none'?' · '+f.ovl+' of prior '+(f.prior_refs.join(', ')):'')+' · '+(f.cat||'')+(f.owner?' · '+esc(f.owner):'')+'</span>';
 d.insertAdjacentHTML('beforeend',triageUI('tm',String(n)))}
function selectP(id,force){if(!force&&selF==='pt:'+id){clearSel();return}selF='pt:'+id;clearAll();dimAllExcept(PG[id]);const f=D.prior.find(x=>x.id===id);const li=document.getElementById('pl'+cssid(id));if(li)li.classList.add('sel');
 const d=document.getElementById('detail');d.innerHTML='<b>'+esc(f.id)+'</b> <span class="tag">prior '+(D.priorKind||'assessment')+'</span><br>'+esc(f.title)+'<br><span class="tag">'+f.sev+' · '+f.status+'</span>';
 d.insertAdjacentHTML('beforeend',triageUI('pt',id))}
function esc(s){return (s||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}
function cssid(s){return s.replace(/[^A-Za-z0-9_-]/g,'_')}
svg.addEventListener('click',e=>{if(justPanned){justPanned=false;return}if(!e.target.closest('.mk'))clearSel()});
// ---------- triage ----------
const STATUSES=[{k:'open',l:'Open'},{k:'remediated',l:'Remediated'},{k:'fp',l:'False positive'},{k:'accepted',l:'Accepted risk'}];
const TKEY='ctm-triage-'+cssid(D.system);let triage={};try{triage=JSON.parse(localStorage.getItem(TKEY))||{}}catch(e){}
function persist(){try{localStorage.setItem(TKEY,JSON.stringify(triage))}catch(e){}}
const REG=[...D.findings.map(f=>({kind:'tm',id:String(f.n),g:MG[f.n],li:'l'+f.n,def:'open'})),
           ...D.prior.filter(p=>PG[p.id]).map(p=>({kind:'pt',id:p.id,g:PG[p.id],li:'pl'+cssid(p.id),def:/Remediated/i.test(p.status)?'remediated':'open'}))];
function statusOf(kind,id){const k=kind+':'+id;if(triage[k])return triage[k];const r=REG.find(x=>x.kind===kind&&x.id===String(id));return r?r.def:'open'}
let hidden=new Set();
function refreshTriage(){let shown=0;REG.forEach(r=>{const st=statusOf(r.kind,r.id);const le=document.getElementById(r.li);
 ['stk-open','stk-remediated','stk-fp','stk-accepted'].forEach(c=>{r.g&&r.g.classList.remove(c);le&&le.classList.remove(c)});
 r.g&&r.g.classList.add('stk-'+st);le&&le.classList.add('stk-'+st);const h=hidden.has(st);
 if(r.g)r.g.style.display=h?'none':'';if(le)le.style.display=h?'none':'';if(!h)shown++;if(r.sel)r.sel.value=st});
 const c=document.getElementById('tcount');if(c)c.textContent='Showing '+shown+' of '+REG.length}
function setStatus(kind,id,st){triage[kind+':'+id]=st;persist();refreshTriage();if(kind==='tm')select(+id,true);else selectP(id,true)}
function triageUI(kind,id){const cur=statusOf(kind,id);return '<div style="margin-top:8px;border-top:1px solid var(--boxb);padding-top:6px"><div class="tag" style="margin-bottom:4px">Presentation status</div>'+STATUSES.map(s=>'<button class="sbtn'+(cur===s.k?' on':'')+'" onclick="setStatus(\''+kind+'\',\''+id+'\',\''+s.k+'\')">'+s.l+'</button>').join('')+'</div>'}
// ---------- lists ----------
const list=document.getElementById('list');
D.findings.forEach(f=>{const d=document.createElement('div');d.className='f';d.id='l'+f.n;
 d.innerHTML='<span class="dot" style="background:'+(D.sevFill[f.sev]||'#888')+';box-shadow:0 0 0 2px '+(D.ovlRing[f.ovl]||'#137333')+'">'+f.n+'</span><span>'+esc(f.title)+'<br><span class="tag">'+f.sev+' · '+f.conf+' conf'+(f.ovl&&f.ovl!=='none'?' · '+f.ovl:'')+'</span></span>';
 d.onclick=()=>select(f.n);list.appendChild(d)});
if(D.prior.length){const h=document.createElement('div');h.innerHTML='<h2 style="margin:12px 0 6px">Prior findings <span class="tag">('+(D.priorKind||'assessment')+')</span></h2>';list.appendChild(h);
 D.prior.forEach(f=>{const d=document.createElement('div');d.className='f';d.id='pl'+cssid(f.id);const rem=/Remediated/i.test(f.status);
  d.innerHTML='<span class="dot" style="background:'+(D.sevFill[f.sev]||'#888')+';border-radius:3px;transform:rotate(45deg);box-shadow:0 0 0 2px #7b1fa2;'+(rem?'opacity:.55':'')+'">'+f.n+'</span><span>'+esc(f.title)+'<br><span class="tag">'+esc(f.id)+' · '+f.sev+' · '+f.status+'</span></span>';
  d.onclick=()=>selectP(f.id);list.appendChild(d)})}
// per-row status selects
REG.forEach(r=>{const le=document.getElementById(r.li);if(!le)return;const sel=document.createElement('select');sel.className='rowsel';
 STATUSES.forEach(x=>{const o=document.createElement('option');o.value=x.k;o.textContent=x.l;sel.appendChild(o)});sel.value=statusOf(r.kind,r.id);
 sel.onclick=e=>e.stopPropagation();sel.onchange=e=>{e.stopPropagation();setStatus(r.kind,r.id,sel.value)};r.sel=sel;
 const span=le.querySelector('span:last-child')||le;span.appendChild(document.createElement('br'));span.appendChild(sel)});
// toolbar
const tb=document.getElementById('triagebar');tb.innerHTML='<span id="tcount"></span>';
[['remediated','Hide remediated'],['fp','Hide false positives'],['accepted','Hide accepted']].forEach(([k,l])=>{const b=document.createElement('button');b.dataset.k=k;b.textContent=l;b.onclick=()=>{if(hidden.has(k)){hidden.delete(k);b.classList.remove('on')}else{hidden.add(k);b.classList.add('on')}refreshTriage()};tb.appendChild(b)});
function tbtn(t,f){const b=document.createElement('button');b.textContent=t;b.onclick=f;tb.appendChild(b);return b}
tbtn('Only open',()=>{['remediated','fp','accepted'].forEach(k=>hidden.add(k));tb.querySelectorAll('button[data-k]').forEach(b=>b.classList.add('on'));refreshTriage()});
tbtn('Show all',()=>{hidden.clear();tb.querySelectorAll('button[data-k]').forEach(b=>b.classList.remove('on'));refreshTriage()});
tbtn('Clear selection',()=>clearSel());
tbtn('Reset marks',()=>{triage={};persist();refreshTriage()});
const exp=tbtn('Export',async()=>{const t=JSON.stringify(triage);try{await navigator.clipboard.writeText(t);exp.textContent='Copied'}catch(e){prompt('Copy triage JSON:',t)}setTimeout(()=>exp.textContent='Export',1200)});
tbtn('Import',()=>{const t=prompt('Paste triage JSON');if(t)try{triage=JSON.parse(t);persist();refreshTriage()}catch(e){alert('Invalid JSON')}});

// ---------- attack chains ----------
const chainbar=document.getElementById('chainbar');let activeChain=null;
function clearChain(){activeChain=null;document.querySelectorAll('#chainbar button').forEach(b=>b.classList.remove('on'));while(cLayer.firstChild)cLayer.removeChild(cLayer.firstChild)}
clearChainHook=clearChain;
function showChain(c,btn){const already=activeChain===c.id;clearSel();if(already)return;activeChain=c.id;btn.classList.add('on');
 Object.values(MG).forEach(m=>m.classList.add('dim'));Object.values(PG).forEach(m=>m.classList.add('dim'));
 const pts=[];c.steps.forEach(s=>{const g=(s.k==='tm'?MG[s.ref]:PG[s.ref]);if(g)g.classList.remove('dim');const p=MPOS[s.k+':'+s.ref];if(p)pts.push(p)});
 if(pts.length>=2){let d='M'+pts[0][0]+','+pts[0][1];for(let i=1;i<pts.length;i++)d+=' L'+pts[i][0]+','+pts[i][1];
  el('path',{d,fill:'none',stroke:'var(--chain)','stroke-width':3,'stroke-dasharray':'8 5','marker-end':'url(#arh)',class:'chainpath'},cLayer)}
 if(pts.length){const xs=pts.map(p=>p[0]),ys=pts.map(p=>p[1]);fitTo(Math.min(...xs),Math.min(...ys),Math.max(...xs),Math.max(...ys),110)}
 const det=document.getElementById('detail');det.innerHTML='<b>'+esc(c.name)+'</b> <span class="tag">attack chain · '+c.sev+'</span><br>'+esc(c.narrative||'')+'<br><span class="tag">path: '+c.steps.map(s=>s.k==='tm'?('#'+s.ref):esc(s.ref)).join(' \u2192 ')+'</span>'}
if(D.chains&&D.chains.length){const lbl=document.createElement('span');lbl.className='tag';lbl.style.alignSelf='center';lbl.textContent='Attack chains:';chainbar.appendChild(lbl);
 D.chains.forEach(c=>{const b=document.createElement('button');b.textContent=c.name;b.title=c.narrative||'';b.onclick=()=>showChain(c,b);chainbar.appendChild(b)})}
else{chainbar.style.display='none'}
refreshTriage();
</script></body></html>"""
