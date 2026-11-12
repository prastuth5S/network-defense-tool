from __future__ import annotations

from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse

from network_defense.evidence import EvidenceStore

app = FastAPI(title="PacketSight", version="0.1.0")
store = EvidenceStore()


@app.get("/api/flows")
def flows(limit: int = Query(100, ge=1, le=1000)):
    return store.read("flows", limit)


@app.get("/api/detections")
def detections(limit: int = Query(100, ge=1, le=1000)):
    return store.read("detections", limit)


@app.get("/api/evidence")
def evidence(kind: str = Query("packets", pattern="^(packets|flows|detections)$"), limit: int = Query(100, ge=1, le=1000)):
    return store.read(kind, limit)


@app.get("/api/overview")
def overview():
    flow_items, detection_items = store.read("flows", 10_000), store.read("detections", 10_000)
    return {"flow_count": len(flow_items), "detection_count": len(detection_items), "total_flow_bytes": sum(item.get("bytes", 0) for item in flow_items), "recent_detections": detection_items[:10]}


PAGE = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>PacketSight</title><style>
*{box-sizing:border-box}body{margin:0;background:#0b1220;color:#e6edf7;font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}header{min-height:62px;padding:0 5%;display:flex;align-items:center;gap:28px;background:#111b2e;border-bottom:1px solid #263653}.brand{font-size:18px;font-weight:750;color:white}.brand b{color:#38bdf8}nav{display:flex;gap:4px;flex:1}nav a{padding:20px 12px;text-decoration:none;color:#aebfd8;border-bottom:3px solid transparent}nav a.active,nav a:hover{color:white;border-bottom-color:#38bdf8}button,input,select{font:inherit}button{border:0;border-radius:5px;background:#2563eb;color:white;padding:8px 12px;cursor:pointer}main{max-width:1280px;margin:auto;padding:28px 5%}h1{margin:0;font-size:26px}.sub{color:#9fb0c9;margin:4px 0 24px}.metrics{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:24px}.metric,.panel{background:#111b2e;border:1px solid #263653;border-radius:8px}.metric{padding:17px}.metric label{color:#9fb0c9;text-transform:uppercase;font-size:11px;font-weight:700;letter-spacing:.07em}.metric strong{display:block;font-size:27px;color:white}.panel{padding:18px}.panel-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:12px}.tools{display:flex;gap:8px;flex-wrap:wrap}input,select{background:#0b1220;border:1px solid #354968;border-radius:5px;color:#e6edf7;padding:8px}.scroll{overflow:auto}table{width:100%;border-collapse:collapse}th{text-align:left;color:#9fb0c9;text-transform:uppercase;font-size:10px;letter-spacing:.06em}th,td{padding:10px 8px;border-bottom:1px solid #263653;vertical-align:top}.clickable{cursor:pointer}.clickable:hover{background:#17233a}.badge{display:inline-block;border-radius:20px;padding:2px 8px;font-size:12px;font-weight:700}.high{color:#fee2e2;background:#7f1d1d}.medium{color:#fef3c7;background:#78350f}.low{color:#cffafe;background:#164e63}pre{display:none;margin:8px 0 0;padding:10px;white-space:pre-wrap;word-break:break-word;background:#0b1220;border-radius:5px;color:#bdcbe0}.empty{color:#9fb0c9;text-align:center;padding:24px}@media(max-width:650px){header{padding:10px 4%;gap:8px;flex-wrap:wrap}.brand{width:100%}nav a{padding:7px}.metrics{grid-template-columns:1fr}main{padding:20px 4%}}
</style></head><body><header><div class="brand">Packet<b>Sight</b></div><nav><a href="/" data-page="overview">Overview</a><a href="/detections" data-page="detections">Detections</a><a href="/evidence" data-page="evidence">Evidence</a></nav><button id="refresh">Refresh</button></header><main><h1 id="title"></h1><p class="sub" id="subtitle"></p><section class="metrics" id="metrics"></section><section class="panel"><div class="panel-head"><strong id="tableTitle"></strong><div class="tools" id="tools"></div></div><div class="scroll"><table><thead id="head"></thead><tbody id="body"></tbody></table></div><div class="empty" id="empty" hidden>No records yet. Run <code>python run_lab_demo.py</code> to populate safe sample data.</div></section></main><script>
const active="__ACTIVE__", $=x=>document.getElementById(x), esc=x=>String(x??"—").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c])), fmt=x=>new Intl.NumberFormat().format(x||0), bytes=x=>{x=Number(x||0);if(x<1024)return fmt(x)+" B";let u=["KB","MB","GB"],i=-1;do{x/=1024;i++}while(x>=1024&&i<2);return x.toFixed(x<10?1:0)+" "+u[i]};
document.querySelector(`[data-page="${active}"]`).classList.add("active");
function stats(items){$("metrics").innerHTML=items.map(x=>`<div class="metric"><label>${x[0]}</label><strong>${x[1]}</strong><span>${x[2]||""}</span></div>`).join("")}
function table(rows,cols){$("head").innerHTML="<tr>"+cols.map(x=>`<th>${x[0]}</th>`).join("")+"<th>Details</th></tr>";$("body").innerHTML=rows.map((r,i)=>`<tr class="clickable" data-row="${i}">${cols.map(c=>`<td>${c[1](r)}</td>`).join("")}<td><button>View</button><pre>${esc(JSON.stringify(r,null,2))}</pre></td></tr>`).join("");$("empty").hidden=rows.length>0;document.querySelectorAll(".clickable").forEach(r=>r.onclick=()=>{let p=r.querySelector("pre");p.style.display=p.style.display==="block"?"none":"block"})}
const dcols=[["Time",r=>esc(r.timestamp)],["Severity",r=>`<span class="badge ${esc(r.severity)}">${esc(r.severity)}</span>`],["Rule",r=>esc(r.rule.replaceAll("_"," "))],["Analyst summary",r=>esc(r.summary)]];
const pcols=[["Time",r=>esc(r.timestamp)],["Source",r=>esc(r.src_ip)+(r.src_port?":"+r.src_port:"")],["Destination",r=>esc(r.dst_ip)+(r.dst_port?":"+r.dst_port:"")],["Protocol",r=>esc(r.protocol)],["Size",r=>bytes(r.length)],["DNS query",r=>esc(r.dns_query)]];
async function load(){let [o,d,p]=await Promise.all([fetch("/api/overview").then(x=>x.json()),fetch("/api/detections?limit=100").then(x=>x.json()),fetch("/api/evidence?kind=packets&limit=100").then(x=>x.json())]);if(active==="overview"){ $("title").textContent="Security overview";$("subtitle").textContent="Network telemetry and rule-based findings, organized for quick analyst review.";stats([["Completed flows",fmt(o.flow_count)],["Retained flow volume",bytes(o.total_flow_bytes)],["Detections",fmt(o.detection_count)]]);$("tableTitle").textContent="Recent detections";table(d.slice(0,10),dcols)}else if(active==="detections"){ $("title").textContent="Detection queue";$("subtitle").textContent="Select a finding to inspect its evidence fields.";stats([["Total findings",fmt(d.length)],["High severity",fmt(d.filter(x=>x.severity==="high").length)],["Newest rule",esc(d[0]?.rule||"None")]]);$("tableTitle").textContent="Rule findings";$("tools").innerHTML='<select id="severity"><option value="">All severities</option><option>high</option><option>medium</option><option>low</option></select>';let draw=()=>table(d.filter(x=>!$("severity").value||x.severity===$("severity").value),dcols);$("severity").onchange=draw;draw()}else{$("title").textContent="Packet evidence";$("subtitle").textContent="Metadata-only records. Packet payloads are not stored.";stats([["Packets shown",fmt(p.length)],["Latest record",esc(p[0]?.timestamp||"None")],["DNS queries",fmt(p.filter(x=>x.dns_query).length)]]);$("tableTitle").textContent="Recent packet metadata";$("tools").innerHTML='<input id="filter" placeholder="Filter IP, port, protocol…">';let draw=()=>{let q=$("filter").value.toLowerCase();table(p.filter(x=>JSON.stringify(x).toLowerCase().includes(q)),pcols)};$("filter").oninput=draw;draw()}}
$("refresh").onclick=load;load().catch(e=>{$("empty").hidden=false;$("empty").textContent="Could not load data: "+e.message});
</script></body></html>'''


def dashboard(active: str) -> HTMLResponse:
    return HTMLResponse(PAGE.replace("__ACTIVE__", active))


@app.get("/", response_class=HTMLResponse)
def dashboard_overview(): return dashboard("overview")


@app.get("/detections", response_class=HTMLResponse)
def dashboard_detections(): return dashboard("detections")


@app.get("/evidence", response_class=HTMLResponse)
def dashboard_evidence(): return dashboard("evidence")
