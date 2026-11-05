"use strict";
const el = id => document.getElementById(id);
const pretty = value => JSON.stringify(value, null, 2);
let token = "";
async function api(path, options = {}) {
  const headers = {...(options.headers || {})};
  if (token) headers.Authorization = "Bearer " + token;
  const response = await fetch(path, {...options, headers});
  const data = await response.json();
  if (!response.ok && !data.result) throw new Error(data.error || "服务暂不可用");
  return data;
}
function textNode(tag, text, className) {
  const node = document.createElement(tag);
  node.textContent = text;
  if (className) node.className = className;
  return node;
}
function svgNode(tag, attributes, text) {
  const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [key, value] of Object.entries(attributes || {})) node.setAttribute(key, value);
  if (text !== undefined) node.textContent = text;
  return node;
}
function showGraph(graph) {
  el("graph-version").textContent = graph.graph_version;
  const box = el("graph"); box.replaceChildren();
  const svg = svgNode("svg", {viewBox:"0 0 1320 650", "aria-hidden":"true"});
  const defs = svgNode("defs");
  const marker = svgNode("marker", {id:"arrow", markerWidth:"8", markerHeight:"8", refX:"7", refY:"3", orient:"auto", markerUnits:"strokeWidth"});
  marker.append(svgNode("path", {d:"M0,0 L0,6 L8,3 z", fill:"#98adb4"})); defs.append(marker); svg.append(defs);
  const types = ["Component", "Point", "Variable", "ControlLoop", "Constraint"];
  const colors = {Component:"#dfecef", Point:"#e4edf9", Variable:"#dff0e9", ControlLoop:"#eee7f7", Constraint:"#fff0ce"};
  const positions = new Map();
  types.forEach((type, column) => {
    const group = graph.nodes.filter(node => node.type === type);
    svg.append(svgNode("text", {x:column*260+25, y:30, fill:"#667c85", "font-size":"12", "font-weight":"600"}, type));
    group.forEach((node, row) => positions.set(node.id, {x:column*260+20, y:75+row*(500/Math.max(group.length-1,1)), node}));
  });
  for (const edge of graph.edges) {
    const a = positions.get(edge.source), b = positions.get(edge.target);
    if (!a || !b) continue;
    const forward = b.x > a.x;
    const sx = a.x+(forward?215:0), tx = b.x+(forward?0:215), sy=a.y+23, ty=b.y+23;
    const path = svgNode("path", {d:`M${sx},${sy} C${sx+(forward?40:-40)},${sy} ${tx+(forward?-40:40)},${ty} ${tx},${ty}`, fill:"none", stroke:"#a1b4ba", "stroke-width":"1.2", "marker-end":"url(#arrow)"});
    path.append(svgNode("title", {}, `${edge.source} — ${edge.type} → ${edge.target}`)); svg.append(path);
  }
  for (const {x,y,node} of positions.values()) {
    const group=svgNode("g");
    group.append(svgNode("rect", {x,y,width:215,height:52,rx:7,fill:colors[node.type],stroke:"#c3d2d6"}));
    group.append(svgNode("text", {x:x+10,y:y+21,fill:"#183c46","font-size":"12"}, node.id.replace(/^[^:]+:/,"")));
    const label=node.label || node.id;
    group.append(svgNode("text", {x:x+10,y:y+40,fill:"#526d76","font-size":"10"}, label.length>30?label.slice(0,29)+"…":label));
    group.append(svgNode("title", {}, label+"\n证据："+(node.evidence_refs||[]).join(", "))); svg.append(group);
  }
  box.append(svg);
  const rows=el("edges"); rows.replaceChildren();
  for (const edge of graph.edges) {
    const row=document.createElement("tr");
    [edge.source,edge.type,edge.target,(edge.evidence_refs||[]).join(" · ")].forEach(value=>row.append(textNode("td",value)));
    rows.append(row);
  }
}
function showRecord(record) {
  const result=record.result;
  el("result-section").hidden=false;
  el("decision").textContent=result.decision;
  el("decision").className="badge "+result.decision;
  el("record-ref").textContent=`记录 ${record.record_id} · ${record.recorded_at} · 后端 ${record.backend} · 配置 ${record.bundle_profile||"未标注"}`;
  const c=result.completeness || {};
  el("completeness").textContent=(c.complete?"本次评估范围内的信息完整。":"评估不完整，不能视为放行依据。")+" 完整性详情："+pretty(c);
  const body=el("constraints"); body.replaceChildren();
  for (const item of result.constraints||[]) {
    const row=document.createElement("tr");
    row.append(textNode("td",item.constraint_id));
    row.append(textNode("td",`${item.category||""} / ${item.template||""}`));
    const status=document.createElement("td");status.append(textNode("span",item.status,"badge "+item.status));row.append(status);
    const metrics=document.createElement("td");metrics.append(textNode("pre",pretty(item.metrics||{})));row.append(metrics);
    row.append(textNode("td",item.reason||"—"));body.append(row);
  }
  el("trace").textContent=pretty(result.query_trace||[]);
  el("evidence").textContent=pretty({input_issues:result.input_issues,evidence:result.evidence});
  el("raw-result").textContent=pretty(record);
}
async function refreshRecords() {
  const data=await api("/api/records"); const box=el("records");box.replaceChildren();
  if (!data.records.length) box.append(textNode("p","暂无评估记录。","muted"));
  for (const item of data.records) {
    const button=textNode("button",`${item.recorded_at||""} · ${item.decision||item.error} · ${item.graph_version||""} · ${item.record_id}`,"record-button");
    button.addEventListener("click",async()=>{try{showRecord(await api("/api/records/"+encodeURIComponent(item.record_id)));el("result-section").scrollIntoView({behavior:"smooth"});}catch(error){el("message").textContent=error.message;}});
    box.append(button);
  }
}
async function loadExample() {
  const data=await api("/api/example");el("request").value=pretty(data.request);el("example-notice").textContent=data.notice;
}
async function connect() {
  token=el("token").value;
  try {
    const health=await api("/api/health");el("health").textContent="已连接 · "+health.backend;
    el("backend").textContent="图谱后端："+health.backend+" · 评估服务不执行控制写入";
    el("bundle-profile").textContent=health.bundle_profile === "synthetic_demo"
      ? "当前配置：synthetic_demo（合成演示）。示例规则和数值不能作为真实现场放行依据。"
      : health.bundle_profile === "archived_lab_evidence"
        ? "当前配置：archived_lab_evidence（实验归档证据）。配置与示例均不代表实时现场状态。"
        : "当前配置：unclassified（来源类型未标注或无法识别）。不能确认属于演示数据或实验归档，也不代表实时现场状态。";
    showGraph(await api("/api/graph"));await refreshRecords();
    if (!el("request").value) await loadExample();el("message").textContent="";
  }catch(error){el("health").textContent="连接未就绪";el("message").textContent=error.message;}
}
el("connect").addEventListener("click",connect);
el("load-example").addEventListener("click",()=>loadExample().catch(error=>el("message").textContent=error.message));
el("refresh-records").addEventListener("click",()=>refreshRecords().catch(error=>el("message").textContent=error.message));
el("evaluate").addEventListener("click",async()=>{
  el("evaluate").disabled=true;el("message").textContent="正在查询图谱并计算约束…";
  try {
    const request=JSON.parse(el("request").value);
    const record=await api("/api/evaluate",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(request)});
    showRecord(record);await refreshRecords();el("message").textContent="评估已记录；未执行控制操作。";
    el("result-section").scrollIntoView({behavior:"smooth"});
  }catch(error){el("message").textContent="评估未完成："+error.message;}
  finally{el("evaluate").disabled=false;}
});
connect();
