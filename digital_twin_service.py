"""
JeiGuard AI v1.0.2 — Mejora 6: Digital Twin Network Visualization
Mapa topológico interactivo con D3.js que muestra ataques propagándose en tiempo real.
Copyright © 2026 Jeiner Tello Nuñez — MIT License
"""
from __future__ import annotations

import json
import time
import asyncio
import random
from dataclasses import dataclass, field, asdict
from typing import Optional
from enum import Enum


# ── Modelos de datos ──────────────────────────────────────────────────────────
class NodeType(str, Enum):
    SERVER      = "server"
    WORKSTATION = "workstation"
    ROUTER      = "router"
    FIREWALL    = "firewall"
    ATTACKER    = "attacker"
    SENSOR      = "sensor"
    DATABASE    = "database"
    CLOUD       = "cloud"


class NodeRisk(str, Enum):
    SAFE        = "safe"
    LOW         = "low"
    MEDIUM      = "medium"
    HIGH        = "high"
    CRITICAL    = "critical"
    COMPROMISED = "compromised"


@dataclass
class NetworkNode:
    id:          str
    label:       str
    ip:          str
    type:        NodeType
    risk:        NodeRisk        = NodeRisk.SAFE
    group:       str             = "internal"
    alerts_count: int            = 0
    last_alert:  Optional[str]   = None
    x:           Optional[float] = None
    y:           Optional[float] = None
    metadata:    dict            = field(default_factory=dict)

    def to_d3(self) -> dict:
        return {
            "id":          self.id,
            "label":       self.label,
            "ip":          self.ip,
            "type":        self.type.value,
            "risk":        self.risk.value,
            "group":       self.group,
            "alerts":      self.alerts_count,
            "last_alert":  self.last_alert,
        }


@dataclass
class NetworkEdge:
    id:        str
    source:    str
    target:    str
    bandwidth: int    = 1000    # Mbps
    active:    bool   = True
    animated:  bool   = False   # True cuando hay ataque activo
    attack_type: Optional[str] = None

    def to_d3(self) -> dict:
        return {
            "id":           self.id,
            "source":       self.source,
            "target":       self.target,
            "bandwidth":    self.bandwidth,
            "active":       self.active,
            "animated":     self.animated,
            "attack_type":  self.attack_type,
        }


@dataclass
class AttackVector:
    vector_id:   str
    src_ip:      str
    dst_ip:      str
    category:    str
    confidence:  float
    timestamp:   float
    path:        list[str]   # Nodos por donde pasa el ataque
    active:      bool = True

    def to_d3(self) -> dict:
        return {
            "id":         self.vector_id,
            "src":        self.src_ip,
            "dst":        self.dst_ip,
            "category":   self.category,
            "confidence": self.confidence,
            "path":       self.path,
            "active":     self.active,
            "timestamp":  self.timestamp,
        }


class NetworkDigitalTwin:
    """
    Gemelo digital de la red que mantiene el estado topológico y
    refleja los ataques detectados en tiempo real.
    """

    def __init__(self):
        self._nodes:         dict[str, NetworkNode]  = {}
        self._edges:         dict[str, NetworkEdge]  = {}
        self._attack_vectors: dict[str, AttackVector] = {}
        self._ip_to_node:    dict[str, str]          = {}
        self._callbacks:     list                    = []
        self._stats = {
            "total_alerts":   0,
            "active_attacks": 0,
            "nodes_at_risk":  0,
        }
        self._initialize_demo_topology()

    # ── API pública ────────────────────────────────────────────────────────────

    def register_alert(self, src_ip: str, dst_ip: str, category: str,
                        confidence: float, sensor_id: str = "sensor-01") -> None:
        """Registra un ataque y actualiza la topología."""
        self._stats["total_alerts"] += 1

        src_node_id = self._get_or_create_attacker_node(src_ip)
        dst_node_id = self._ensure_node_for_ip(dst_ip)

        if src_node_id and dst_node_id:
            self._update_node_risk(dst_node_id, confidence, category)
            path = self._compute_attack_path(src_node_id, dst_node_id)
            self._animate_attack_path(path, category)
            self._register_attack_vector(src_ip, dst_ip, category, confidence, path)

        self._update_stats()
        self._notify_subscribers()

    def add_node(self, node: NetworkNode) -> None:
        self._nodes[node.id] = node
        self._ip_to_node[node.ip] = node.id

    def add_edge(self, edge: NetworkEdge) -> None:
        self._edges[edge.id] = edge

    def get_topology(self) -> dict:
        """Retorna la topología completa para D3.js."""
        return {
            "nodes":          [n.to_d3() for n in self._nodes.values()],
            "edges":          [e.to_d3() for e in self._edges.values()],
            "attack_vectors": [v.to_d3() for v in self._attack_vectors.values()
                               if v.active],
            "stats":          self._stats,
            "timestamp":      time.time(),
        }

    def get_node_details(self, node_id: str) -> Optional[dict]:
        node = self._nodes.get(node_id)
        if not node:
            return None
        attacks = [v.to_d3() for v in self._attack_vectors.values()
                   if node.ip in (v.src_ip, v.dst_ip)]
        return {**node.to_d3(), "attacks": attacks}

    def get_risk_summary(self) -> dict:
        risk_counts: dict[str, int] = {r.value: 0 for r in NodeRisk}
        for node in self._nodes.values():
            risk_counts[node.risk.value] += 1
        return risk_counts

    def subscribe(self, callback) -> None:
        self._callbacks.append(callback)

    def get_stats(self) -> dict:
        return self._stats

    # ── Internals ──────────────────────────────────────────────────────────────

    def _initialize_demo_topology(self) -> None:
        """Crea una topología de red empresarial de demostración."""
        nodes = [
            NetworkNode("fw-01",  "Firewall",         "192.168.0.1",  NodeType.FIREWALL,    NodeRisk.SAFE,   "perimeter"),
            NetworkNode("rt-01",  "Core Router",       "192.168.0.2",  NodeType.ROUTER,     NodeRisk.SAFE,   "internal"),
            NetworkNode("sv-01",  "Web Server",        "192.168.1.10", NodeType.SERVER,     NodeRisk.SAFE,   "dmz"),
            NetworkNode("sv-02",  "App Server",        "192.168.1.11", NodeType.SERVER,     NodeRisk.SAFE,   "internal"),
            NetworkNode("sv-03",  "DB Server",         "192.168.1.12", NodeType.DATABASE,   NodeRisk.SAFE,   "internal"),
            NetworkNode("sv-04",  "File Server",       "192.168.1.13", NodeType.SERVER,     NodeRisk.SAFE,   "internal"),
            NetworkNode("wk-01",  "Workstation 01",    "192.168.2.10", NodeType.WORKSTATION,NodeRisk.SAFE,   "users"),
            NetworkNode("wk-02",  "Workstation 02",    "192.168.2.11", NodeType.WORKSTATION,NodeRisk.SAFE,   "users"),
            NetworkNode("wk-03",  "Workstation 03",    "192.168.2.12", NodeType.WORKSTATION,NodeRisk.SAFE,   "users"),
            NetworkNode("sns-01", "IDS Sensor",        "192.168.0.10", NodeType.SENSOR,     NodeRisk.SAFE,   "perimeter"),
            NetworkNode("cld-01", "Cloud Gateway",     "192.168.0.20", NodeType.CLOUD,      NodeRisk.SAFE,   "cloud"),
        ]
        edges = [
            NetworkEdge("e01", "fw-01",  "rt-01",  10000),
            NetworkEdge("e02", "rt-01",  "sv-01",  1000),
            NetworkEdge("e03", "rt-01",  "sv-02",  1000),
            NetworkEdge("e04", "rt-01",  "sv-03",  1000),
            NetworkEdge("e05", "rt-01",  "sv-04",  1000),
            NetworkEdge("e06", "rt-01",  "wk-01",  100),
            NetworkEdge("e07", "rt-01",  "wk-02",  100),
            NetworkEdge("e08", "rt-01",  "wk-03",  100),
            NetworkEdge("e09", "fw-01",  "sns-01", 1000),
            NetworkEdge("e10", "rt-01",  "cld-01", 10000),
            NetworkEdge("e11", "sv-02",  "sv-03",  10000),
        ]
        for node in nodes:
            self.add_node(node)
        for edge in edges:
            self.add_edge(edge)

    def _get_or_create_attacker_node(self, ip: str) -> str:
        node_id = self._ip_to_node.get(ip)
        if not node_id:
            node_id = f"ext-{ip.replace('.', '-')}"
            attacker = NetworkNode(
                id=node_id, label=f"Attacker\n{ip}", ip=ip,
                type=NodeType.ATTACKER, risk=NodeRisk.CRITICAL, group="external"
            )
            self.add_node(attacker)
        return node_id

    def _ensure_node_for_ip(self, ip: str) -> Optional[str]:
        return self._ip_to_node.get(ip)

    def _update_node_risk(self, node_id: str, confidence: float, category: str) -> None:
        node = self._nodes.get(node_id)
        if not node:
            return
        if confidence >= 0.95:
            node.risk = NodeRisk.CRITICAL
        elif confidence >= 0.85:
            node.risk = NodeRisk.HIGH
        elif confidence >= 0.70:
            node.risk = NodeRisk.MEDIUM
        elif confidence >= 0.50:
            node.risk = NodeRisk.LOW
        node.alerts_count += 1
        node.last_alert = category

    def _compute_attack_path(self, src_id: str, dst_id: str) -> list[str]:
        """Calcula el camino del ataque (simplificado BFS)."""
        adj: dict[str, list[str]] = {n: [] for n in self._nodes}
        for edge in self._edges.values():
            if edge.active:
                adj[edge.source].append(edge.target)
                adj[edge.target].append(edge.source)

        visited = {src_id}
        queue   = [[src_id]]
        while queue:
            path = queue.pop(0)
            node = path[-1]
            if node == dst_id:
                return path
            for neighbor in adj.get(node, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(path + [neighbor])
        return [src_id, dst_id]

    def _animate_attack_path(self, path: list[str], attack_type: str) -> None:
        for i in range(len(path) - 1):
            edge_id = next(
                (eid for eid, e in self._edges.items()
                 if {e.source, e.target} == {path[i], path[i+1]}),
                None
            )
            if edge_id:
                self._edges[edge_id].animated   = True
                self._edges[edge_id].attack_type = attack_type

    def _register_attack_vector(self, src_ip: str, dst_ip: str, category: str,
                                  confidence: float, path: list[str]) -> None:
        vector_id = f"AV-{int(time.time())}-{src_ip.split('.')[-1]}"
        self._attack_vectors[vector_id] = AttackVector(
            vector_id=vector_id, src_ip=src_ip, dst_ip=dst_ip,
            category=category, confidence=confidence,
            timestamp=time.time(), path=path,
        )
        # Limpiar vectores antiguos (> 5 minutos)
        cutoff = time.time() - 300
        self._attack_vectors = {
            k: v for k, v in self._attack_vectors.items()
            if v.timestamp > cutoff
        }

    def _update_stats(self) -> None:
        self._stats["active_attacks"] = sum(
            1 for v in self._attack_vectors.values() if v.active)
        self._stats["nodes_at_risk"] = sum(
            1 for n in self._nodes.values()
            if n.risk not in (NodeRisk.SAFE, NodeRisk.LOW))

    def _notify_subscribers(self) -> None:
        topology = self.get_topology()
        for callback in self._callbacks:
            try:
                callback(topology)
            except Exception:
                pass


# ── HTML del Digital Twin con D3.js ──────────────────────────────────────────
DIGITAL_TWIN_HTML = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>JeiGuard AI — Digital Twin de Red</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body { background:#0A1628; color:#E8EAED; font-family:'Courier New',monospace; overflow:hidden; }
#header { display:flex; align-items:center; gap:16px; padding:12px 20px;
          background:#0E3460; border-bottom:1px solid #00B4D8; }
#header h1 { color:#00B4D8; font-size:16px; font-weight:700; }
.kpi { text-align:center; padding:4px 16px; border-left:1px solid #334466; }
.kpi-val { font-size:20px; font-weight:700; color:#00B4D8; }
.kpi-lbl { font-size:10px; color:#8B949E; text-transform:uppercase; letter-spacing:1px; }
#canvas { width:100vw; height:calc(100vh - 52px); }
.node circle { stroke-width:2; transition:all .3s; cursor:pointer; }
.node text { font-size:10px; fill:#CAF0F8; pointer-events:none; }
.node.attacker circle { animation: pulse 1s infinite; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.5} }
.link { stroke:#334466; stroke-width:1.5; fill:none; }
.link.animated { stroke:#E63946; stroke-width:2.5; stroke-dasharray:8 4; animation:flow 1s linear infinite; }
@keyframes flow { to { stroke-dashoffset:-24; } }
.tooltip { position:absolute; background:#0E3460; border:1px solid #00B4D8; border-radius:6px;
           padding:8px 12px; font-size:12px; pointer-events:none; opacity:0;
           transition:opacity .2s; max-width:200px; }
</style>
</head>
<body>
<div id="header">
  <h1>JeiGuard AI — Digital Twin de Red</h1>
  <div class="kpi"><div class="kpi-val" id="kpi-alerts">0</div><div class="kpi-lbl">Alertas</div></div>
  <div class="kpi"><div class="kpi-val" id="kpi-attacks" style="color:#E63946">0</div><div class="kpi-lbl">Ataques activos</div></div>
  <div class="kpi"><div class="kpi-val" id="kpi-risk" style="color:#F77F00">0</div><div class="kpi-lbl">Nodos en riesgo</div></div>
</div>
<div id="canvas"></div>
<div class="tooltip" id="tooltip"></div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"></script>
<script>
const RISK_COLORS = {
  safe:'#334466', low:'#06D6A0', medium:'#F77F00',
  high:'#E63946', critical:'#FF0044', compromised:'#7209B7'
};
const NODE_RADIUS = { server:18, database:18, router:16, firewall:16, workstation:14, attacker:14, sensor:12, cloud:20 };

const W = window.innerWidth, H = window.innerHeight - 52;
const svg = d3.select('#canvas').append('svg').attr('width',W).attr('height',H);

// Marcador de flecha
svg.append('defs').append('marker')
  .attr('id','arrow').attr('viewBox','0 0 10 10')
  .attr('refX',8).attr('refY',5).attr('markerWidth',6).attr('markerHeight',6)
  .attr('orient','auto-start-reverse')
  .append('path').attr('d','M2 1L8 5L2 9').attr('fill','none')
  .attr('stroke','#E63946').attr('stroke-width',1.5);

const g = svg.append('g');
svg.call(d3.zoom().scaleExtent([.3,3])
  .on('zoom', e => g.attr('transform', e.transform)));

const sim = d3.forceSimulation()
  .force('link', d3.forceLink().id(d=>d.id).distance(100))
  .force('charge', d3.forceManyBody().strength(-400))
  .force('center', d3.forceCenter(W/2, H/2))
  .force('collision', d3.forceCollide().radius(d => (NODE_RADIUS[d.type]||14)+8));

let linkSel, nodeSel, tooltip = document.getElementById('tooltip');
let totalAlerts = 0;

function updateGraph(data) {
  const nodes = data.nodes;
  const links = data.edges.map(e => ({...e, source:e.source, target:e.target}));

  sim.nodes(nodes);
  sim.force('link').links(links);

  // Links
  linkSel = g.selectAll('.link').data(links, d=>d.id);
  const linkEnter = linkSel.enter().append('line').attr('class','link');
  linkSel = linkEnter.merge(linkSel)
    .attr('class', d => 'link' + (d.animated?' animated':''))
    .attr('marker-end', d => d.animated ? 'url(#arrow)' : null);
  linkSel.exit().remove();

  // Nodes
  nodeSel = g.selectAll('.node').data(nodes, d=>d.id);
  const nodeEnter = nodeSel.enter().append('g').attr('class', d=>'node '+d.type)
    .call(d3.drag()
      .on('start', (e,d) => { if(!e.active) sim.alphaTarget(.3).restart(); d.fx=d.x; d.fy=d.y; })
      .on('drag',  (e,d) => { d.fx=e.x; d.fy=e.y; })
      .on('end',   (e,d) => { if(!e.active) sim.alphaTarget(0); d.fx=null; d.fy=null; }))
    .on('mouseover', (e,d) => {
      tooltip.style.opacity = '1';
      tooltip.style.left = (e.pageX+12)+'px';
      tooltip.style.top  = (e.pageY-10)+'px';
      tooltip.innerHTML = `<b>${d.label}</b><br>IP: ${d.ip}<br>Riesgo: ${d.risk.toUpperCase()}<br>Alertas: ${d.alerts}`;
    })
    .on('mouseout', () => { tooltip.style.opacity = '0'; });

  nodeEnter.append('circle')
    .attr('r', d => NODE_RADIUS[d.type]||14)
    .attr('stroke', d => RISK_COLORS[d.risk]||'#334466');
  nodeEnter.append('text').attr('dy','32px').attr('text-anchor','middle');

  nodeSel = nodeEnter.merge(nodeSel);
  nodeSel.select('circle')
    .attr('fill', d => d.risk==='safe' ? '#1C2E4A' : RISK_COLORS[d.risk]+'33')
    .attr('stroke', d => RISK_COLORS[d.risk]||'#334466')
    .attr('stroke-width', d => d.risk==='safe' ? 1.5 : 2.5);
  nodeSel.select('text').text(d => d.label.split('\\n')[0]);
  nodeSel.exit().remove();

  // KPIs
  document.getElementById('kpi-alerts').textContent  = data.stats.total_alerts;
  document.getElementById('kpi-attacks').textContent = data.stats.active_attacks;
  document.getElementById('kpi-risk').textContent    = data.stats.nodes_at_risk;

  sim.alpha(.3).restart();
}

sim.on('tick', () => {
  if(linkSel) linkSel.attr('x1',d=>d.source.x).attr('y1',d=>d.source.y)
                      .attr('x2',d=>d.target.x).attr('y2',d=>d.target.y);
  if(nodeSel) nodeSel.attr('transform', d=>`translate(${d.x},${d.y})`);
});

// Cargar topología inicial desde el servidor
fetch('/api/v1/digital-twin/topology')
  .then(r=>r.json())
  .then(updateGraph)
  .catch(() => {
    // Fallback: demo estático si no hay servidor
    updateGraph(DEMO_TOPOLOGY);
  });

// WebSocket para actualizaciones en tiempo real
try {
  const ws = new WebSocket(`ws://${location.host}/ws/digital-twin`);
  ws.onmessage = e => updateGraph(JSON.parse(e.data));
} catch(err) {}
</script>
</body>
</html>"""


# ── Streamlit app para el Digital Twin ───────────────────────────────────────
STREAMLIT_DIGITAL_TWIN = '''
import streamlit as st
import streamlit.components.v1 as components
import time
import random
import sys
sys.path.insert(0, ".")

from digital_twin.digital_twin_service import NetworkDigitalTwin, DIGITAL_TWIN_HTML

st.set_page_config(page_title="JeiGuard AI — Digital Twin", layout="wide",
                   page_icon="🛡️")

@st.cache_resource
def get_twin():
    return NetworkDigitalTwin()

twin = get_twin()

col1, col2, col3, col4 = st.columns(4)
stats = twin.get_stats()
with col1: st.metric("Total alertas",   stats["total_alerts"])
with col2: st.metric("Ataques activos", stats["active_attacks"])
with col3: st.metric("Nodos en riesgo", stats["nodes_at_risk"])
with col4: st.metric("Nodos totales",   len(twin._nodes))

col_map, col_info = st.columns([2, 1])

with col_map:
    st.subheader("Mapa topológico en tiempo real")
    components.html(DIGITAL_TWIN_HTML, height=600, scrolling=False)

with col_info:
    st.subheader("Resumen de riesgo")
    risk_summary = twin.get_risk_summary()
    for level, count in risk_summary.items():
        if count > 0:
            color = {"safe":"green","low":"blue","medium":"orange",
                     "high":"red","critical":"red","compromised":"purple"}.get(level,"gray")
            st.markdown(f":{color}[**{level.upper()}**: {count} nodos]")

    st.subheader("Simular ataque")
    if st.button("Generar ataque DDoS"):
        twin.register_alert("10.42.183.97", "192.168.1.10", "DoS_DDoS", 0.95)
        st.success("Ataque DDoS simulado!")
        st.rerun()

    if st.button("Generar APT"):
        for cat, dst, conf in [
            ("Probe_Scan","192.168.1.10",0.88),
            ("R2L","192.168.1.11",0.82),
            ("U2R","192.168.1.12",0.79),
        ]:
            twin.register_alert("172.16.99.1", dst, cat, conf)
        st.success("Campaña APT simulada!")
        st.rerun()
'''


# ── Demo ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  JeiGuard AI v1.0.2 — Digital Twin Network")
    print("=" * 60)

    twin = NetworkDigitalTwin()
    print(f"\nTopología inicializada:")
    print(f"  Nodos: {len(twin._nodes)}")
    print(f"  Edges: {len(twin._edges)}")

    # Simular escenario de ataque
    attacks = [
        ("10.42.183.97", "192.168.1.10", "DoS_DDoS",    0.948),
        ("10.42.183.97", "192.168.1.11", "Probe_Scan",  0.881),
        ("172.16.99.1",  "192.168.2.10", "R2L",         0.821),
        ("172.16.99.1",  "192.168.1.12", "U2R",         0.792),
    ]

    for src, dst, cat, conf in attacks:
        print(f"\nAtaque: {src} → {dst} [{cat}] conf={conf:.1%}")
        twin.register_alert(src, dst, cat, conf)

    topology = twin.get_topology()
    print(f"\nEstado de la topología:")
    print(f"  Vectores de ataque activos: {len(topology['attack_vectors'])}")
    print(f"  Nodos en riesgo: {twin.get_stats()['nodes_at_risk']}")

    risk_summary = twin.get_risk_summary()
    print(f"\nResumen de riesgo:")
    for level, count in risk_summary.items():
        if count > 0:
            print(f"  {level.upper()}: {count} nodos")

    # Guardar HTML del digital twin
    with open("/tmp/jeiguard_digital_twin.html", "w") as f:
        f.write(DIGITAL_TWIN_HTML)
    print(f"\nHTML del Digital Twin guardado en: /tmp/jeiguard_digital_twin.html")
