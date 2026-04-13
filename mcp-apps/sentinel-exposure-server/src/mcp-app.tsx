/**
 * Sentinel Exposure Management - React Frontend
 *
 * Renders 3 views based on structuredContent.viewType:
 *   - exposure-graph: Interactive force-directed SVG graph
 *   - vulnerability-dashboard: Severity bars, device rankings, CVE tables
 *   - compliance-posture: Gauge charts, standard scores, recommendation tables
 */
import type { McpUiHostContext } from "@modelcontextprotocol/ext-apps";
import { useApp } from "@modelcontextprotocol/ext-apps/react";
import React, { useMemo, useState, useEffect, useCallback, useRef } from "react";
import { createRoot } from "react-dom/client";
import "./mcp-app.css";

// ─── Type definitions (mirror server schemas) ───────────────

interface GraphNode {
  id: string;
  name: string;
  label: string;
  riskScore?: number;
  exposureScore?: number;
  isInternetFacing?: boolean;
  isRceVulnerable?: boolean;
  sensorHealth?: string;
  maxCvss?: number;
  // Layout props (computed)
  x?: number;
  y?: number;
  dx?: number;
  dy?: number;
}

interface GraphEdge {
  sourceId: string;
  sourceName: string;
  sourceLabel?: string;
  targetId: string;
  targetName: string;
  targetLabel?: string;
  edgeLabel: string;
}

interface ChokePoint {
  name: string;
  incomingPaths: number;
  totalVulns?: number;
  criticalVulns?: number;
  highVulns?: number;
}

interface ExposureGraphData {
  viewType: "exposure-graph";
  nodes: GraphNode[];
  edges: GraphEdge[];
  chokePoints?: ChokePoint[];
  title: string;
  focus: string;
  stats: {
    totalNodes: number;
    totalEdges: number;
    uniqueNodeTypes: number;
    uniqueEdgeTypes: number;
    internetFacingCount: number;
    chokePointCount: number;
  };
  generatedAt: string;
}

interface SeverityDistribution {
  critical: number;
  high: number;
  medium: number;
  low: number;
  totalDevices: number;
  totalUniqueVulns: number;
}

interface TopDevice {
  name: string;
  os: string;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  weightedScore: number;
}

interface OsPlatform {
  os: string;
  deviceCount: number;
  totalVulns: number;
  critical: number;
  high: number;
  weightedScore: number;
}

interface TopCve {
  cveId: string;
  severity: string;
  affectedDevices: number;
}

interface VulnDashboardData {
  viewType: "vulnerability-dashboard";
  severityDistribution: SeverityDistribution;
  topDevices: TopDevice[];
  osPlatforms?: OsPlatform[];
  topCVEs?: TopCve[];
  title: string;
  stats: {
    totalDevices: number;
    totalVulns: number;
    criticalPercent: number;
    highPercent: number;
    maxWeightedScore: number;
  };
  generatedAt: string;
}

interface Standard {
  name: string;
  score: number;
  healthy: number;
  unhealthy: number;
  notApplicable?: number;
  total: number;
}

interface AttackPathSummary {
  critical: number;
  high: number;
  medium: number;
  total: number;
  riskScore?: number;
}

interface Recommendation {
  name: string;
  status: "Healthy" | "Unhealthy" | "NotApplicable";
  severity: string;
  category?: string;
}

interface ComplianceData {
  viewType: "compliance-posture";
  standards: Standard[];
  attackPaths?: AttackPathSummary;
  recommendations?: Recommendation[];
  title: string;
  stats: {
    totalStandards: number;
    avgScore: number;
    totalHealthy: number;
    totalUnhealthy: number;
    totalRecommendations: number;
  };
  generatedAt: string;
}

type ViewData = ExposureGraphData | VulnDashboardData | ComplianceData;

// ─── Utility: Node type display mapping ─────────────────────

function getNodeTypeInfo(label: string): { icon: string; color: string; shortLabel: string } {
  const l = label.toLowerCase();
  if (l.includes("virtualmachines") || l.includes("machines"))
    return { icon: "\uD83D\uDDA5", color: "#0078d4", shortLabel: "VM" };
  if (l.includes("user") || l.includes("identity") || l.includes("serviceprincipal"))
    return { icon: "\uD83D\uDC64", color: "#8764b8", shortLabel: "Identity" };
  if (l.includes("storage"))
    return { icon: "\uD83D\uDCE6", color: "#e87400", shortLabel: "Storage" };
  if (l.includes("subscription"))
    return { icon: "\u2601", color: "#666", shortLabel: "Subscription" };
  if (l.includes("publicip") || l.includes("ipaddress"))
    return { icon: "\uD83C\uDF10", color: "#f65314", shortLabel: "IP" };
  if (l.includes("networkinterface"))
    return { icon: "\uD83D\uDD0C", color: "#00a4ef", shortLabel: "NIC" };
  if (l.includes("function"))
    return { icon: "\u26A1", color: "#ffbb00", shortLabel: "Function" };
  if (l.includes("kubernetes") || l.includes("managedcluster"))
    return { icon: "\u2699", color: "#326ce5", shortLabel: "K8s" };
  if (l.includes("keyvault"))
    return { icon: "\uD83D\uDD11", color: "#7cbb00", shortLabel: "Vault" };
  if (l.includes("loadbalancer"))
    return { icon: "\u2696", color: "#00b7c3", shortLabel: "LB" };
  if (l.includes("resourcegroup"))
    return { icon: "\uD83D\uDCC1", color: "#999", shortLabel: "RG" };
  if (l.includes("webapp") || l.includes("site"))
    return { icon: "\uD83C\uDF10", color: "#0078d4", shortLabel: "App" };
  if (l.includes("sql") || l.includes("database"))
    return { icon: "\uD83D\uDDC3", color: "#e81123", shortLabel: "DB" };
  return { icon: "\u25CF", color: "#888", shortLabel: label.split("/").pop() || "Node" };
}

function getEdgeColor(edgeLabel: string): string {
  const l = edgeLabel.toLowerCase();
  if (l.includes("permission")) return "#8764b8";
  if (l.includes("affecting") || l.includes("vulnerab")) return "#f65314";
  if (l.includes("traffic") || l.includes("route")) return "#7cbb00";
  if (l.includes("member")) return "#666";
  if (l.includes("authenticate") || l.includes("credential") || l.includes("impersonate")) return "#e81123";
  if (l.includes("contains") || l.includes("runs on")) return "#00a4ef";
  return "#555";
}

// ─── Force-directed layout ──────────────────────────────────

function computeForceLayout(
  nodes: GraphNode[],
  edges: GraphEdge[],
  width: number,
  height: number,
  iterations = 120
): GraphNode[] {
  // Clone nodes for layout computation
  const laid = nodes.map((n) => ({
    ...n,
    x: width / 2 + (seededRandom(n.id) - 0.5) * width * 0.7,
    y: height / 2 + (seededRandom(n.id + "y") - 0.5) * height * 0.7,
    dx: 0,
    dy: 0,
  }));

  const nodeMap = new Map(laid.map((n) => [n.id, n]));
  const k = Math.sqrt((width * height) / Math.max(laid.length, 1));

  for (let iter = 0; iter < iterations; iter++) {
    const temp = 1 - iter / iterations;

    // Reset displacement
    for (const n of laid) { n.dx = 0; n.dy = 0; }

    // Repulsive forces between all pairs
    for (let a = 0; a < laid.length; a++) {
      for (let b = a + 1; b < laid.length; b++) {
        const dx = laid[a].x! - laid[b].x!;
        const dy = laid[a].y! - laid[b].y!;
        const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
        const force = (k * k) / dist;
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        laid[a].dx! += fx;
        laid[a].dy! += fy;
        laid[b].dx! -= fx;
        laid[b].dy! -= fy;
      }
    }

    // Attractive forces along edges
    for (const e of edges) {
      const src = nodeMap.get(e.sourceId);
      const tgt = nodeMap.get(e.targetId);
      if (!src || !tgt) continue;
      const dx = tgt.x! - src.x!;
      const dy = tgt.y! - src.y!;
      const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
      const force = (dist * dist) / k;
      const fx = (dx / dist) * force;
      const fy = (dy / dist) * force;
      src.dx! += fx * 0.5;
      src.dy! += fy * 0.5;
      tgt.dx! -= fx * 0.5;
      tgt.dy! -= fy * 0.5;
    }

    // Center gravity
    for (const n of laid) {
      n.dx! += (width / 2 - n.x!) * 0.01;
      n.dy! += (height / 2 - n.y!) * 0.01;
    }

    // Apply forces with cooling
    for (const n of laid) {
      const mag = Math.sqrt(n.dx! * n.dx! + n.dy! * n.dy!);
      if (mag > 0) {
        const limit = temp * 40;
        n.x! += (n.dx! / mag) * Math.min(mag, limit);
        n.y! += (n.dy! / mag) * Math.min(mag, limit);
      }
      n.x = Math.max(60, Math.min(width - 60, n.x!));
      n.y = Math.max(60, Math.min(height - 60, n.y!));
    }
  }

  return laid;
}

function seededRandom(seed: string): number {
  let hash = 0;
  for (let i = 0; i < seed.length; i++) {
    const c = seed.charCodeAt(i);
    hash = ((hash << 5) - hash) + c;
    hash |= 0;
  }
  return ((hash & 0x7fffffff) % 10000) / 10000;
}

// ─── View 1: Exposure Graph ─────────────────────────────────

function ExposureGraphView({ data }: { data: ExposureGraphData }) {
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [hoveredEdge, setHoveredEdge] = useState<string | null>(null);
  const svgWidth = 900;
  const svgHeight = 600;

  const chokeNames = useMemo(
    () => new Set(data.chokePoints?.map((c) => c.name) ?? []),
    [data.chokePoints]
  );

  const layoutNodes = useMemo(
    () => computeForceLayout(data.nodes, data.edges, svgWidth, svgHeight),
    [data.nodes, data.edges]
  );

  const nodeMap = useMemo(
    () => new Map(layoutNodes.map((n) => [n.id, n])),
    [layoutNodes]
  );

  // Edge type legend
  const edgeTypes = useMemo(() => {
    const counts = new Map<string, number>();
    data.edges.forEach((e) => counts.set(e.edgeLabel, (counts.get(e.edgeLabel) || 0) + 1));
    return Array.from(counts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8);
  }, [data.edges]);

  // Node type legend
  const nodeTypes = useMemo(() => {
    const counts = new Map<string, number>();
    data.nodes.forEach((n) => counts.set(n.label, (counts.get(n.label) || 0) + 1));
    return Array.from(counts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8);
  }, [data.nodes]);

  return (
    <div className="graph-wrapper">
      <h2 className="view-title">{data.title}</h2>

      <div className="graph-stats">
        <span>Nodes: <strong>{data.stats.totalNodes}</strong> ({data.stats.uniqueNodeTypes} types)</span>
        <span>Edges: <strong>{data.stats.totalEdges}</strong> ({data.stats.uniqueEdgeTypes} types)</span>
        {data.stats.internetFacingCount > 0 && (
          <span className="stat-danger">Internet-facing: <strong>{data.stats.internetFacingCount}</strong></span>
        )}
        {data.stats.chokePointCount > 0 && (
          <span className="stat-warning">Choke points: <strong>{data.stats.chokePointCount}</strong></span>
        )}
      </div>

      <div className="graph-container">
        <svg
          viewBox={`0 0 ${svgWidth} ${svgHeight}`}
          className="graph-svg"
          xmlns="http://www.w3.org/2000/svg"
        >
          <defs>
            <marker id="arrow" viewBox="0 0 10 6" refX="10" refY="3"
              markerWidth="8" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 0 L 10 3 L 0 6 z" fill="#555" />
            </marker>
            <filter id="glow">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          {/* Edges */}
          {data.edges.map((e, i) => {
            const src = nodeMap.get(e.sourceId);
            const tgt = nodeMap.get(e.targetId);
            if (!src || !tgt) return null;
            const isHovered = hoveredEdge === `${e.sourceId}-${e.targetId}-${i}`;
            return (
              <g key={`edge-${i}`}
                onMouseEnter={() => setHoveredEdge(`${e.sourceId}-${e.targetId}-${i}`)}
                onMouseLeave={() => setHoveredEdge(null)}>
                <line
                  x1={src.x} y1={src.y} x2={tgt.x} y2={tgt.y}
                  stroke={getEdgeColor(e.edgeLabel)}
                  strokeWidth={isHovered ? 2.5 : 1}
                  strokeOpacity={isHovered ? 0.9 : 0.35}
                  markerEnd="url(#arrow)"
                />
                {isHovered && (
                  <text
                    x={(src.x! + tgt.x!) / 2}
                    y={(src.y! + tgt.y!) / 2 - 6}
                    fill="#e0e0e0"
                    fontSize="9"
                    textAnchor="middle"
                    className="edge-label"
                  >
                    {e.edgeLabel}
                  </text>
                )}
              </g>
            );
          })}

          {/* Nodes */}
          {layoutNodes.map((n) => {
            const info = getNodeTypeInfo(n.label);
            const isChoke = chokeNames.has(n.name);
            const isSelected = selectedNode?.id === n.id;
            const radius = isChoke ? 16 : n.isInternetFacing ? 12 : 8;

            return (
              <g key={n.id}
                onClick={() => setSelectedNode(isSelected ? null : n)}
                style={{ cursor: "pointer" }}>
                {/* Choke point glow */}
                {isChoke && (
                  <circle cx={n.x} cy={n.y} r={radius + 6}
                    fill="none" stroke="#ffbb00" strokeWidth="2"
                    strokeOpacity="0.6" filter="url(#glow)" />
                )}
                {/* Internet-facing ring */}
                {n.isInternetFacing && !isChoke && (
                  <circle cx={n.x} cy={n.y} r={radius + 4}
                    fill="none" stroke="#f65314" strokeWidth="1.5"
                    strokeDasharray="3 2" />
                )}
                {/* Main node circle */}
                <circle cx={n.x} cy={n.y} r={radius}
                  fill={info.color}
                  fillOpacity={isSelected ? 1 : 0.85}
                  stroke={isSelected ? "#fff" : "none"}
                  strokeWidth={isSelected ? 2 : 0}
                />
                {/* Node label */}
                <text x={n.x} y={n.y! + radius + 12} fill="#a0a0a0"
                  fontSize="8" textAnchor="middle">
                  {n.name.length > 18 ? n.name.slice(0, 16) + ".." : n.name}
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      {/* Legends */}
      <div className="graph-legends">
        <div className="legend-section">
          <span className="legend-title">Node types</span>
          <div className="legend-items">
            {nodeTypes.map(([label, count]) => {
              const info = getNodeTypeInfo(label);
              return (
                <span key={label} className="legend-item">
                  <span className="legend-dot" style={{ backgroundColor: info.color }} />
                  {info.shortLabel} ({count})
                </span>
              );
            })}
          </div>
        </div>
        <div className="legend-section">
          <span className="legend-title">Edge types</span>
          <div className="legend-items">
            {edgeTypes.map(([label, count]) => (
              <span key={label} className="legend-item">
                <span className="legend-line" style={{ backgroundColor: getEdgeColor(label) }} />
                {label} ({count})
              </span>
            ))}
          </div>
        </div>
        <div className="legend-section">
          <span className="legend-title">Indicators</span>
          <div className="legend-items">
            <span className="legend-item"><span className="legend-ring ring-choke" /> Choke point</span>
            <span className="legend-item"><span className="legend-ring ring-internet" /> Internet-facing</span>
          </div>
        </div>
      </div>

      {/* Detail panel */}
      {selectedNode && (
        <NodeDetailPanel node={selectedNode} data={data} onClose={() => setSelectedNode(null)} />
      )}

      {/* Choke point table */}
      {data.chokePoints && data.chokePoints.length > 0 && (
        <div className="choke-table-section">
          <h3 className="section-title">Choke Points — Remediation Priority</h3>
          <table className="data-table">
            <thead>
              <tr>
                <th>Node</th>
                <th>Incoming Paths</th>
                <th>Vulns</th>
                <th>Critical</th>
                <th>High</th>
              </tr>
            </thead>
            <tbody>
              {data.chokePoints.map((cp) => (
                <tr key={cp.name}>
                  <td className="td-name">{cp.name}</td>
                  <td className="td-center"><strong>{cp.incomingPaths.toLocaleString()}</strong></td>
                  <td className="td-center">{cp.totalVulns?.toLocaleString() ?? "-"}</td>
                  <td className="td-center td-critical">{cp.criticalVulns ?? "-"}</td>
                  <td className="td-center td-high">{cp.highVulns ?? "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="view-footer">Generated: {new Date(data.generatedAt).toLocaleString()}</div>
    </div>
  );
}

function NodeDetailPanel({
  node, data, onClose,
}: {
  node: GraphNode;
  data: ExposureGraphData;
  onClose: () => void;
}) {
  const info = getNodeTypeInfo(node.label);
  const incoming = data.edges.filter((e) => e.targetId === node.id);
  const outgoing = data.edges.filter((e) => e.sourceId === node.id);
  const choke = data.chokePoints?.find((c) => c.name === node.name);

  return (
    <div className="detail-panel">
      <div className="detail-header">
        <span className="detail-icon" style={{ color: info.color }}>{info.icon}</span>
        <span className="detail-name">{node.name}</span>
        <button className="detail-close" onClick={onClose}>&times;</button>
      </div>
      <div className="detail-body">
        <div className="detail-row">
          <span className="detail-label">Type</span>
          <span className="detail-value">{info.shortLabel}</span>
        </div>
        <div className="detail-row">
          <span className="detail-label">Full label</span>
          <span className="detail-value detail-mono">{node.label}</span>
        </div>
        {node.riskScore !== undefined && (
          <div className="detail-row">
            <span className="detail-label">Risk Score</span>
            <span className={`detail-value ${node.riskScore > 50 ? 'val-danger' : node.riskScore > 20 ? 'val-warning' : 'val-ok'}`}>
              {node.riskScore}
            </span>
          </div>
        )}
        {node.exposureScore !== undefined && (
          <div className="detail-row">
            <span className="detail-label">Exposure Score</span>
            <span className="detail-value">{node.exposureScore}</span>
          </div>
        )}
        {node.isInternetFacing && (
          <div className="detail-row"><span className="flag flag-internet">INTERNET-FACING</span></div>
        )}
        {node.isRceVulnerable && (
          <div className="detail-row">
            <span className="flag flag-rce">RCE VULNERABLE</span>
            {node.maxCvss && <span className="detail-value val-danger"> CVSS: {node.maxCvss}</span>}
          </div>
        )}
        {choke && (
          <div className="detail-row">
            <span className="flag flag-choke">CHOKE POINT</span>
            <span className="detail-value"> {choke.incomingPaths} paths</span>
          </div>
        )}
        <div className="detail-row">
          <span className="detail-label">Connections</span>
          <span className="detail-value">{incoming.length} in / {outgoing.length} out</span>
        </div>
        {incoming.length > 0 && (
          <div className="detail-edges">
            <span className="detail-label">Incoming edges</span>
            {incoming.slice(0, 8).map((e, i) => (
              <div key={i} className="edge-item">
                <span className="edge-from">{e.sourceName}</span>
                <span className="edge-arrow" style={{ color: getEdgeColor(e.edgeLabel) }}> &rarr; </span>
                <span className="edge-type">{e.edgeLabel}</span>
              </div>
            ))}
            {incoming.length > 8 && <div className="edge-more">+{incoming.length - 8} more</div>}
          </div>
        )}
      </div>
    </div>
  );
}

// ─── View 2: Vulnerability Dashboard ────────────────────────

function VulnDashboardView({ data }: { data: VulnDashboardData }) {
  const sev = data.severityDistribution;
  const maxScore = data.stats.maxWeightedScore || 1;

  return (
    <div className="vuln-wrapper">
      <h2 className="view-title">{data.title}</h2>

      {/* KPI row */}
      <div className="kpi-row">
        <div className="kpi-card">
          <span className="kpi-value">{sev.totalDevices.toLocaleString()}</span>
          <span className="kpi-label">Devices</span>
        </div>
        <div className="kpi-card">
          <span className="kpi-value">{sev.totalUniqueVulns.toLocaleString()}</span>
          <span className="kpi-label">Unique CVEs</span>
        </div>
        <div className="kpi-card kpi-critical">
          <span className="kpi-value">{sev.critical.toLocaleString()}</span>
          <span className="kpi-label">Critical</span>
        </div>
        <div className="kpi-card kpi-high">
          <span className="kpi-value">{sev.high.toLocaleString()}</span>
          <span className="kpi-label">High</span>
        </div>
      </div>

      {/* Severity distribution bar */}
      <div className="severity-section">
        <h3 className="section-title">Severity Distribution</h3>
        <div className="severity-bar">
          {sev.critical > 0 && (
            <div className="sev-segment sev-critical"
              style={{ flex: sev.critical }}
              title={`Critical: ${sev.critical}`}>
              {sev.critical}
            </div>
          )}
          {sev.high > 0 && (
            <div className="sev-segment sev-high"
              style={{ flex: sev.high }}
              title={`High: ${sev.high}`}>
              {sev.high}
            </div>
          )}
          {sev.medium > 0 && (
            <div className="sev-segment sev-medium"
              style={{ flex: sev.medium }}
              title={`Medium: ${sev.medium}`}>
              {sev.medium}
            </div>
          )}
          {sev.low > 0 && (
            <div className="sev-segment sev-low"
              style={{ flex: sev.low }}
              title={`Low: ${sev.low}`}>
              {sev.low}
            </div>
          )}
        </div>
        <div className="severity-legend">
          <span><span className="sev-dot sev-dot-critical" /> Critical ({data.stats.criticalPercent}%)</span>
          <span><span className="sev-dot sev-dot-high" /> High ({data.stats.highPercent}%)</span>
          <span><span className="sev-dot sev-dot-medium" /> Medium</span>
          <span><span className="sev-dot sev-dot-low" /> Low</span>
        </div>
      </div>

      {/* Top vulnerable devices */}
      <div className="section">
        <h3 className="section-title">Top Vulnerable Devices (Weighted Score)</h3>
        <div className="device-list">
          {data.topDevices.map((d) => (
            <div key={d.name} className="device-row">
              <div className="device-info">
                <span className="device-name">{d.name}</span>
                <span className="device-os">{d.os}</span>
              </div>
              <div className="device-bar-container">
                <div className="device-bar">
                  <div className="bar-fill bar-critical" style={{ width: `${(d.critical * 4 / maxScore) * 100}%` }} />
                  <div className="bar-fill bar-high" style={{ width: `${(d.high * 2 / maxScore) * 100}%` }} />
                  <div className="bar-fill bar-medium" style={{ width: `${(d.medium / maxScore) * 100}%` }} />
                  <div className="bar-fill bar-low" style={{ width: `${(d.low / maxScore) * 100}%` }} />
                </div>
                <span className="device-score">{d.weightedScore}</span>
              </div>
              <div className="device-counts">
                <span className="count-critical">{d.critical}C</span>
                <span className="count-high">{d.high}H</span>
                <span className="count-medium">{d.medium}M</span>
                <span className="count-low">{d.low}L</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* OS Platform breakdown */}
      {data.osPlatforms && data.osPlatforms.length > 0 && (
        <div className="section">
          <h3 className="section-title">Risk by OS Platform</h3>
          <table className="data-table">
            <thead>
              <tr>
                <th>Platform</th>
                <th>Devices</th>
                <th>Vulns</th>
                <th>Critical</th>
                <th>High</th>
                <th>Score</th>
              </tr>
            </thead>
            <tbody>
              {data.osPlatforms.map((p) => (
                <tr key={p.os}>
                  <td className="td-name">{p.os}</td>
                  <td className="td-center">{p.deviceCount}</td>
                  <td className="td-center">{p.totalVulns.toLocaleString()}</td>
                  <td className="td-center td-critical">{p.critical}</td>
                  <td className="td-center td-high">{p.high}</td>
                  <td className="td-center"><strong>{p.weightedScore}</strong></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Top CVEs */}
      {data.topCVEs && data.topCVEs.length > 0 && (
        <div className="section">
          <h3 className="section-title">Most Prevalent CVEs</h3>
          <table className="data-table">
            <thead>
              <tr>
                <th>CVE ID</th>
                <th>Severity</th>
                <th>Affected Devices</th>
              </tr>
            </thead>
            <tbody>
              {data.topCVEs.map((c) => (
                <tr key={c.cveId}>
                  <td className="td-mono">{c.cveId}</td>
                  <td className={`td-center td-${c.severity.toLowerCase()}`}>{c.severity}</td>
                  <td className="td-center"><strong>{c.affectedDevices}</strong></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="view-footer">Generated: {new Date(data.generatedAt).toLocaleString()}</div>
    </div>
  );
}

// ─── View 3: Compliance Posture ─────────────────────────────

function GaugeChart({ score, size = 80 }: { score: number; size?: number }) {
  const r = (size - 8) / 2;
  const circumference = Math.PI * r; // Half circle
  const filled = (score / 100) * circumference;

  const getColor = (s: number) => {
    if (s >= 80) return "#7cbb00";
    if (s >= 60) return "#00a4ef";
    if (s >= 40) return "#ffbb00";
    if (s >= 20) return "#e87400";
    return "#f65314";
  };

  return (
    <svg width={size} height={size * 0.65} viewBox={`0 0 ${size} ${size * 0.65}`}>
      {/* Background arc */}
      <path
        d={`M 4 ${size * 0.6} A ${r} ${r} 0 0 1 ${size - 4} ${size * 0.6}`}
        fill="none" stroke="#333" strokeWidth="6" strokeLinecap="round"
      />
      {/* Filled arc */}
      <path
        d={`M 4 ${size * 0.6} A ${r} ${r} 0 0 1 ${size - 4} ${size * 0.6}`}
        fill="none" stroke={getColor(score)} strokeWidth="6" strokeLinecap="round"
        strokeDasharray={`${filled} ${circumference}`}
      />
      {/* Score text */}
      <text x={size / 2} y={size * 0.55} textAnchor="middle" fill="#e0e0e0"
        fontSize="14" fontWeight="700">
        {score}%
      </text>
    </svg>
  );
}

function CompliancePostureView({ data }: { data: ComplianceData }) {
  const [showUnhealthyOnly, setShowUnhealthyOnly] = useState(false);

  const filteredRecs = useMemo(() => {
    if (!data.recommendations) return [];
    return showUnhealthyOnly
      ? data.recommendations.filter((r) => r.status === "Unhealthy")
      : data.recommendations;
  }, [data.recommendations, showUnhealthyOnly]);

  return (
    <div className="compliance-wrapper">
      <h2 className="view-title">{data.title}</h2>

      {/* KPI row */}
      <div className="kpi-row">
        <div className="kpi-card">
          <span className="kpi-value">{data.stats.totalStandards}</span>
          <span className="kpi-label">Standards</span>
        </div>
        <div className="kpi-card">
          <span className="kpi-value">{data.stats.avgScore}%</span>
          <span className="kpi-label">Avg Compliance</span>
        </div>
        <div className="kpi-card kpi-ok">
          <span className="kpi-value">{data.stats.totalHealthy}</span>
          <span className="kpi-label">Healthy</span>
        </div>
        <div className="kpi-card kpi-critical">
          <span className="kpi-value">{data.stats.totalUnhealthy}</span>
          <span className="kpi-label">Unhealthy</span>
        </div>
      </div>

      {/* Attack paths */}
      {data.attackPaths && (
        <div className="section attack-path-section">
          <h3 className="section-title">Attack Paths (CTEM)</h3>
          <div className="attack-path-cards">
            <div className="ap-card ap-critical">
              <span className="ap-value">{data.attackPaths.critical}</span>
              <span className="ap-label">Critical</span>
            </div>
            <div className="ap-card ap-high">
              <span className="ap-value">{data.attackPaths.high}</span>
              <span className="ap-label">High</span>
            </div>
            <div className="ap-card ap-medium">
              <span className="ap-value">{data.attackPaths.medium}</span>
              <span className="ap-label">Medium</span>
            </div>
            <div className="ap-card ap-total">
              <span className="ap-value">{data.attackPaths.total}</span>
              <span className="ap-label">Total</span>
            </div>
            {data.attackPaths.riskScore !== undefined && (
              <div className="ap-card ap-score">
                <span className="ap-value">{data.attackPaths.riskScore}</span>
                <span className="ap-label">Risk Score</span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Standards gauges */}
      <div className="section">
        <h3 className="section-title">Standards Compliance</h3>
        <div className="standards-grid">
          {data.standards.map((s) => (
            <div key={s.name} className="standard-card">
              <GaugeChart score={s.score} />
              <span className="standard-name" title={s.name}>
                {s.name.length > 28 ? s.name.slice(0, 26) + ".." : s.name}
              </span>
              <div className="standard-counts">
                <span className="sc-healthy">{s.healthy} healthy</span>
                <span className="sc-unhealthy">{s.unhealthy} unhealthy</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Recommendations table */}
      {data.recommendations && data.recommendations.length > 0 && (
        <div className="section">
          <div className="section-header">
            <h3 className="section-title">Recommendations ({filteredRecs.length})</h3>
            <label className="filter-toggle">
              <input type="checkbox" checked={showUnhealthyOnly}
                onChange={(e) => setShowUnhealthyOnly(e.target.checked)} />
              Unhealthy only
            </label>
          </div>
          <table className="data-table">
            <thead>
              <tr>
                <th>Recommendation</th>
                <th>Status</th>
                <th>Severity</th>
                {filteredRecs.some((r) => r.category) && <th>Category</th>}
              </tr>
            </thead>
            <tbody>
              {filteredRecs.slice(0, 50).map((r, i) => (
                <tr key={i}>
                  <td className="td-name">{r.name}</td>
                  <td className={`td-center td-status-${r.status.toLowerCase()}`}>
                    {r.status === "Healthy" ? "\u2705" : r.status === "Unhealthy" ? "\uD83D\uDD34" : "\u2796"} {r.status}
                  </td>
                  <td className={`td-center td-${r.severity.toLowerCase()}`}>{r.severity}</td>
                  {filteredRecs.some((x) => x.category) && <td>{r.category ?? ""}</td>}
                </tr>
              ))}
            </tbody>
          </table>
          {filteredRecs.length > 50 && (
            <div className="table-more">Showing 50 of {filteredRecs.length} recommendations</div>
          )}
        </div>
      )}

      <div className="view-footer">Generated: {new Date(data.generatedAt).toLocaleString()}</div>
    </div>
  );
}

// ─── Root App ───────────────────────────────────────────────

function App() {
  const [data, setData] = useState<ViewData | null>(null);
  const [_hostContext, setHostContext] = useState<McpUiHostContext | undefined>();

  const { app, error } = useApp({
    appInfo: { name: "Sentinel Exposure Management", version: "0.1.0" },
    capabilities: {},
    onAppCreated: (app) => {
      app.ontoolresult = (params) => {
        if (params.structuredContent) {
          setData(params.structuredContent as unknown as ViewData);
        }
      };
      app.onhostcontextchanged = (params) => {
        setHostContext((prev) => ({ ...prev, ...params }));
      };
    },
  });

  useEffect(() => {
    if (app) {
      setHostContext(app.getHostContext());
    }
  }, [app]);

  if (error) {
    return <div className="status-msg error"><span>Error: {error.message}</span></div>;
  }

  if (!app) {
    return <div className="status-msg loading"><div className="spinner" /><span>Connecting...</span></div>;
  }

  if (!data) {
    return <div className="status-msg loading"><div className="spinner" /><span>Waiting for exposure data...</span></div>;
  }

  switch (data.viewType) {
    case "exposure-graph":
      return <ExposureGraphView data={data} />;
    case "vulnerability-dashboard":
      return <VulnDashboardView data={data} />;
    case "compliance-posture":
      return <CompliancePostureView data={data} />;
    default:
      return <div className="status-msg error"><span>Unknown view type</span></div>;
  }
}

// Mount the app
const container = document.getElementById("root");
if (container) {
  const root = createRoot(container);
  root.render(<App />);
}
