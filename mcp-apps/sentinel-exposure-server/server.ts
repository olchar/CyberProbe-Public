/**
 * Sentinel Exposure Management MCP Server
 *
 * Unified server providing 3 visualization tools:
 *   1. show-exposure-graph     — Interactive force-directed graph of ExposureGraphNodes/Edges
 *   2. show-vulnerability-dashboard — Vulnerability posture: severity distribution, top devices, CVEs
 *   3. show-compliance-posture — CNAPP/CTEM compliance scores, standards, recommendations
 *
 * Data shapes match the output of CyberProbe's exposure-management skill KQL queries.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ReadResourceResult } from "@modelcontextprotocol/sdk/types.js";
import fs from "node:fs/promises";
import path from "node:path";
import { z } from "zod";
import {
  RESOURCE_MIME_TYPE,
  registerAppResource,
  registerAppTool,
} from "@modelcontextprotocol/ext-apps/server";

// Works both from source (server.ts) and compiled (dist/server.js)
const DIST_DIR = import.meta.filename.endsWith(".ts")
  ? path.join(import.meta.dirname, "dist")
  : import.meta.dirname;

// ─────────────────────────────────────────────────────────────
// Shared schemas
// ─────────────────────────────────────────────────────────────

const ViewTypeSchema = z.enum([
  "exposure-graph",
  "vulnerability-dashboard",
  "compliance-posture",
]);

// ─────────────────────────────────────────────────────────────
// Tool 1: Exposure Graph
// ─────────────────────────────────────────────────────────────

const GraphNodeSchema = z.object({
  id: z.string().describe("NodeId from ExposureGraphNodes"),
  name: z.string().describe("NodeName (e.g., device name, identity UPN, IP)"),
  label: z.string().describe("NodeLabel (e.g., microsoft.compute/virtualmachines, azure/user)"),
  riskScore: z.number().optional().describe("Risk score from NodeProperties.rawData.riskScore"),
  exposureScore: z.number().optional().describe("Exposure score from NodeProperties.rawData.exposureScore"),
  isInternetFacing: z.boolean().optional().describe("True if isCustomerFacing == true"),
  isRceVulnerable: z.boolean().optional().describe("True if vulnerable to remote code execution"),
  sensorHealth: z.string().optional().describe("sensorHealthState: Active, Inactive, etc."),
  maxCvss: z.number().optional().describe("Max CVSS score for RCE-vulnerable assets"),
});

const GraphEdgeSchema = z.object({
  sourceId: z.string().describe("SourceNodeId"),
  sourceName: z.string().describe("SourceNodeName"),
  sourceLabel: z.string().optional().describe("SourceNodeLabel"),
  targetId: z.string().describe("TargetNodeId"),
  targetName: z.string().describe("TargetNodeName"),
  targetLabel: z.string().optional().describe("TargetNodeLabel"),
  edgeLabel: z.string().describe("EdgeLabel (e.g., 'has permissions to', 'affecting', 'routes traffic to')"),
});

const ChokePointSchema = z.object({
  name: z.string().describe("Node name of the choke point"),
  incomingPaths: z.number().describe("Number of incoming attack path edges"),
  totalVulns: z.number().optional().describe("Total vulnerability count (from cross-reference query)"),
  criticalVulns: z.number().optional().describe("Critical vulnerability count"),
  highVulns: z.number().optional().describe("High vulnerability count"),
});

const ExposureGraphInputSchema = z.object({
  nodes: z.array(GraphNodeSchema).describe("Array of exposure graph nodes from ExposureGraphNodes KQL query"),
  edges: z.array(GraphEdgeSchema).describe("Array of exposure graph edges from ExposureGraphEdges KQL query"),
  chokePoints: z.array(ChokePointSchema).optional().describe("Highlighted choke point nodes with path counts"),
  title: z.string().optional().default("Exposure Graph").describe("Title displayed above the graph"),
  focus: z.enum(["full", "choke-points", "internet-facing", "attack-paths"])
    .optional().default("full")
    .describe("Graph focus mode: full graph, choke points only, internet-facing only, or attack paths"),
});

const ExposureGraphOutputSchema = z.object({
  viewType: z.literal("exposure-graph"),
  nodes: z.array(GraphNodeSchema),
  edges: z.array(GraphEdgeSchema),
  chokePoints: z.array(ChokePointSchema).optional(),
  title: z.string(),
  focus: z.string(),
  stats: z.object({
    totalNodes: z.number(),
    totalEdges: z.number(),
    uniqueNodeTypes: z.number(),
    uniqueEdgeTypes: z.number(),
    internetFacingCount: z.number(),
    chokePointCount: z.number(),
  }),
  generatedAt: z.string(),
});

// ─────────────────────────────────────────────────────────────
// Tool 2: Vulnerability Dashboard
// ─────────────────────────────────────────────────────────────

const SeverityDistributionSchema = z.object({
  critical: z.number().describe("Count of critical-severity unique CVEs"),
  high: z.number().describe("Count of high-severity unique CVEs"),
  medium: z.number().describe("Count of medium-severity unique CVEs"),
  low: z.number().describe("Count of low-severity unique CVEs"),
  totalDevices: z.number().describe("Number of devices with vulnerabilities"),
  totalUniqueVulns: z.number().describe("Total unique CVE count"),
});

const TopDeviceSchema = z.object({
  name: z.string().describe("DeviceName"),
  os: z.string().describe("OSPlatform"),
  total: z.number().describe("Total vulnerability count"),
  critical: z.number().describe("Critical-severity count"),
  high: z.number().describe("High-severity count"),
  medium: z.number().describe("Medium-severity count"),
  low: z.number().describe("Low-severity count"),
  weightedScore: z.number().describe("Weighted score: Critical*4 + High*2 + Medium*1 + Low"),
});

const OsPlatformSchema = z.object({
  os: z.string().describe("OS platform name"),
  deviceCount: z.number().describe("Number of devices with this OS"),
  totalVulns: z.number().describe("Total vulnerability count"),
  critical: z.number().describe("Critical-severity count"),
  high: z.number().describe("High-severity count"),
  weightedScore: z.number().describe("Weighted risk score"),
});

const TopCveSchema = z.object({
  cveId: z.string().describe("CVE identifier"),
  severity: z.string().describe("Vulnerability severity level"),
  affectedDevices: z.number().describe("Number of affected devices"),
});

const VulnDashboardInputSchema = z.object({
  severityDistribution: SeverityDistributionSchema.describe("Fleet-level severity breakdown"),
  topDevices: z.array(TopDeviceSchema).describe("Top vulnerable devices by weighted score"),
  osPlatforms: z.array(OsPlatformSchema).optional().describe("Vulnerability breakdown by OS platform"),
  topCVEs: z.array(TopCveSchema).optional().describe("Most prevalent critical/high CVEs"),
  title: z.string().optional().default("Vulnerability Posture").describe("Dashboard title"),
});

const VulnDashboardOutputSchema = z.object({
  viewType: z.literal("vulnerability-dashboard"),
  severityDistribution: SeverityDistributionSchema,
  topDevices: z.array(TopDeviceSchema),
  osPlatforms: z.array(OsPlatformSchema).optional(),
  topCVEs: z.array(TopCveSchema).optional(),
  title: z.string(),
  stats: z.object({
    totalDevices: z.number(),
    totalVulns: z.number(),
    criticalPercent: z.number(),
    highPercent: z.number(),
    maxWeightedScore: z.number(),
  }),
  generatedAt: z.string(),
});

// ─────────────────────────────────────────────────────────────
// Tool 3: Compliance Posture
// ─────────────────────────────────────────────────────────────

const StandardSchema = z.object({
  name: z.string().describe("Standard display name (e.g., 'Microsoft Cloud Security Benchmark')"),
  score: z.number().describe("Compliance score 0-100 percent"),
  healthy: z.number().describe("Count of Healthy assessments"),
  unhealthy: z.number().describe("Count of Unhealthy assessments"),
  notApplicable: z.number().optional().default(0).describe("Count of Not Applicable assessments"),
  total: z.number().describe("Total assessment count"),
});

const AttackPathSummarySchema = z.object({
  critical: z.number().describe("Critical-risk attack paths"),
  high: z.number().describe("High-risk attack paths"),
  medium: z.number().describe("Medium-risk attack paths"),
  total: z.number().describe("Total attack path count"),
  riskScore: z.number().optional().describe("Composite risk score from weighted risk factors"),
});

const RecommendationSchema = z.object({
  name: z.string().describe("Recommendation display name"),
  status: z.enum(["Healthy", "Unhealthy", "NotApplicable"]).describe("Assessment status"),
  severity: z.string().describe("Recommendation severity: High, Medium, Low"),
  category: z.string().optional().describe("Category grouping"),
});

const ComplianceInputSchema = z.object({
  standards: z.array(StandardSchema).describe("Per-standard compliance scores"),
  attackPaths: AttackPathSummarySchema.optional().describe("Attack path summary (CTEM headline)"),
  recommendations: z.array(RecommendationSchema).optional().describe("Individual recommendation statuses"),
  title: z.string().optional().default("CNAPP Compliance Posture").describe("Dashboard title"),
});

const ComplianceOutputSchema = z.object({
  viewType: z.literal("compliance-posture"),
  standards: z.array(StandardSchema),
  attackPaths: AttackPathSummarySchema.optional(),
  recommendations: z.array(RecommendationSchema).optional(),
  title: z.string(),
  stats: z.object({
    totalStandards: z.number(),
    avgScore: z.number(),
    totalHealthy: z.number(),
    totalUnhealthy: z.number(),
    totalRecommendations: z.number(),
  }),
  generatedAt: z.string(),
});

// ─────────────────────────────────────────────────────────────
// Server factory
// ─────────────────────────────────────────────────────────────

export function createServer(): McpServer {
  const server = new McpServer({
    name: "Sentinel Exposure Management Server",
    version: "0.1.0",
  });

  const graphResourceUri = "ui://show-exposure-graph/mcp-app.html";
  const vulnResourceUri = "ui://show-vulnerability-dashboard/mcp-app.html";
  const complianceResourceUri = "ui://show-compliance-posture/mcp-app.html";

  // ── Tool 1: Exposure Graph ──────────────────────────────────

  registerAppTool(
    server,
    "show-exposure-graph",
    {
      title: "Show Exposure Graph",
      description: `Renders an interactive force-directed graph of your exposure attack surface.
Pass ExposureGraphNodes and ExposureGraphEdges data from Advanced Hunting KQL queries.
Highlights choke points, internet-facing assets, and attack path relationships.
Supports focus modes: full graph, choke-points only, internet-facing only, or attack-paths.`,
      inputSchema: ExposureGraphInputSchema.shape,
      outputSchema: ExposureGraphOutputSchema.shape,
      _meta: { ui: { resourceUri: graphResourceUri } },
    },
    async ({ nodes, edges, chokePoints, title, focus }) => {
      const nodeTypes = new Set(nodes.map((n) => n.label));
      const edgeTypes = new Set(edges.map((e) => e.edgeLabel));
      const internetFacing = nodes.filter((n) => n.isInternetFacing).length;

      const stats = {
        totalNodes: nodes.length,
        totalEdges: edges.length,
        uniqueNodeTypes: nodeTypes.size,
        uniqueEdgeTypes: edgeTypes.size,
        internetFacingCount: internetFacing,
        chokePointCount: chokePoints?.length ?? 0,
      };

      const summary = `${title}
Nodes: ${stats.totalNodes} (${stats.uniqueNodeTypes} types)
Edges: ${stats.totalEdges} (${stats.uniqueEdgeTypes} relationship types)
Internet-facing: ${stats.internetFacingCount}
Choke points: ${stats.chokePointCount}`;

      return {
        content: [{ type: "text", text: summary }],
        structuredContent: {
          viewType: "exposure-graph" as const,
          nodes,
          edges,
          chokePoints,
          title,
          focus,
          stats,
          generatedAt: new Date().toISOString(),
        },
      };
    }
  );

  // ── Tool 2: Vulnerability Dashboard ─────────────────────────

  registerAppTool(
    server,
    "show-vulnerability-dashboard",
    {
      title: "Show Vulnerability Dashboard",
      description: `Renders a vulnerability posture dashboard with severity distribution,
top vulnerable devices by weighted score, OS platform breakdown, and most prevalent CVEs.
Pass data from DeviceTvmSoftwareVulnerabilities Advanced Hunting queries.`,
      inputSchema: VulnDashboardInputSchema.shape,
      outputSchema: VulnDashboardOutputSchema.shape,
      _meta: { ui: { resourceUri: vulnResourceUri } },
    },
    async ({ severityDistribution, topDevices, osPlatforms, topCVEs, title }) => {
      const totalVulns = severityDistribution.totalUniqueVulns;
      const criticalPct = totalVulns > 0
        ? Math.round((severityDistribution.critical / totalVulns) * 1000) / 10
        : 0;
      const highPct = totalVulns > 0
        ? Math.round((severityDistribution.high / totalVulns) * 1000) / 10
        : 0;
      const maxWeighted = topDevices.length > 0
        ? Math.max(...topDevices.map((d) => d.weightedScore))
        : 0;

      const stats = {
        totalDevices: severityDistribution.totalDevices,
        totalVulns,
        criticalPercent: criticalPct,
        highPercent: highPct,
        maxWeightedScore: maxWeighted,
      };

      const summary = `${title}
Devices: ${stats.totalDevices}
Unique CVEs: ${stats.totalVulns.toLocaleString()}
Critical: ${severityDistribution.critical} (${criticalPct}%)
High: ${severityDistribution.high} (${highPct}%)
Top device score: ${maxWeighted}`;

      return {
        content: [{ type: "text", text: summary }],
        structuredContent: {
          viewType: "vulnerability-dashboard" as const,
          severityDistribution,
          topDevices,
          osPlatforms,
          topCVEs,
          title,
          stats,
          generatedAt: new Date().toISOString(),
        },
      };
    }
  );

  // ── Tool 3: Compliance Posture ──────────────────────────────

  registerAppTool(
    server,
    "show-compliance-posture",
    {
      title: "Show Compliance Posture",
      description: `Renders a CNAPP/CTEM compliance posture dashboard with per-standard scores,
attack path summary, and recommendation status breakdown.
Pass data from securityresources Azure Resource Graph queries and Defender for Cloud assessments.`,
      inputSchema: ComplianceInputSchema.shape,
      outputSchema: ComplianceOutputSchema.shape,
      _meta: { ui: { resourceUri: complianceResourceUri } },
    },
    async ({ standards, attackPaths, recommendations, title }) => {
      const avgScore = standards.length > 0
        ? Math.round((standards.reduce((s, st) => s + st.score, 0) / standards.length) * 10) / 10
        : 0;
      const totalHealthy = standards.reduce((s, st) => s + st.healthy, 0);
      const totalUnhealthy = standards.reduce((s, st) => s + st.unhealthy, 0);

      const stats = {
        totalStandards: standards.length,
        avgScore,
        totalHealthy,
        totalUnhealthy,
        totalRecommendations: recommendations?.length ?? 0,
      };

      const summary = `${title}
Standards: ${stats.totalStandards}
Avg compliance: ${avgScore}%
Healthy: ${totalHealthy} | Unhealthy: ${totalUnhealthy}
Attack paths: ${attackPaths?.total ?? "N/A"}
Recommendations: ${stats.totalRecommendations}`;

      return {
        content: [{ type: "text", text: summary }],
        structuredContent: {
          viewType: "compliance-posture" as const,
          standards,
          attackPaths,
          recommendations,
          title,
          stats,
          generatedAt: new Date().toISOString(),
        },
      };
    }
  );

  // ── Resources — all 3 tools share the same React app ────────

  async function serveHtml(): Promise<ReadResourceResult> {
    const html = await fs.readFile(
      path.join(DIST_DIR, "mcp-app.html"),
      "utf-8"
    );
    return { contents: [{ uri: graphResourceUri, mimeType: RESOURCE_MIME_TYPE, text: html }] };
  }

  registerAppResource(server, graphResourceUri, graphResourceUri,
    { mimeType: RESOURCE_MIME_TYPE }, serveHtml);
  registerAppResource(server, vulnResourceUri, vulnResourceUri,
    { mimeType: RESOURCE_MIME_TYPE }, async () => {
      const r = await serveHtml();
      return { contents: [{ ...r.contents[0], uri: vulnResourceUri }] };
    });
  registerAppResource(server, complianceResourceUri, complianceResourceUri,
    { mimeType: RESOURCE_MIME_TYPE }, async () => {
      const r = await serveHtml();
      return { contents: [{ ...r.contents[0], uri: complianceResourceUri }] };
    });

  return server;
}
