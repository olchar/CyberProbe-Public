# MCP Apps — Interactive Visualizations for Copilot Chat

This directory contains **Model Context Protocol (MCP) Apps** — local MCP servers that render interactive visualizations inline in VS Code Copilot Chat.

MCP Apps extend CyberProbe's investigation skills with rich visual output: graphs, dashboards, gauge charts, and tables — all rendered as React single-page applications inside the chat panel.

---

## Available Apps

### sentinel-exposure-server

**Unified Exposure Management / CTEM / CNAPP visualization server**

| Tool | Visualization | Data Source |
|------|---------------|-------------|
| `show-exposure-graph` | Force-directed SVG graph with color-coded nodes, choke point glow rings, internet-facing dashed rings, click-to-inspect detail panel, remediation priority table | `ExposureGraphNodes` + `ExposureGraphEdges` (Advanced Hunting) |
| `show-vulnerability-dashboard` | KPI cards, stacked severity distribution bar, device ranking with weighted score bars, OS platform table, top CVE table | `DeviceTvmSoftwareVulnerabilities` (Advanced Hunting) |
| `show-compliance-posture` | KPI cards, attack path severity cards, SVG gauge charts per standard, filterable recommendations table | `securityresources` (Azure Resource Graph) |

**Stack**: Node.js, TypeScript, React 18, Vite 5, `vite-plugin-singlefile`, `@modelcontextprotocol/ext-apps`

---

## Architecture

Each MCP App follows the same pattern:

```
mcp-apps/<app-name>/
├── package.json            # Dependencies & build scripts
├── main.ts                 # Stdio entry point (StdioServerTransport)
├── server.ts               # Tool definitions (registerAppTool) + resource (registerAppResource)
├── mcp-app.html            # HTML shell with #root div
├── vite.config.ts          # Vite + React + singleFile plugins
├── tsconfig.json           # Frontend TypeScript config
├── tsconfig.server.json    # Server TypeScript config
├── src/
│   ├── mcp-app.tsx         # React frontend (renders structuredContent from tools)
│   └── mcp-app.css         # Dark theme CSS
├── node_modules/           # Dependencies (gitignored)
└── dist/                   # Build output (gitignored)
    ├── main.js             # Compiled server
    └── mcp-app.html        # Single-file HTML (all JS/CSS inlined)
```

### How It Works

1. **`registerAppTool`** defines a tool with input schema (Zod) and a handler that returns `structuredContent` (JSON data for the frontend)
2. **`registerAppResource`** serves the built single-file HTML at a `ui://` URI
3. **React frontend** listens for `ontoolresult` events, receives `structuredContent`, and renders the appropriate view
4. **VS Code** renders the HTML inline in Copilot Chat when the tool is invoked

### Data Flow

```
exposure-management skill                MCP App Server              React Frontend
─────────────────────                    ──────────────              ──────────────
KQL queries via AH/ARG                   
  → ExposureGraphNodes/Edges              show-exposure-graph
  → DeviceTvmSoftwareVulnerabilities      show-vulnerability-dashboard
  → securityresources                     show-compliance-posture
                                            │
                                            ▼
                                         structuredContent (JSON)
                                            │
                                            ▼
                                         mcp-app.html renders
                                         interactive SVG inline
                                         in Copilot Chat
```

---

## Building

```bash
cd mcp-apps/sentinel-exposure-server
npm install
npm run build
```

This runs two build steps:
1. `build:app` — Vite bundles React + CSS into a single HTML file (`dist/mcp-app.html`)
2. `build:server` — TypeScript compiles the server to `dist/main.js`

---

## Configuration

MCP Apps are registered in `.vscode/mcp.json` as local stdio servers:

```json
"Exposure Management": {
    "command": "node",
    "args": ["${workspaceFolder}/mcp-apps/sentinel-exposure-server/dist/main.js", "--stdio"],
    "type": "stdio"
}
```

---

## Creating New MCP Apps

To add a new visualization app:

1. Copy `sentinel-exposure-server/` as a template
2. Update `package.json` name and description
3. Define tools in `server.ts` with Zod schemas matching your data shapes
4. Build the React views in `src/mcp-app.tsx`
5. Style in `src/mcp-app.css` (dark theme base included)
6. Add entry to `.vscode/mcp.json`
7. Build with `npm run build`

---

**Last Updated:** April 13, 2026
