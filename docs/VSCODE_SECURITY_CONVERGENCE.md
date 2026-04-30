# VS Code as the SecOps IDE — Convergence of Microsoft Security AI Features

**Created:** 2026-04-30
**Sources:** Microsoft Learn (Sentinel, Defender XDR, Security Copilot)

---

## TL;DR

VS Code has become Microsoft's de-facto **security-engineering workbench**. The convergence has two distinct shapes:

| Pattern | What it means | Examples |
|---|---|---|
| **Embedded VS Code inside the Defender portal** | A VS Code runtime is hosted *in the browser* alongside Defender/Sentinel — you never leave the portal | **SOAR Playbook Generator** (preview) — the Cline AI coding agent in embedded VS Code authoring Python playbooks |
| **Standalone VS Code as the security IDE** | The Microsoft Sentinel extension + GitHub Copilot Agent mode + Jupyter + MCP turn local VS Code into a SecOps IDE | Connector Builder, Custom Graph authoring, Notebook jobs, MCP tool collections, Security Copilot agent authoring |

Both Sentinel-AI-connector creation and SOAR playbook generation **converge in VS Code** — but one runs *embedded* in the portal, the other runs *locally* with GitHub Copilot.

---

## VS Code-Centric AI Features

| Feature | Where VS Code fits | Status | Reference |
|---|---|---|---|
| **Generate playbooks using AI in Sentinel** | Embedded VS Code + **Cline** AI agent in the Defender portal. Plan/Act mode, Python output, integration profiles, Enhanced Alert Trigger covering Sentinel + Defender + XDR alerts. | Preview | [docs](https://learn.microsoft.com/azure/sentinel/automation/generate-playbook) |
| **Sentinel custom connectors via AI agent** | Local VS Code + Microsoft Sentinel extension + **GitHub Copilot Agent mode** (requires **Claude Sonnet 4.5**). Generates CCF-based connectors, schemas, UI, polling logic. | GA | [docs](https://learn.microsoft.com/azure/sentinel/create-custom-connector-builder-agent) |
| **AI-assisted custom graph authoring** | Local VS Code + Jupyter + GitHub Copilot building Sentinel custom graphs from natural language | Preview | [docs](https://learn.microsoft.com/azure/sentinel/datalake/create-graphs-with-ai) |
| **Sentinel data lake notebooks** | VS Code + Sentinel extension + PySpark + GitHub Copilot for KQL/Python in Jupyter against the lake | GA | [docs](https://learn.microsoft.com/azure/sentinel/datalake/notebooks) |
| **Sentinel MCP server** | VS Code is the reference MCP host. Multiple scenario-focused tool collections (data exploration, hunting, agent creation). | GA | [docs](https://learn.microsoft.com/azure/sentinel/datalake/sentinel-mcp-overview) |
| **Security Copilot Agent Creation MCP** | `https://sentinel.microsoft.com/mcp/security-copilot-agent-creation` — build Security Copilot agents from VS Code with GitHub Copilot agent mode | GA | [docs](https://learn.microsoft.com/copilot/security/developer/mcp-get-started) |
| **Security Store platform-solution publishing** | Requires VS Code + Sentinel extension + GitHub Copilot extension to author and publish solutions to Microsoft Security Store | GA | [docs](https://learn.microsoft.com/azure/sentinel/solution-setup-essentials) |

---

## Recent AI Features (Not VS Code-Centric)

These run inside Defender / Security Copilot, not VS Code:

| Feature | Date | What it does | Reference |
|---|---|---|---|
| **Security Analyst Agent** | April 2026 (preview) | Multi-step autonomous risk investigation across Defender XDR + Sentinel Log Analytics + Sentinel Data Lake. Flexible analysis, interactive exploration, follow-up chat. Surfaces prioritized risks with evidence trail. | [docs](https://learn.microsoft.com/copilot/security/security-analyst-agent) |
| **Dynamic Threat Detection Agent** | Preview | Always-on, zero-touch backend agent that uncovers **false negatives** by correlating alerts/anomalies/TI across Defender + Sentinel. Generates dynamic alerts with MITRE mapping. | [docs](https://learn.microsoft.com/defender-xdr/dynamic-threat-detection-agent) |
| **AIAgentsInfo table expansion** | April 2026 (preview) | Advanced Hunting `AIAgentsInfo` now covers **Microsoft Foundry, third-party marketplace, and custom LOB agents** — not just Copilot Studio. New columns for richer XPIA/jailbreak hunting. | [docs](https://learn.microsoft.com/defender-xdr/advanced-hunting-aiagentsinfo-table) |
| **Built-in alert tuning rules** | April 2026 (GA) | Suppress benign Defender for Endpoint / Defender for Office 365 alerts without breaking AIR. | [docs](https://learn.microsoft.com/defender-xdr/investigate-alerts#built-in-alert-tuning-rules) |
| **Activities tab — predictive shielding & disruption status** | April 2026 (preview) | Track auto-disruption + predictive shielding actions per incident (Contain user, GPO hardening, Safeboot hardening). | [docs](https://learn.microsoft.com/defender-xdr/autoad-results#track-the-action-status-in-the-activities-tab-preview) |
| **Phishing Triage Agent** | July 2025 (preview) | Autonomous phishing classification with semantic analysis + decision map. | [docs](https://learn.microsoft.com/defender-xdr/phishing-triage-agent) |
| **Threat Intelligence Briefing Agent** | July 2025 (preview) | Org-specific threat-intel briefings in minutes via dynamic reasoning. | [docs](https://learn.microsoft.com/copilot/security/threat-intel-briefing-agent) |
| **Microsoft Security Store** | Sept 2025 | ~30 partner-built Security Copilot agents (Forensic, Ransomware Kill Chain, Privileged Admin Watchdog, Workload ID Agent, etc.) + 50 SaaS solutions. Published via VS Code + Sentinel extension. | [Store](https://securitystore.microsoft.com/) |
| **Security Copilot Capacity Calculator** | July 2025 | SCU forecasting in standalone experience. | — |

---

## The Convergence Picture

```
                              ┌─────────────────────────────────┐
                              │   GitHub Copilot Agent Mode      │
                              │   + Claude Sonnet 4.5            │
                              └──────────────┬──────────────────┘
                                             │
                  ┌──────────────────────────┼──────────────────────────┐
                  │                          │                          │
        ┌─────────▼─────────┐    ┌──────────▼─────────┐   ┌────────────▼────────────┐
        │  Standalone VS    │    │ Embedded VS Code   │   │ Defender / Sec. Copilot │
        │  Code (local)     │    │ (in Defender       │   │ backend (no IDE)        │
        │                   │    │  portal)           │   │                         │
        │ • Connector       │    │ • SOAR Playbook    │   │ • Security Analyst Agt  │
        │   Builder         │    │   Generator (Cline)│   │ • Dynamic Threat Det.   │
        │ • Custom Graph    │    │                    │   │ • Phishing Triage Agt   │
        │ • Lake Notebooks  │    │                    │   │ • TI Briefing Agent     │
        │ • Sentinel MCP    │    │                    │   │ • Partner agents        │
        │ • Sec Copilot     │    │                    │   │                         │
        │   Agent creation  │    │                    │   │                         │
        └───────────────────┘    └────────────────────┘   └─────────────────────────┘
                  │                          │                          │
                  └──────────────────────────┼──────────────────────────┘
                                             │
                              ┌──────────────▼──────────────┐
                              │ Sentinel Data Lake / Graph  │
                              │ Defender XDR / Security     │
                              │ Copilot SCUs                │
                              └─────────────────────────────┘
```

---

## Bottom Line

Microsoft is treating VS Code as the **detection-engineering and automation IDE** for SecOps (connectors, graphs, notebooks, playbooks via embedded Cline, MCP-based agents), while the *runtime* of finished agents continues to live in Defender / Sentinel / Security Copilot. If you've already adopted the Sentinel VS Code extension and GitHub Copilot Agent mode (which CyberProbe does), you're sitting on the convergence point.

### Two things specifically worth a closer look right now (relevant to CyberProbe's AI posture work)

1. **Expanded `AIAgentsInfo` table** (April 2026) — would have unblocked the Advanced Hunting 403 in the AI Security Posture report; now covers Foundry + 3P + LOB agents. Worth re-running the inventory once `ThreatHunting.Read.All` is granted to the calling app.
2. **Security Analyst Agent** preview — overlaps with what CyberProbe's `kql-auto-investigate` skill does. Useful to benchmark side-by-side: same entity, same time range, compare evidence trails and prioritization.

---

## Related CyberProbe Assets

| Asset | Path |
|---|---|
| AI Security Posture report (current) | [reports-private/ai_security_posture_report_2026-04-30.html](../reports-private/ai_security_posture_report_2026-04-30.html) |
| AI Agent Inventory report | [reports-private/ai_agent_posture_report_2026-04-30.json](../reports-private/ai_agent_posture_report_2026-04-30.json) |
| Sentinel MCP integration in this repo | [.vscode/mcp.json](../.vscode/mcp.json) |
| Auto-investigation skill | [.github/skills/kql-auto-investigate/SKILL.md](../.github/skills/kql-auto-investigate/SKILL.md) |
| Detection engineering skill (Sigma → analytic rules) | [.github/skills/detection-engineering/SKILL.md](../.github/skills/detection-engineering/SKILL.md) |
