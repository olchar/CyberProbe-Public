# Agent Communication, Gateway & Multi-Cloud Hosting on Azure

*Tools (MCP), Agent-to-Agent (A2A), AI Gateway, Foundry Control Plane, and hybrid / multi-cloud patterns*

**Last updated:** 2026-05-01
**Audience:** Architects, platform engineers, and customers evaluating Microsoft's stack for multi-agent AI systems
**Scope:** How AI agents communicate with tools and with each other on Microsoft Azure, which Azure services act as the gateway / control plane, and how to govern agents that run outside Azure (AWS, GCP, on-prem, edge).

---

## 📑 Table of Contents

1. [The Two Communication Layers](#the-two-communication-layers)
2. [Tool Access — MCP (south-bound)](#tool-access--mcp-south-bound)
3. [Agent-to-Agent — A2A (east-west)](#agent-to-agent--a2a-east-west)
4. [Microsoft Multi-Agent Platforms](#microsoft-multi-agent-platforms)
5. [Azure API Management as the AI Gateway](#azure-api-management-as-the-ai-gateway)
6. [Azure API Center — the Agent Registry](#azure-api-center--the-agent-registry)
7. [AI Gateway Inside Microsoft Foundry](#ai-gateway-inside-microsoft-foundry)
8. [Agents in Other Clouds (AWS / GCP / On-Prem / Edge)](#agents-in-other-clouds-aws--gcp--on-prem--edge)
9. [Reference Architecture](#reference-architecture)
10. [How CyberProbe Maps to This Model](#how-cyberprobe-maps-to-this-model)
11. [Caveats & Current Limitations](#caveats--current-limitations)
12. [References](#references)

---

## The Two Communication Layers

Distinguishing these two layers is essential — they use different protocols and different gateway capabilities.

| Layer | Direction | Purpose | Protocol |
|---|---|---|---|
| **Tool access** | Agent ↔ system | Agent calls APIs, databases, SaaS | **MCP** (Model Context Protocol) |
| **Agent-to-agent** | Agent ↔ agent | Agents delegate, negotiate, hand off | **A2A** (Agent2Agent Protocol) |

Production systems use **both** — they are complementary, not competing.

---

## Tool Access — MCP (south-bound)

**MCP** is an open standard (originated by Anthropic, broadly adopted) that lets LLM agents discover and call typed tools over a well-described interface.

**Why it matters:**
- Typed tool schemas — agent cannot fabricate parameters.
- Server-side auth — tokens live in the MCP server, not in the prompt.
- Capability scoping — each MCP server exposes only the verbs it needs.
- Auditable telemetry — every tool call is a discrete, structured event.
- Containment for prompt injection — agents can only respond by invoking other typed tools.

**Architecture:**
```
[ AI Agent / Host ] ──► [ MCP Client ] ──► [ MCP Server ] ──► [ Database / API / SaaS ]
```

---

## Agent-to-Agent — A2A (east-west)

**A2A (Agent2Agent Protocol)** is the open standard for agents (built on different frameworks/vendors) to discover and talk to each other.

**Key concepts:**
- **Agent Card** — JSON manifest at `/.well-known/agent.json` describing capabilities, skills, auth, endpoints.
- **JSON-RPC** runtime — task delegation, streaming updates, long-running async tasks.
- **Vendor-neutral** — Microsoft, Google, Salesforce, SAP, ServiceNow back it; donated to the Linux Foundation in 2025.

Think of A2A as **MCP for agents talking to other agents** instead of tools.

---

## Microsoft Multi-Agent Platforms

| Platform | Role | Multi-agent support |
|---|---|---|
| **Microsoft Agent Framework** (GA) | Unifies Semantic Kernel + AutoGen; .NET & Python | Sequential, concurrent, group-chat, handoff, graph-based orchestration; native MCP + A2A |
| **Microsoft Foundry — Agent Service** | Hosted agent runtime | "Connected agents" — one agent invokes another; tool registry; tracing; A2A + MCP |
| **Microsoft 365 Agents SDK / Agents Toolkit** | Agents in Teams, Copilot, Outlook | Cross-agent chaining, MCP tools |
| **Copilot Studio** | Low-code agent builder | Chains to other Copilot Studio agents, Foundry agents, external A2A endpoints |
| **Security Copilot** | Domain-specific (security) | Composable custom agents with skills (KQL, Defender, Sentinel, Intune, Purview) |

---

## Azure API Management as the AI Gateway

> **Direct answer to "is there an Azure gateway for agent communication?": Yes — Azure API Management's AI Gateway.**

The **AI Gateway** is **not a separate product** — it is an extension of the same APIM gateway documented in [API gateways in Azure API Management](https://learn.microsoft.com/azure/api-management/api-management-gateways-overview). Same SKUs, same policies engine, same data planes (managed, self-hosted, workspace).

### Three Classes of AI Traffic APIM Mediates

| Type | Purpose | Status |
|---|---|---|
| **AI model APIs** | Azure OpenAI, Foundry models, Bedrock, OpenAI-compatible endpoints | GA |
| **MCP servers** | Tool-access protocol (south-bound). Expose REST APIs as MCP, or pass through existing MCP servers | GA |
| **A2A agent APIs** | **Agent-to-agent communication** (east-west) | **Preview** (Basic v2 / Standard v2 / Premium v2) |

### What APIM Adds When You Import an A2A Agent

When you point APIM at an agent's Agent Card URL, it:

1. **Mediates JSON-RPC** runtime operations to the A2A backend.
2. **Rewrites the Agent Card** so consumers see APIM's hostname, prefers JSON-RPC transport, and includes APIM's subscription-key requirement in security.
3. **Applies the full APIM policy engine** — subscription keys, OAuth/Entra, rate limits, IP filters, transformations, content safety.
4. **Emits OpenTelemetry GenAI semantic-convention** telemetry into Application Insights:
   - `gen_ai.agent.id`
   - `gen_ai.agent.name`

### Common Policies for AI/Agent Traffic

- Token-limit and token-metric policies (cost control)
- Semantic caching (response reuse)
- Content safety / jailbreak detection
- Load balancing across multiple AI endpoints
- Per-app / per-team quota
- Backend authentication via managed identity

---

## Azure API Center — the Agent Registry

APIM mediates *traffic*. **Azure API Center** is the *catalog* — Microsoft's enterprise agent registry.

**Capabilities:**
- Centralized discovery of first-party and third-party agents (and APIs, MCP servers).
- Stores agent cards, skills, capabilities, customizable metadata.
- A2A agents in a linked APIM instance **sync automatically** into API Center.
- **Dependency maps** (preview) — visualize agent-to-agent relationships across the enterprise; help an agent identify which other agent to call.
- Curbs "shadow AI" by providing a governed channel for agent discovery and consumption.

---

## AI Gateway Inside Microsoft Foundry

For customers building on **Microsoft Foundry**, the AI Gateway can be enabled **directly in the Foundry control plane** (preview):

| Asset | What you can govern from Foundry |
|---|---|
| **Models** | Token quotas, rate limits across all model deployments |
| **Agents** | Register agents from anywhere (Azure, other clouds, on-prem); telemetry in Foundry + App Insights; apply throttling / content safety |
| **Tools (MCP)** | Register MCP tools hosted anywhere; appear in Foundry inventory for agent consumption |

Drop into the full Azure API Management experience for advanced scenarios (custom policies, federated gateways, enterprise networking) without losing continuity with Foundry-managed resources.

---

## Agents in Other Clouds (AWS / GCP / On-Prem / Edge)

Microsoft supports two complementary patterns for agents that run **outside Azure**. Large enterprises typically combine them.

### Pattern 1 — Register an External Agent in Foundry Control Plane

Microsoft Foundry Control Plane is explicitly designed for **agents running across different platforms and infrastructures** (Azure compute, AWS, GCP, on-prem, edge).

**Flow:**

1. Deploy your agent **anywhere reachable** (AWS Lambda / ECS / EKS, GCP Cloud Run / GKE, on-prem Kubernetes, bare metal).
2. Expose it over **HTTP** (general agents) or **A2A** with `/.well-known/agent-card.json`.
3. In Foundry, ensure an **AI Gateway is configured** (APIM under the hood).
4. **Register the agent** in Foundry Control Plane and select the protocol (HTTP or A2A).
5. Foundry generates a **proxy URL** backed by APIM. Clients call the proxy URL — original auth on the agent still applies.
6. For A2A agents, Foundry auto-discovers the Agent Card.

**What you get:**

- Centralized inventory and discoverability across clouds.
- Access control and monitoring through the AI Gateway.
- Telemetry in Application Insights using OpenTelemetry GenAI semantic conventions (`gen_ai.agent.id`, `gen_ai.agent.name`).
- Same APIM policy engine — rate limits, content safety, transformations, subscription keys.

**Agent requirements:**

- Exclusive endpoint reachable from the Foundry resource's network.
- HTTP or A2A protocol.
- (Optional) Emit OpenTelemetry GenAI traces.
- Foundry (new) portal for the management UI.

### Pattern 2 — APIM Self-Hosted Gateway (Hybrid / Multi-Cloud Data Plane)

For latency-sensitive, compliance-bound, sovereign, or air-gapped scenarios, deploy the **APIM gateway data plane** itself into the foreign environment.

- Self-hosted gateway is a **Linux Docker container**.
- Commonly deployed to **Kubernetes** — AKS, EKS, GKE, OpenShift, **Azure Arc-enabled Kubernetes**, or any conformant cluster.
- It **federates with an Azure-hosted APIM instance** for configuration and policy distribution; telemetry flows back to Azure.
- Agent traffic flows **directly** between callers and the agent backend in the same environment — never round-trips to Azure.

**Why use it:**

| Driver | Benefit |
|---|---|
| Latency | Calls between an agent and its tools stay local (e.g., both in AWS us-east-1) |
| Compliance / data residency | Traffic never crosses cloud or regional boundaries |
| Cost | Avoids cross-cloud egress fees |
| Air-gap / sovereign cloud | Run gateways where there is no inbound Azure connectivity |

**Tier note:** Self-hosted gateway is available in **Developer** and **Premium** APIM tiers (pre-v2 SKUs). For v2 SKUs, verify current docs — feature parity is evolving.

### Bonus — Microsoft Agent 365 Hosted Outside Azure

When the agent must appear in Microsoft 365 surfaces (Teams, Outlook, Copilot) but its **runtime** lives elsewhere:

- Identity, permissions, and Agent Blueprint live in **Entra ID + Microsoft Graph**.
- Runtime executes in GCP / AWS / on-prem.
- Bot Framework messaging endpoint registered against the foreign cloud.
- See: [Build an Agent 365 agent on Google Cloud Run](https://learn.microsoft.com/microsoft-agent-365/developer/deploy-agent-gcp) (analogous steps for AWS).

### Decision Cheat Sheet

| Scenario | Recommended pattern |
|---|---|
| Agent in AWS/GCP, want central Azure governance | **Pattern 1** — Register in Foundry Control Plane |
| Agent in AWS, must keep traffic in AWS for compliance/latency | **Pattern 2** — Self-hosted gateway in EKS, **+ Pattern 1** for catalog |
| On-prem agent, no inbound Azure, needs SOC oversight | **Pattern 2** — Self-hosted gateway on Arc-enabled Kubernetes |
| Agent must appear in Teams/Outlook, runtime in GCP | **Agent 365 + non-Azure hosting** |
| Multiple agents across clouds talking to each other | **Pattern 1** + APIM A2A mediation + API Center catalog |

### Cross-Cloud Architecture

```
  ┌─ AWS / GCP / On-Prem ────────────────────┐         ┌─ Azure ──────────────────────────────┐
  │                                          │         │                                       │
  │   Agent runtime                          │         │   Microsoft Foundry (Control Plane)   │
  │   ├─ A2A or HTTP endpoint                │ ◄────── │   ├─ AI Gateway (APIM)                │
  │   └─ /.well-known/agent-card.json        │ proxy   │   ├─ Custom agent registration        │
  │                                          │ URL     │   ├─ App Insights (OTel GenAI traces) │
  │   (Optional) APIM self-hosted gateway    │         │   └─ API Center (catalog + dep maps)  │
  │   container for local mediation          │ ◄────── │                                       │
  └──────────────────────────────────────────┘ federate└───────────────────────────────────────┘
                         ▲
                         │ A2A / HTTP via Foundry proxy URL
                         │
                    Other agents (Azure, GCP, on-prem, partner)
```

---

## Reference Architecture

```
                    ┌──────────────────────────────────────────────┐
                    │          Azure API Center (catalog)          │
                    │  agent registry · skills · dependency maps   │
                    └────────────────────┬─────────────────────────┘
                                         │ auto-sync
                                         ▼
  Agent A ──► [ APIM AI Gateway ] ──► Agent B  (A2A / JSON-RPC)
  Agent A ──► [ APIM AI Gateway ] ──► MCP server  ──► REST / DB / SaaS
  Agent A ──► [ APIM AI Gateway ] ──► Foundry / Azure OpenAI / Bedrock
                          │
                          ├─ Entra ID auth, subscription keys, OAuth
                          ├─ Rate limit, token quota, semantic cache
                          ├─ Content safety, jailbreak detection
                          └─ App Insights (OpenTelemetry GenAI)
```

**Key properties:**
- **One gateway, three traffic types** (models, MCP, A2A) — uniform auth, observability, and policy.
- **One catalog** (API Center) — uniform discovery and governance.
- **Open protocols** (MCP + A2A) — works with non-Microsoft agents (Google ADK, LangGraph, custom).

---

## How CyberProbe Maps to This Model

This repository already implements the south-bound (MCP) half of the pattern:

| CyberProbe Component | Role | Today | Gateway-Aligned Future |
|---|---|---|---|
| `.vscode/mcp.json` (Sentinel, Defender XDR Triage, Graph, Azure, Learn, Sentinel Graph) | MCP servers (tool access) | Local MCP transport | Front with APIM AI Gateway → remote MCP for enterprise consumers |
| `mcp-apps/sentinel-exposure-server/` | Custom MCP server | Code-first MCP | Publish as APIM-managed MCP server |
| `.github/skills/*` (incident-investigation, threat-enrichment, exposure-management, defender-response, etc.) | Specialist "agents" composed by the host LLM | Prompt-chained skills | Wrap each as an A2A-exposed agent (or Foundry connected agent / Security Copilot agent) so a supervisor can fan out and merge |
| `security-copilot/` | Native Microsoft security agents | Composable Security Copilot agents | Already supports agent-to-agent within Security Copilot; expose externally via A2A through APIM |

**Evolution path:**

1. **Today (works):** Skills as prompts + MCP for tools. The host LLM is the orchestrator.
2. **Next:** Wrap each skill as an A2A-exposed agent. A "triage supervisor" delegates to `incident-investigation`, `threat-enrichment`, `exposure-management` in parallel and merges results.
3. **Mature:** APIM AI Gateway fronts both MCP servers (south-bound) and A2A agents (east-west). API Center publishes the catalog. Foundry hosts agents.

---

## Caveats & Current Limitations

- **A2A support in APIM is preview.** Available only on **v2 SKUs** (Basic v2 / Standard v2 / Premium v2).
- **JSON-RPC only** for A2A today; other A2A transports are not yet mediated.
- **Deserialization of outgoing response bodies isn't supported** for A2A APIs.
- **AI Gateway in Foundry** is preview; advanced scenarios still require dropping into the APIM portal.
- **API Center dependency maps** for A2A agents are preview.

Always check the official docs for current GA status before designing for production.

---

## References

### Azure API Management — AI Gateway

- [AI gateway in Azure API Management (capabilities overview)](https://learn.microsoft.com/azure/api-management/genai-gateway-capabilities)
- [API gateways in Azure API Management (foundational concept)](https://learn.microsoft.com/azure/api-management/api-management-gateways-overview)
- [Import an A2A agent API (preview)](https://learn.microsoft.com/azure/api-management/agent-to-agent-api)
- [About MCP servers in Azure API Management](https://learn.microsoft.com/azure/api-management/mcp-server-overview)
- [Expose a REST API as an MCP server](https://learn.microsoft.com/azure/api-management/export-rest-mcp-server)
- [Expose and govern an existing MCP server](https://learn.microsoft.com/azure/api-management/expose-existing-mcp-server)
- [Import a Microsoft Foundry API](https://learn.microsoft.com/azure/api-management/azure-ai-foundry-api)
- [Import a language model API](https://learn.microsoft.com/azure/api-management/openai-compatible-llm-api)

### Azure API Center — Agent Registry

- [Agent registry in Azure API Center](https://learn.microsoft.com/azure/api-center/agent-to-agent-overview)
- [Register and manage agents in API Center](https://learn.microsoft.com/azure/api-center/register-manage-agents)
- [Track API resource dependencies](https://learn.microsoft.com/azure/api-center/track-resource-dependencies)

### Microsoft Foundry

- [Enable AI gateway in Microsoft Foundry](https://learn.microsoft.com/azure/ai-foundry/configuration/enable-ai-api-management-gateway-portal)
- [Register custom agents in Foundry](https://learn.microsoft.com/azure/foundry/control-plane/register-custom-agent)
- [Manage agents at scale in Foundry Control Plane](https://learn.microsoft.com/azure/foundry/control-plane/how-to-manage-agents)
- [Connect to an A2A agent endpoint from Foundry Agent Service (preview)](https://learn.microsoft.com/azure/foundry/agents/how-to/tools/agent-to-agent)
- [Govern tools with AI gateway](https://learn.microsoft.com/azure/ai-foundry/agents/how-to/tools/governance)
- [Connect an AI gateway to Foundry Agent Service](https://learn.microsoft.com/azure/foundry/agents/how-to/ai-gateway)

### Hybrid & Multi-Cloud (Self-Hosted Gateway)

- [Self-hosted gateway overview](https://learn.microsoft.com/azure/api-management/self-hosted-gateway-overview)
- [Deploy self-hosted gateway to Azure Kubernetes Service](https://learn.microsoft.com/azure/api-management/how-to-deploy-self-hosted-gateway-azure-kubernetes-service)
- [Deploy self-hosted gateway to Azure Arc-enabled Kubernetes](https://learn.microsoft.com/azure/api-management/how-to-deploy-self-hosted-gateway-azure-arc)
- [Build an Agent 365 agent on Google Cloud Run](https://learn.microsoft.com/microsoft-agent-365/developer/deploy-agent-gcp)

### Open Protocols

- [Model Context Protocol (MCP)](https://modelcontextprotocol.io/)
- [Agent2Agent Protocol (A2A) specification](https://a2a-protocol.org/dev/specification/)
- [OpenTelemetry GenAI semantic conventions](https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/)
