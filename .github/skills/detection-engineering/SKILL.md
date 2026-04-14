---
name: detection-engineering
description: Convert community detection rules (Sigma YAML, YARA-L, Splunk SPL) to Microsoft Sentinel analytics rules and Defender XDR custom detections. Parse, map, convert, validate, and deploy detection rules using pySigma, GitHub Copilot, and KQL validation tools. Use for detection-as-code workflows, Sigma rule conversion, and analytic rule lifecycle management.
---

# Detection Engineering — Sigma to Sentinel Conversion Skill

This skill enables end-to-end conversion of community detection rules (primarily Sigma YAML) into production-ready Microsoft Sentinel Analytic Rules and Defender XDR Custom Detections. It combines automated conversion via pySigma with AI-assisted validation and optimization.

---

## Table of Contents

1. [When to Use This Skill](#when-to-use-this-skill)
2. [Prerequisites](#prerequisites)
3. [Core Workflow — 7 Phases](#core-workflow--7-phases)
4. [Phase 1: Ingest Rule](#phase-1-ingest-rule)
5. [Phase 2: Parse Sigma YAML](#phase-2-parse-sigma-yaml)
6. [Phase 3: Map Logsource to Sentinel Table](#phase-3-map-logsource-to-sentinel-table)
7. [Phase 4: Convert Detection Logic to KQL](#phase-4-convert-detection-logic-to-kql)
8. [Phase 5: Validate KQL](#phase-5-validate-kql)
9. [Phase 6: Package as Sentinel Analytic Rule](#phase-6-package-as-sentinel-analytic-rule)
10. [Phase 7: Deploy or Export](#phase-7-deploy-or-export)
11. [Sigma Logsource → Sentinel Table Mapping](#sigma-logsource--sentinel-table-mapping)
12. [Sigma Modifier → KQL Operator Mapping](#sigma-modifier--kql-operator-mapping)
13. [Detection Logic Translation Patterns](#detection-logic-translation-patterns)
14. [Entity Mapping Templates](#entity-mapping-templates)
15. [Batch Conversion Workflow](#batch-conversion-workflow)
16. [pySigma Automated Conversion](#pysigma-automated-conversion)
17. [Common Pitfalls & Troubleshooting](#common-pitfalls--troubleshooting)
18. [References](#references)

---

## When to Use This Skill

Use this skill when:
- ✅ User asks to "convert a Sigma rule" to Sentinel or KQL
- ✅ User wants to import community detections (SigmaHQ, Azure-Sentinel, Splunk)
- ✅ User asks to "create a detection rule" from a YAML file
- ✅ User provides a Sigma rule (YAML content, file path, or GitHub URL)
- ✅ User asks about detection-as-code workflows
- ✅ User wants to convert multiple Sigma rules in batch
- ✅ User wants to generate Sentinel Analytic Rules from threat descriptions
- ✅ User mentions "Sigma", "detection rule", "analytic rule", "community detection"

Do NOT use this skill when:
- ❌ User wants to write KQL from scratch (use `kql-query-builder`)
- ❌ User wants to execute existing queries (use `kql-sentinel-queries`)
- ❌ User is investigating a specific incident (use `incident-investigation`)
- ❌ User is looking for Microsoft Learn docs only (use `microsoft-learn-docs`)

---

## Prerequisites

1. **Python environment** (for pySigma): `.venv` activated in workspace
2. **pySigma packages** (optional but recommended):
   ```bash
   pip install pySigma pySigma-backend-kusto sigma-cli
   ```
3. **KQL Search MCP** (for schema validation): `validate_kql_query`, `get_table_schema`, `search_tables`
4. **Sentinel MCP** (for test execution): `mcp_data_explorat_query_lake`
5. **Environment config**: Read `enrichment/config.json` for `sentinel_workspace_id` and `tenant_id`

---

## Core Workflow — 7 Phases

```
┌─────────────────────────────────────────────────────────────────────┐
│                    DETECTION ENGINEERING WORKFLOW                     │
├──────┬──────────────────────────────────────────────────────────────┤
│  1   │ INGEST — Accept Sigma YAML (file, URL, pasted, SigmaHQ ID)  │
│  2   │ PARSE — Extract logsource, detection, MITRE tags, metadata   │
│  3   │ MAP — Translate logsource → Sentinel table + field names     │
│  4   │ CONVERT — Translate detection logic → KQL query              │
│  5   │ VALIDATE — Schema-check KQL, test-execute with | take 0     │
│  6   │ PACKAGE — Wrap in Sentinel Analytic Rule (YAML/ARM/JSON)     │
│  7   │ DEPLOY — Push to Sentinel, export for CI/CD, or save local  │
└──────┴──────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Ingest Rule

Accept Sigma rules from multiple sources:

| Source | How to Ingest |
|--------|---------------|
| Local file (`.yml`) | `read_file` — read YAML content directly |
| GitHub URL | `fetch_webpage` — fetch raw YAML from GitHub |
| SigmaHQ rule path | Construct URL: `https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/<path>` |
| Pasted YAML | User pastes content directly in chat |
| SigmaHQ rule ID | Search `https://github.com/SigmaHQ/sigma` for the rule by title or ID |
| Splunk SPL | Parse SPL → extract fields/logic → map to Sigma structure → proceed to Phase 3 |

**Example — fetch a SigmaHQ rule:**
```
User: "Convert the Sigma rule for T1078.004 — Cloud Account brute force"
→ Search SigmaHQ repo: https://github.com/SigmaHQ/sigma/tree/master/rules/cloud/azure/
→ Fetch raw YAML content
→ Proceed to Phase 2
```

---

## Phase 2: Parse Sigma YAML

Extract these key sections from the Sigma rule:

```yaml
# Example Sigma Rule Structure
title: Azure AD Sign-in Brute Force
id: a]b2c3d4-e5f6-...
status: test|stable|experimental
description: Detects brute force sign-in attempts
references:
  - https://attack.mitre.org/techniques/T1078/004/
author: CommunityContributor
date: 2025/01/15
tags:
  - attack.initial_access
  - attack.t1078.004
logsource:                         # ← CRITICAL: maps to Sentinel table
  product: azure
  service: signinlogs
detection:                         # ← CRITICAL: maps to KQL logic
  selection:
    ResultType: '50126'
  filter_success:
    ResultType: '0'
  condition: selection and not filter_success
  timeframe: 5m                    # ← temporal window
fields:                            # ← projected columns
  - UserPrincipalName
  - IPAddress
  - ResultType
falsepositives:
  - Legitimate password resets
level: medium                      # ← maps to Sentinel severity
```

**Key extractions:**

| Sigma Field | Used In | Sentinel Mapping |
|-------------|---------|------------------|
| `logsource.product` + `logsource.service` | Phase 3 | → Sentinel table name |
| `detection.selection.*` | Phase 4 | → `where` clauses |
| `detection.condition` | Phase 4 | → KQL boolean logic |
| `detection.timeframe` | Phase 4 | → `bin()` or `summarize` window |
| `tags` (attack.*) | Phase 6 | → MITRE ATT&CK tactics/techniques |
| `level` | Phase 6 | → Sentinel severity |
| `fields` | Phase 4 | → `project` columns |
| `title`, `description`, `id` | Phase 6 | → Rule metadata |

---

## Phase 3: Map Logsource to Sentinel Table

This is the most error-prone phase. Use the mapping table below, then ALWAYS verify with `get_table_schema` from KQL Search MCP.

### Sigma Logsource → Sentinel Table Mapping

#### Windows Event Logs

| Sigma Logsource (`product`/`category`/`service`) | Sentinel Table | Notes |
|--------------------------------------------------|----------------|-------|
| `windows` / `process_creation` | `SecurityEvent` (EventID 4688) or `SysmonEvent` (EventID 1) or `DeviceProcessEvents` | SecurityEvent = native Windows audit; Sysmon = richer; DeviceProcessEvents = MDE |
| `windows` / `file_event` | `DeviceFileEvents` or `SysmonEvent` (EventID 11) | MDE-onboarded → DeviceFileEvents |
| `windows` / `network_connection` | `DeviceNetworkEvents` or `SysmonEvent` (EventID 3) | MDE-onboarded → DeviceNetworkEvents |
| `windows` / `registry_set`, `registry_add`, `registry_delete` | `DeviceRegistryEvents` or `SysmonEvent` (EventID 12/13/14) | MDE-onboarded → DeviceRegistryEvents |
| `windows` / `image_load` | `DeviceImageLoadEvents` or `SysmonEvent` (EventID 7) | DLL/module load events |
| `windows` / `dns_query` | `DeviceEvents` (ActionType == "DnsQueryResponse") or `SysmonEvent` (EventID 22) | |
| `windows` / `pipe_created` | `SysmonEvent` (EventID 17/18) | Named pipe creation/connection |
| `windows` / `ps_script` / `ps_module` | `DeviceEvents` (ActionType contains "PowerShell") | PowerShell script block / module logging |
| `windows` / — / `security` | `SecurityEvent` | Windows Security event log |
| `windows` / — / `system` | `Event` | Windows System event log |
| `windows` / — / `powershell` | `Event` (EventID 4103/4104) or `DeviceEvents` | Script block logging |
| `windows` / — / `sysmon` | `SysmonEvent` | Requires Sysmon data connector |
| `windows` / — / `windefend` | `DeviceEvents` (ActionType startswith "Antimalware") | Windows Defender events |
| `windows` / — / `bits-client` | `Event` (Source == "Microsoft-Windows-Bits-Client") | BITS transfer events |

#### Azure / Entra ID

| Sigma Logsource | Sentinel Table | Notes |
|-----------------|----------------|-------|
| `azure` / — / `signinlogs` | `SigninLogs` | Interactive sign-ins. Use `TimeGenerated` not `Timestamp`. |
| `azure` / — / `auditlogs` | `AuditLogs` | Entra ID audit events. `InitiatedBy` and `TargetResources` are dynamic — always `tostring()`. |
| `azure` / — / `azureactivity` | `AzureActivity` | Azure control-plane operations (ARM). |
| `azure` / — / `activitylogs` | `AuditLogs` | Alias — same as auditlogs. |
| `azure` / — / `riskdetection` | `AADUserRiskEvents` | Identity Protection risk detections. NOT `AADRiskySignIns` (doesn't exist in Sentinel). |

#### Microsoft 365

| Sigma Logsource | Sentinel Table | Notes |
|-----------------|----------------|-------|
| `m365` / — / `exchange` | `OfficeActivity` (OfficeWorkload == "Exchange") | Mailbox rules, mail operations |
| `m365` / — / `sharepoint` | `OfficeActivity` (OfficeWorkload == "SharePoint") | File access, sharing |
| `m365` / — / `teams` | `OfficeActivity` (OfficeWorkload == "MicrosoftTeams") | Teams events |
| `m365` / — / `threat_management` | `SecurityAlert` (ProviderName == "OATP") | Defender for Office 365 alerts |

#### Network / Firewall / Proxy

| Sigma Logsource | Sentinel Table | Notes |
|-----------------|----------------|-------|
| `linux` / `network_connection` | `Syslog` or `CommonSecurityLog` | Depends on data source |
| — / `firewall` | `CommonSecurityLog` | CEF-formatted firewall logs |
| — / `proxy` | `CommonSecurityLog` or custom `*_CL` | Web proxy logs |
| — / `dns` | `DnsEvents` or `DeviceEvents` | DNS query logs |
| — / `webserver` | `W3CIISLog` or `AppServiceHTTPLogs` | Web server access logs |

#### Linux

| Sigma Logsource | Sentinel Table | Notes |
|-----------------|----------------|-------|
| `linux` / `process_creation` | `Syslog` (Facility == "authpriv") or `DeviceProcessEvents` | MDE for Linux → DeviceProcessEvents |
| `linux` / — / `sshd` | `Syslog` (ProcessName == "sshd") | SSH authentication events |
| `linux` / — / `auth` | `Syslog` (Facility == "auth" or "authpriv") | Authentication events |
| `linux` / — / `syslog` | `Syslog` | Generic syslog |
| `linux` / — / `auditd` | `Syslog` (Facility == "kern") or `AuditLog_CL` | Linux audit daemon |

#### Cloud Apps

| Sigma Logsource | Sentinel Table | Notes |
|-----------------|----------------|-------|
| `gcp` / `gcp.audit` | `GCPAuditLogs_CL` or custom | Requires GCP data connector |
| `aws` / `cloudtrail` | `AWSCloudTrail` | Requires AWS data connector |

**⚠️ MANDATORY after mapping:** Verify the target table schema:
```
Call: get_table_schema({ table_name: "<mapped_table>" })
```
Confirm that the field names in the Sigma `detection` block match the actual Sentinel column names.

---

## Phase 4: Convert Detection Logic to KQL

### Sigma Modifier → KQL Operator Mapping

| Sigma Modifier | KQL Operator | Example (Sigma → KQL) |
|---------------|-------------|----------------------|
| (none / exact) | `==` or `=~` | `UserName: admin` → `UserName =~ "admin"` |
| `contains` | `has` or `contains` | `CommandLine\|contains: mimikatz` → `CommandLine has "mimikatz"` |
| `startswith` | `startswith` | `Image\|startswith: C:\Windows\Temp` → `Image startswith @"C:\Windows\Temp"` |
| `endswith` | `endswith` | `Image\|endswith: .exe` → `Image endswith ".exe"` |
| `re` | `matches regex` | `CommandLine\|re: '(?i)invoke-.*'` → `CommandLine matches regex @"(?i)invoke-.*"` |
| `base64` | `base64_decode_tostring()` | Decode base64 field, then match |
| `base64offset` | `base64_decode_tostring()` with offset handling | Complex — manual conversion needed |
| `cidr` | `ipv4_is_in_range()` | `SourceIP\|cidr: 10.0.0.0/8` → `ipv4_is_in_range(SourceIP, "10.0.0.0/8")` |
| `all` | All values must match (AND) | See detection logic patterns below |
| `windash` | Match both `-` and `/` flag variants | `CommandLine has "-enc" or CommandLine has "/enc"` |
| `wide` | UTF-16 matching | `base64_decode_tostring()` with UTF-16 decode |
| `utf8` | Default string handling | No special handling needed in KQL |
| `exists` | `isnotempty()` | `FieldName\|exists: true` → `isnotempty(FieldName)` |

### Detection Logic Translation Patterns

**Pattern 1: Simple selection**
```yaml
# Sigma
detection:
  selection:
    EventID: 4625
    LogonType: 10
  condition: selection
```
```kql
// KQL
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4625
| where LogonType == 10
```

**Pattern 2: Selection with list (OR within field)**
```yaml
# Sigma
detection:
  selection:
    EventID:
      - 4624
      - 4625
      - 4648
  condition: selection
```
```kql
// KQL
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID in (4624, 4625, 4648)
```

**Pattern 3: Selection with modifier list (OR with contains)**
```yaml
# Sigma
detection:
  selection:
    CommandLine|contains:
      - 'mimikatz'
      - 'sekurlsa'
      - 'kerberos::list'
  condition: selection
```
```kql
// KQL
DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any ("mimikatz", "sekurlsa", "kerberos::list")
```

**Pattern 4: Multiple selections with AND condition**
```yaml
# Sigma
detection:
  selection_process:
    Image|endswith: '\powershell.exe'
  selection_cmdline:
    CommandLine|contains:
      - '-enc'
      - '-encodedcommand'
  condition: selection_process and selection_cmdline
```
```kql
// KQL
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName endswith "powershell.exe"
| where ProcessCommandLine has_any ("-enc", "-encodedcommand")
```

**Pattern 5: Selection with filter (NOT)**
```yaml
# Sigma
detection:
  selection:
    EventID: 4688
    NewProcessName|endswith: '\cmd.exe'
  filter:
    ParentProcessName|endswith: '\explorer.exe'
  condition: selection and not filter
```
```kql
// KQL
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4688
| where NewProcessName endswith @"\cmd.exe"
| where not(ParentProcessName endswith @"\explorer.exe")
```

**Pattern 6: Selection with `|all` modifier (AND for list items)**
```yaml
# Sigma
detection:
  selection:
    CommandLine|contains|all:
      - 'net'
      - 'user'
      - '/add'
  condition: selection
```
```kql
// KQL — each value must be present (AND)
DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has "net"
    and ProcessCommandLine has "user"
    and ProcessCommandLine has "/add"
```

**Pattern 7: Aggregation condition (count, temporal)**
```yaml
# Sigma
detection:
  selection:
    EventID: 4625
  condition: selection | count(TargetUserName) by SourceIP > 10
  timeframe: 5m
```
```kql
// KQL
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4625
| summarize FailedAttempts = count(), TargetUsers = dcount(TargetUserName)
    by SourceIP = IpAddress, bin(TimeGenerated, 5m)
| where FailedAttempts > 10
```

**Pattern 8: Near temporal correlation**
```yaml
# Sigma
detection:
  selection1:
    EventID: 4624
    LogonType: 10
  selection2:
    EventID: 4688
    NewProcessName|endswith: '\cmd.exe'
  condition: selection1 | near selection2
  timeframe: 5m
```
```kql
// KQL — temporal join
let rdp_logons = SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4624 and LogonType == 10
| project RdpTime = TimeGenerated, TargetAccount, Computer;
let cmd_exec = SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4688 and NewProcessName endswith @"\cmd.exe"
| project CmdTime = TimeGenerated, Account, Computer;
rdp_logons
| join kind=inner cmd_exec on $left.Computer == $right.Computer
| where abs(datetime_diff('minute', CmdTime, RdpTime)) <= 5
| project RdpTime, CmdTime, TargetAccount, Computer
```

**Pattern 9: `1/all of selection*` (OR/AND across named selections)**
```yaml
# Sigma
detection:
  selection_cmd1:
    CommandLine|contains: 'whoami'
  selection_cmd2:
    CommandLine|contains: 'hostname'
  selection_cmd3:
    CommandLine|contains: 'ipconfig'
  condition: 1 of selection_cmd*  # any one matches (OR)
```
```kql
// KQL — 1 of (OR)
DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has "whoami"
    or ProcessCommandLine has "hostname"
    or ProcessCommandLine has "ipconfig"
```

```yaml
# If condition were: all of selection_cmd*  # all must match (AND)
```
```kql
// KQL — all of (AND across separate events, use summarize)
DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has "whoami"
    or ProcessCommandLine has "hostname"
    or ProcessCommandLine has "ipconfig"
| summarize CommandsFound = dcount(ProcessCommandLine) by DeviceName, bin(Timestamp, 5m)
| where CommandsFound >= 3
```

---

## Phase 5: Validate KQL

After generating KQL, validate before packaging.

### Step 1: Schema Validation

```
Call: validate_kql_query({ query: "<generated_kql>" })
```

If validation fails, check:
- ❌ Column name mismatch → Use `get_table_schema` to verify field names
- ❌ Operator mismatch → Check KQL operator mapping above
- ❌ Table not found → Check logsource mapping; may need Data Lake vs Advanced Hunting switch

### Step 2: Test Execution (zero-result dry run)

Run the query with `| take 0` to confirm it parses without errors:

```
Call: mcp_data_explorat_query_lake({
  query: "<generated_kql> | take 0",
  workspaceId: "<from config.json>"
})
```

If the table is Advanced Hunting only (e.g., `DeviceProcessEvents`), use:
```
Call: RunAdvancedHuntingQuery({
  query: "<generated_kql> | take 0"
})
```

### Step 3: Test with Real Data

Run with `| take 10` to verify the query returns expected shape:
```
Call: mcp_data_explorat_query_lake({
  query: "<generated_kql_with_reasonable_timerange> | take 10",
  workspaceId: "<from config.json>"
})
```

---

## Phase 6: Package as Sentinel Analytic Rule

### Severity Mapping

| Sigma Level | Sentinel Severity |
|-------------|------------------|
| `informational` | Informational |
| `low` | Low |
| `medium` | Medium |
| `high` | High |
| `critical` | High |

### MITRE Tag Mapping

| Sigma Tag Pattern | Sentinel Tactic | Sentinel Technique |
|-------------------|----------------|-------------------|
| `attack.initial_access` | InitialAccess | — |
| `attack.execution` | Execution | — |
| `attack.persistence` | Persistence | — |
| `attack.privilege_escalation` | PrivilegeEscalation | — |
| `attack.defense_evasion` | DefenseEvasion | — |
| `attack.credential_access` | CredentialAccess | — |
| `attack.discovery` | Discovery | — |
| `attack.lateral_movement` | LateralMovement | — |
| `attack.collection` | Collection | — |
| `attack.command_and_control` | CommandAndControl | — |
| `attack.exfiltration` | Exfiltration | — |
| `attack.impact` | Impact | — |
| `attack.t1078` | — | T1078 |
| `attack.t1078.004` | — | T1078.004 |

### Sentinel Analytic Rule YAML Template

```yaml
id: <generate-unique-guid>
name: "<sigma_title>"
description: |
  <sigma_description>
  
  Converted from Sigma rule: <sigma_id>
  Original author: <sigma_author>
  References: <sigma_references>
severity: <mapped_severity>
requiredDataConnectors:
  - connectorId: <connector_for_table>
    dataTypes:
      - <sentinel_table>
queryFrequency: PT1H            # Adjust based on sigma timeframe
queryPeriod: P1D                # Lookback window
triggerOperator: GreaterThan
triggerThreshold: 0
tactics:
  - <mapped_tactics>
relevantTechniques:
  - <mapped_techniques>
query: |
  <validated_kql_query>
entityMappings:
  <see Entity Mapping Templates below>
version: 1.0.0
kind: Scheduled
```

### ARM Template (for import/export)

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.SecurityInsights/alertRules",
      "apiVersion": "2024-01-01-preview",
      "name": "<rule-guid>",
      "kind": "Scheduled",
      "properties": {
        "displayName": "<sigma_title>",
        "description": "<sigma_description>\n\nConverted from Sigma rule: <sigma_id>",
        "severity": "<mapped_severity>",
        "enabled": true,
        "query": "<validated_kql_query>",
        "queryFrequency": "PT1H",
        "queryPeriod": "P1D",
        "triggerOperator": "GreaterThan",
        "triggerThreshold": 0,
        "suppressionDuration": "PT5H",
        "suppressionEnabled": false,
        "tactics": ["<mapped_tactics>"],
        "techniques": ["<mapped_techniques>"],
        "entityMappings": [
          {
            "entityType": "Account",
            "fieldMappings": [
              { "identifier": "FullName", "columnName": "UserPrincipalName" }
            ]
          },
          {
            "entityType": "IP",
            "fieldMappings": [
              { "identifier": "Address", "columnName": "IPAddress" }
            ]
          }
        ]
      }
    }
  ]
}
```

---

## Phase 7: Deploy or Export

| Method | When to Use | How |
|--------|-------------|-----|
| **Save to queries/ library** | Store for later use or review | Save `.kql` file to `queries/<domain>/` with standardized metadata header |
| **Export ARM JSON** | Cross-workspace deployment, CI/CD | Generate ARM template (see Phase 6), save to `reports/` or a deployment folder |
| **Sentinel REST API** | Direct deployment to workspace | `PUT` to `Microsoft.SecurityInsights/alertRules/{ruleId}` via `az rest` |
| **CI/CD pipeline** | Detection-as-code workflow | Push ARM/YAML to Git, trigger pipeline per [Deploy Custom Content from Repo](https://learn.microsoft.com/azure/sentinel/ci-cd) |
| **Content Hub (manual)** | One-off import | Use Azure Portal → Sentinel → Analytics → Import |

### Deploy via REST API

```powershell
$token = (az account get-access-token --resource https://management.azure.com --query accessToken -o tsv)
$subscriptionId = "<subscription-id>"
$resourceGroup = "<resource-group>"
$workspaceName = "<workspace-name>"
$ruleId = [guid]::NewGuid().ToString()

$body = Get-Content -Path "analytic_rule.json" -Raw

Invoke-RestMethod `
  -Uri "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/alertRules/$($ruleId)?api-version=2024-01-01-preview" `
  -Method PUT `
  -Headers @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' } `
  -Body $body
```

---

## Entity Mapping Templates

Use these entity mapping patterns based on the Sentinel table:

### SigninLogs / AuditLogs (Entra ID)

```yaml
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: UserPrincipalName
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPAddress
  - entityType: CloudApplication
    fieldMappings:
      - identifier: Name
        columnName: AppDisplayName
```

### SecurityEvent (Windows)

```yaml
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: TargetUserName
      - identifier: NTDomain
        columnName: TargetDomainName
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: Computer
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IpAddress
  - entityType: Process
    fieldMappings:
      - identifier: CommandLine
        columnName: CommandLine
```

### DeviceProcessEvents / DeviceNetworkEvents (MDE)

```yaml
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: DeviceName
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountName
      - identifier: NTDomain
        columnName: AccountDomain
  - entityType: Process
    fieldMappings:
      - identifier: CommandLine
        columnName: ProcessCommandLine
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: RemoteIP
```

### OfficeActivity (M365)

```yaml
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: UserId
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: ClientIP
```

---

## Batch Conversion Workflow

For converting multiple Sigma rules at once:

### Step 1: Identify Rules

Browse SigmaHQ by MITRE technique, log source category, or tag:
```
https://github.com/SigmaHQ/sigma/tree/master/rules/windows/process_creation/
https://github.com/SigmaHQ/sigma/tree/master/rules/cloud/azure/
```

### Step 2: Use pySigma for Bulk Conversion

See [pySigma Automated Conversion](#pysigma-automated-conversion) below.

### Step 3: Validate Each Output

For each converted rule, run through Phase 5 validation.

### Step 4: Package as ARM Template Array

Combine multiple rules into a single ARM deployment template for batch import.

---

## pySigma Automated Conversion

### Install

```bash
pip install pySigma pySigma-backend-kusto sigma-cli
```

### sigma-cli (Single Rule)

```bash
# Convert to Sentinel (ASIM-normalized)
sigma convert -t kusto -p sentinel_asim rule.yml

# Convert to Sentinel (default tables)
sigma convert -t kusto -p sentinel rule.yml

# Convert to Microsoft XDR (Advanced Hunting)
sigma convert -t kusto -p microsoft_xdr rule.yml

# Convert to Azure Monitor
sigma convert -t kusto -p azure_monitor rule.yml
```

### sigma-cli (Batch — Directory)

```bash
# Convert all rules in a directory
sigma convert -t kusto -p sentinel_asim rules/windows/process_creation/ --output converted_rules/

# Convert with specific pipeline
sigma convert -t kusto -p sentinel_asim -p sysmon rules/windows/sysmon/ --output converted_rules/
```

### Python Script (Programmatic)

```python
from sigma.rule import SigmaRule
from sigma.backends.kusto import KustoBackend
from sigma.pipelines.sentinel import sentinel_asim_pipeline
from sigma.collection import SigmaCollection
from pathlib import Path
import yaml

# Initialize backend with Sentinel ASIM pipeline
backend = KustoBackend(processing_pipeline=sentinel_asim_pipeline())

# Single rule conversion
rule_yaml = Path("rule.yml").read_text()
rule = SigmaRule.from_yaml(rule_yaml)
kql_queries = backend.convert_rule(rule)
print(kql_queries[0])

# Batch conversion from directory
rules_dir = Path("rules/windows/process_creation/")
for rule_file in rules_dir.glob("*.yml"):
    try:
        rule = SigmaRule.from_yaml(rule_file.read_text())
        kql = backend.convert_rule(rule)
        print(f"✅ {rule.title}: {len(kql)} queries generated")
        # Save converted KQL
        output = rules_dir.parent / "converted" / f"{rule_file.stem}.kql"
        output.write_text(kql[0])
    except Exception as e:
        print(f"❌ {rule_file.name}: {e}")
```

### SigmAIQ (LLM-Enhanced)

```python
from sigmaiq import SigmAIQBackend

# Convert with Microsoft Sentinel backend
backend = SigmAIQBackend(target="microsoft_sentinel_asim")
result = backend.translate(rule_yaml)
```

---

## Common Pitfalls & Troubleshooting

| Pitfall | Symptom | Fix |
|---------|---------|-----|
| **Wrong table** | Query returns 0 results | Verify logsource mapping; check if data connector is enabled |
| **Field name mismatch** | `SemanticError: column not found` | Use `get_table_schema` to verify exact column names. Sigma `Image` → MDE `FileName` or `FolderPath` |
| **Timestamp field wrong** | Query fails or returns all data | Data Lake: `TimeGenerated`. Advanced Hunting: `Timestamp`. Never mix. |
| **`contains` vs `has`** | Unexpected matches or misses | `has` is word-boundary (preferred for performance). `contains` is substring. Use `has` for single tokens, `contains` for paths/substrings. |
| **`|all` not handled** | Detection misses multi-keyword rules | Must convert to explicit AND chain — `has X and has Y and has Z` |
| **`|windash` ignored** | Misses `/enc` variant of `-enc` | Explicitly match both: `has "-enc" or has "/enc"` |
| **Case sensitivity** | Sigma is case-insensitive by default | Use `=~` for case-insensitive equality; `has` is already case-insensitive |
| **Dynamic fields in SigninLogs** | `SemanticError` on `.property` access | Always wrap: `tostring(parse_json(DeviceDetail).operatingSystem)` |
| **`near` temporal correlation** | No direct KQL equivalent | Use `join` with `datetime_diff()` filter (see Pattern 8) |
| **Aggregation timeframe** | Missing `bin()` in KQL | Sigma `timeframe: 5m` → KQL `bin(TimeGenerated, 5m)` in `summarize` |
| **SecurityAlert.Status** | Filtering by status returns wrong results | Status is immutable. Join with SecurityIncident for real status. See copilot-instructions.md. |
| **pySigma field mapping incomplete** | Output KQL has Sigma field names | pySigma pipelines handle most mappings, but may miss custom fields. Always review output. |
| **`1 of selection*`** | Logic error in OR/AND grouping | `1 of` = OR across selections. `all of` = AND (requires summarize for cross-event). |

---

## References

- [SigmaHQ Rule Repository](https://github.com/SigmaHQ/sigma) — 3,000+ community detection rules
- [Sigma Specification](https://github.com/SigmaHQ/sigma-specification) — Formal YAML format reference
- [pySigma](https://github.com/SigmaHQ/pySigma) — Python conversion library
- [pySigma Kusto Backend](https://pypi.org/project/pySigma-backend-kusto/) — Sentinel/XDR/Azure Monitor output
- [sigconverter.io](https://sigconverter.io/) — Web GUI converter
- [SigmAIQ](https://github.com/AttackIQ/SigmAIQ) — LLM-enhanced pySigma wrapper
- [Create Scheduled Analytics Rule](https://learn.microsoft.com/azure/sentinel/create-analytics-rules) — Sentinel rule authoring
- [Custom Detections (Unified)](https://learn.microsoft.com/defender-xdr/custom-detections-overview) — Defender XDR custom detections
- [Import/Export Analytics Rules (ARM)](https://learn.microsoft.com/azure/sentinel/import-export-analytics-rules) — ARM template import/export
- [ASIM Normalization Overview](https://learn.microsoft.com/azure/sentinel/normalization) — Vendor-agnostic detection schemas
- [Deploy Custom Content from Repo](https://learn.microsoft.com/azure/sentinel/ci-cd) — Detection-as-code CI/CD
- [Azure Sentinel Community (GitHub)](https://github.com/Azure/Azure-Sentinel) — Community detections, hunting queries
- Full reference list: See `references/REFERENCES.md` Section 13 — Detection Engineering
