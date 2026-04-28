---
title: ADO Permissions Output
description: Automated extraction and reporting of Azure DevOps security permissions by namespace, group, and user
author: Scott Kissel
ms.date: 2026-03-31
ms.topic: reference
---

## Overview

This toolset extracts Azure DevOps (ADO) security permissions across all security
namespaces for one or more projects in an organization. It produces structured JSON
output suitable for auditing, compliance reviews, and import into Excel or Power BI.

Designed for **unattended pipeline execution**, it authenticates via a Personal Access
Token (PAT), runs sequentially to avoid API throttling, and commits output directly
back to the repository for version-tracked audit history.

## Features

- Extracts permissions from 30+ ADO security namespaces (Build, Git Repositories,
  Release Management, Area Paths, Iterations, Service Endpoints, Dashboards, etc.)
- Resolves security tokens to human-readable names inline (project names, repo names,
  group names, query paths, etc.)
- Reports Allow, Deny, Effective Allow/Deny, and Inherited Allow/Deny separately
- Supports single-project or all-projects extraction via a parameter
- Configurable namespace selection through `ProjectDef.json`
- JSON output compatible with Excel (Power Query) and Power BI
- Structured logging with timestamped entries to a log file and pipeline console
- Automatic retry with back-off for HTTP 429 (throttle) and transient server errors
- Raw ACE/ACL data dump for debugging and deep analysis
- Optional group membership report with recursive AAD/Entra group resolution
- AAD group recursion uses only the ADO Graph API (no Entra module or managed identity required)

## Requirements

- **PowerShell 7+** (pwsh) — required for `-ResponseHeadersVariable` support
- **Azure DevOps PAT** with **Full Access** scope (simplest), or with these minimum scopes:
  - `vso.graph` — Graph API: read users, groups, memberships
  - `vso.security_manage` — Security: read namespaces, ACLs, ACEs
  - `vso.project` — Projects: read project list and properties
  - `vso.build` — Build: read definitions (token resolution)
  - `vso.release` — Release: read definitions (token resolution)
  - `vso.work` — Work Items: read area paths, iterations, queries
  - `vso.serviceendpoint` — Service Connections: read endpoints
  - `vso.dashboards` — Dashboards: read dashboard list
  - `vso.analytics` — Analytics: read views
  - `vso.memberentitlementmanagement` — User Entitlements: read user status and last access date (membership report)
- The PAT user must have sufficient permissions in the target organization. Project
  Collection Administrator (PCA) access ensures complete coverage, but the script
  handles permission errors gracefully for non-PCA accounts.
- For pipeline execution: the **Build Service** identity needs **Contribute** and
  **Create branch** permissions on the target repository (required for pushing output
  to the `output` branch)
- No Azure AD/Entra app registration, managed identity, or additional module
  installation is required. All API calls use PAT-based Basic authentication.

> [!NOTE]
> This toolset targets **Azure DevOps Services** (cloud). On-premises Azure DevOps
> Server (2020+) uses the same REST APIs but different URL formats
> (`https://server:port/collection/` vs `https://dev.azure.com/org/`). On-prem
> compatibility has not been tested.

## Repository Structure

```text
SecurityMain.ps1        # Entry point — orchestrates module loading, directory setup, and execution
SecurityHelper.psm1     # Core module — API calls, namespace permission extraction, JSON output
ProjectAndGroup.psm1    # Supporting module — directory setup, group membership reporting, credentials
ProjectDef.json         # Configuration — namespaces to extract, directory paths, output filenames
main.yml                # Azure Pipelines YAML — scheduled/manual pipeline definition
```

## Configuration

Edit `ProjectDef.json` to control behavior:

```json
{
    "HTTP_preFix"        : "https",
    "LogDirectory"       : "\\Logs\\",
    "DumpDirectory"      : "\\RawData\\",
    "SecurityDir"        : "\\Security\\",
    "GroupFileName"      : "Permissions.json",
    "MembershipFileName" : "Membership.json",
    "rawDataFile"        : "rawdump.txt",
    "Namespaces"         : ["All"]
}
```

| Field | Description |
| --- | --- |
| `GroupFileName` | Output filename for the permissions JSON |
| `MembershipFileName` | Output filename for the group membership JSON |
| `rawDataFile` | Filename for the raw ACE/ACL debug dump |
| `Namespaces` | Array of namespace names to extract, or `["All"]` for everything |

### Namespace Selection

Set `Namespaces` to `["All"]` to extract every active namespace, or specify individual
names to target specific areas:

```json
"Namespaces": ["Git Repositories", "Build", "ReleaseManagement", "ServiceEndpoints"]
```

## Usage

### Pipeline Execution (Recommended)

The included `main.yml` defines an Azure Pipelines definition that:

1. Runs `SecurityMain.ps1` with parameters from the "Run pipeline" UI
2. Optionally publishes output as a pipeline artifact
3. Commits the JSON output back to the repository for audit history
4. Tags each run for point-in-time retrieval (e.g., `run-20260331.1`)

#### Setup

1. Create a **Variable Group** named `ADOPermissions` in your Azure DevOps
   project's Library. Add a variable named `secretPAT` containing your PAT
   token and mark it as secret.
2. Create a pipeline pointing to `main.yml` in this repository.
3. Ensure the **Build Service** identity has **Contribute** and **Create branch**
   permissions on this repository (required for pushing to the `output` branch).
4. If the `output` branch has branch policies, add a policy exception for the
   Build Service identity.
5. The pipeline defaults to `vmImage: 'windows-latest'` (Microsoft-hosted agent).
   If your organization uses self-hosted agents or VMSS scale-set pools, update
   the `pool` section in `main.yml` to match your environment (e.g.,
   `pool: name: 'MyPool'`).

#### Pipeline Parameters

When running the pipeline manually, the "Run pipeline" dialog presents these options:

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `VSTSMasterAcct` | string | (required) | Azure DevOps organization name |
| `ProjectName` | string | (required) | Target project name |
| `AllProjects` | boolean | `false` | Extract all projects in the organization |
| `IncludeMembership` | boolean | `false` | Generate group membership report |
| `RecurseAADGroups` | boolean | `false` | Recursively resolve AAD group members |
| `OutputFormat` | string | `JSON` | Output format: `JSON`, `CSV`, or `Both` |
| `PublishArtifact` | boolean | `false` | Publish output as a pipeline artifact |
| `GitAuthorEmail` | string | `pipeline@noreply.dev.azure.com` | Email used for git commits of output files |

The PAT is stored securely in the `ADOPermissions` variable group and is not
exposed as a parameter.

### Local / Manual Execution

```powershell
./SecurityMain.ps1 `
    -PAT "<your-pat-token>" `
    -VSTSMasterAcct "yourorg" `
    -projectName "YourProject" `
    -allProjects "False" `
    -DirRoot "C:\ADOSecurity" `
    -IncludeMembership "True" `
    -RecurseAADGroups "True" `
    -OutputFormat "Both"
```

## Output

### Permissions JSON

The primary output is a JSON file per project at:

```text
<DirRoot>\Security\<ProjectName>_<date>_Permissions.json
```

Each entry in the JSON array represents a single permission assignment:

```json
{
    "Namespace": "Git Repositories",
    "Project": "MyProject",
    "Object": "my-repo",
    "Type": "Group",
    "UserGroupName": "Contributors",
    "Description": "Members of this group can add, modify, and delete items within the team project.",
    "PermissionType": "Allow",
    "Permission": "Contribute",
    "Bit": 4,
    "PermissionName": "GenericContribute",
    "DecodedValue": "100",
    "RawData": 4,
    "InheritedFrom": ""
}
```

| Field | Description |
| --- | --- |
| `Namespace` | ADO security namespace (e.g., `Git Repositories`, `Build`, `CSS`) |
| `Project` | Project name |
| `Object` | The specific resource (repo name, build definition, area path, etc.) |
| `Type` | `Group`, `Team`, `User`, or `AAD Group` |
| `UserGroupName` | Name of the group or user |
| `Description` | Group description |
| `PermissionType` | `Allow`, `Deny`, `Allow(Effective)`, `Allow(Inherited)`, `Deny(Effective)`, `Deny(Inherited)` |
| `Permission` | Human-readable permission name |
| `Bit` | Numeric bit value of the permission |
| `PermissionName` | Internal permission name |
| `DecodedValue` | Binary representation of the permission bitmask |
| `RawData` | Raw numeric value from the API |
| `InheritedFrom` | Source of inherited permission (if applicable) |

### Raw Data Dump

Debug-level ACE/ACL data is written per group per namespace at:

```text
<DirRoot>\RawData\<ProjectName>_<GroupName>_<Namespace>_<date>_rawdump.txt
```

### Membership JSON

When `-IncludeMembership "True"` is specified, a separate membership report is generated at:

```text
<DirRoot>\Security\<ProjectName>_<date>_Membership.json
```

Each entry represents a membership relationship for a project group. The report
includes both directions: who belongs to each group (**Member**) and what parent
groups each group belongs to (**Member-Of**).

```json
{
    "ProjectName": "MyProject",
    "GroupName": "[MyProject]\\Contributors",
    "GroupType": "Group",
    "GroupDescription": "Members of this group can add, modify, and delete items within the team project.",
    "Relationship": "Member",
    "MemberType": "User",
    "DisplayName": "Jane Doe",
    "MailAddress": "jane@example.com",
    "PrincipalName": "jane@example.com",
    "Origin": "aad",
    "Status": "active",
    "LastAccessedDate": "2026-03-15 14:30:00 UTC"
}
```

| Field | Description |
| --- | --- |
| `ProjectName` | Project the group belongs to |
| `GroupName` | Full principal name of the source group |
| `GroupType` | Whether the source group is a `Team` or `Group` |
| `GroupDescription` | Built-in description of the source group |
| `Relationship` | `Member` (entity is in the group) or `Member-Of` (group belongs to a parent) |
| `MemberType` | `User`, `Group`, or `Team` |
| `DisplayName` | Display name of the related entity |
| `MailAddress` | Email address |
| `PrincipalName` | UPN or group principal name |
| `Origin` | Identity origin (`aad`, `vsts`, `msa`, `ad`, etc.) |
| `ResolvedVia` | How the member was discovered: `"ADO Membership API"` (standard Graph Memberships endpoint) or `"Hierarchy Group Expansion"` (HierarchyQuery for Entra group members). Members resolved via Hierarchy Group Expansion appear in the ADO UI through Entra group nesting and may include disabled or deleted Entra accounts. |
| `Status` | User entitlement status (`active`, `disabled`, `deleted`, etc.). Null for non-user entries and for users with no ADO entitlement (e.g., disabled Entra accounts visible only through group expansion). |
| `LastAccessedDate` | When the user last accessed the organization. Null for non-user entries and for users without an ADO entitlement. |

#### Interpreting Membership Status

The combination of `ResolvedVia`, `Status`, and `LastAccessedDate` tells the full
story of a user's access state:

| `ResolvedVia` | `Status` | `LastAccessedDate` | Meaning |
| --- | --- | --- | --- |
| ADO Membership API | `active` | Recent date | Active user, using ADO |
| ADO Membership API | `active` | Null or very old | Has access, never logged in |
| ADO Membership API | `disabled` | Any | Admin disabled their ADO access |
| ADO Membership API | Null | Null | ADO identity exists but entitlement removed |
| Hierarchy Group Expansion | `active` | Recent date | Active user, also in an Entra group |
| Hierarchy Group Expansion | Null | Null | Ghost member — visible in ADO UI via Entra group but has no ADO entitlement |

When `-RecurseAADGroups "True"` is also specified, any AAD/Entra groups nested
within ADO groups are recursively resolved to their individual members. This
uses only the ADO Graph API and requires no additional Entra modules or
managed identity configuration.

> [!NOTE]
> When `-RecurseAADGroups` is enabled, AAD/Entra group members are resolved
> using the ADO Contribution HierarchyQuery API, which returns the real Entra
> group membership including users whose accounts have been disabled or deleted
> in Entra ID. The `Status` and `LastAccessedDate` fields from the User
> Entitlements API help identify these inactive accounts. Users not found in
> the entitlements data will have null `Status` values.

### Log File

Structured, timestamped log entries are written to:

```text
<DirRoot>\Logs\SecurityHelper_<date>.log
```

Log entries also appear in the pipeline console output for real-time monitoring.

## Importing Output

### Power BI

1. Open Power BI Desktop
2. **Get Data** > **JSON**
3. Select the `Permissions.json` file
4. The data loads as a table ready for filtering, pivoting, and visualization

### Excel

1. Open Excel
2. **Data** > **Get Data** > **From File** > **From JSON**
3. Select the `Permissions.json` file
4. Power Query loads the data as a structured table

Alternatively, use `-OutputFormat CSV` or `-OutputFormat Both` to produce CSV
files directly importable via **Data** > **From Text/CSV** without Power Query.

## Architecture Notes

### API Throttling Protection

All Azure DevOps REST API calls route through `Invoke-AdoRestMethod`, which provides:

- Automatic retry on HTTP 429 with `Retry-After` header respect
- Exponential back-off on transient errors (500, 502, 503, 504)
- Configurable retry count (default: 3 attempts)
- All retries are logged with timestamps and URIs

Sequential execution avoids the 429 penalty box entirely for most orgs. The retry
logic is a safety net, not the primary throttle strategy.

### Token-to-Name Resolution

Permission tokens (GUIDs, paths, namespace-specific formats) are resolved to
human-readable names inline during extraction. This means:

- Output is immediately readable without post-processing
- Pipeline logs show real names as progress happens
- Each namespace has dedicated token-matching logic in the `Get-PermissionsByNamespace`
  switch statement

### Supported Security Namespaces

The following namespaces are actively extracted and token-matched:

`AuditLog`, `AccountAdminSecurity`, `Analytics`, `AnalyticsViews`, `Build`,
`BuildAdministration`, `BoardsExternalIntegration`, `BlobStoreBlobPrivileges`,
`Collection`, `CSS` (Area Paths), `DashboardsPrivileges`, `Discussion Threads`,
`DistributedTask`, `Environment`, `EventSubscriber`, `Git Repositories`, `Identity`,
`Iteration`, `Library`, `MetaTask`, `Plan`, `Process`, `Project`,
`ReleaseManagement`, `ServiceEndpoints`, `ServiceHooks`, `Server`, `Tagging`,
`VersionControlItems`, `VersionControlPrivileges`, `WorkItemQueryFolders`,
`WorkItemTrackingAdministration`, `Workspaces`

## License

[MIT License](LICENSE)

## Known Limitations

- **PowerShell 7+ required.** Windows PowerShell 5.x is not supported due to
  `-ResponseHeadersVariable` usage in `Invoke-RestMethod`.
- **PAT authentication only.** OAuth, Managed Identity, and Entra token-based
  authentication are not supported. The PAT must be manually rotated before
  expiration.
- **Service Principal descriptors** in permission ACEs are passed through as
  raw descriptors. The Azure DevOps Graph API for service principals
  (`/_apis/graph/serviceprincipals`) is available but not yet integrated into
  the permissions report. Membership report entries resolved via subject lookup
  will show service principals by display name where available.
- **HierarchyQuery API is undocumented.** The AAD group recursion feature uses
  the ADO Contribution HierarchyQuery API (`ms.vss-admin-web.org-admin-group-members-data-provider`).
  This is the same API the ADO portal uses but is not part of the public REST
  API contract and may change without notice.
- **Azure DevOps Server (on-premises)** has not been tested. The URL format
  differs (`https://server:port/collection/` vs `https://dev.azure.com/org/`)
  and some APIs may behave differently.
- **Sequential execution.** Namespace processing is sequential to respect API
  throttle limits. Large organizations with many projects may experience longer
  run times.
- **CSV output** uses `Export-Csv` with flat column layout. Nested JSON
  structures (if any) will be serialized as strings in CSV cells.

## Acknowledgments

Original demonstration scripts by **Arthur A. Garcia**
([DevOpsApi](https://github.com/artgarciams/DevOpsApi)) provided the foundational
patterns for descriptor decoding, bitmask permission resolution, and the overall
architecture concept for namespace-based security extraction. Rearchitected and
productionalized by **Scott Kissel** with structured logging, retry logic, JSON output,
AAD group recursion, and comprehensive namespace token resolution.
