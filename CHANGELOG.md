---
title: Changelog
description: Version history and notable changes for ADO Permissions Output
---

## v1.1.0 (2026-04-27)

### Fixed

* **Build Service GUID display name resolution.** Some Azure DevOps
  organizations return the project GUID (or `D<guid>`) as `displayName` for
  project-scoped Build Service identities instead of the friendly
  `"<Project> Build Service (<Org>)"` form. The previous code relied on
  `displayName` being correct, which was not reliable across all orgs and API
  versions. Resolution now uses the `domain` and `principalName` fields from
  the `graph/users` response to look up the project name in an org-wide
  project list, which is always reliable. Affects both `SecurityHelper.psm1`
  (permissions report) and `ProjectAndGroup.psm1` (membership report) across
  all code paths: pre-cached `allSvcUsers`, fallback `ServiceIdentity`
  handler, and `Resolve-ServiceIdentityName`.

* **Null tokenData crash on 404 namespaces.** When `Get-TokenData` returned an
  empty array for CSS, Iteration, or WorkItemQueryFolders namespaces (e.g.,
  project with no areas), PowerShell unrolled `@()` to `$null` at the call
  site, crashing the mandatory `-tokenData` parameter binding on
  `Get-PermissionsByNamespace`. Added `if ($global:all*.Count -lt 1) { return "N/A" }`
  guards in `Get-TokenData` and a defensive `if ($null -eq $tokenDetails) { $tokenDetails = "N/A" }`
  at the call site.

### Changed

* **Output branch strategy.** Pipeline now pushes output to an orphan `output`
  branch instead of force-pushing to the source branch. Prior runs are preserved
  as commit history on the output branch. The Build Service identity now requires
  **Create branch** permission in addition to **Contribute** on the repository.

* **Org-wide project lookup.** Both modules now build an org-wide
  `$allProjectIdToName` / `$projectIdToName` hashtable from all projects in the
  organization (not just the requested project filter). This enables correct
  Build Service name resolution for cross-project identities.

* `ProjectAndGroup.psm1` `Resolve-ServiceIdentityName` simplified: no longer
  calls the identity API. Uses in-memory graph user lookup and displayName GUID
  regex as fallback.

## v1.0.2 (2026-04-24)

### Fixed

* Support comma-separated project names in the `-projectName` / `ProjectName`
  parameter. Previously, supplying a value such as `"corp-ado-001, management-ado-001"`
  produced empty `Security/` and `RawData/` folders because the filter used `-eq`
  against the full string. The filter now splits on commas, trims whitespace, and
  matches any project in the resulting list. Affects `Get-SecuritybyGroupByNamespace`
  in `SecurityHelper.psm1` and `Get-GroupMembershipReport` in `ProjectAndGroup.psm1`.

## v1.0.1 (2026-04-24)

### Fixed

* URL-encode continuation tokens in paginated API calls to prevent HTTP 500 errors
  when tokens contain reserved characters such as `#` (CosmosDB cursors). Affects
  users, groups, and user-entitlement pagination in `ProjectAndGroup.psm1` and
  projects and users pagination in `SecurityHelper.psm1`.
* Pipeline parameter `ProjectName` in `main.yml` now has a default value (single
  space) so the queue-time form accepts submissions when `AllProjects` is selected.
  Updated display name clarifies that the field may be left blank when extracting
  all projects.

## v1.0.0 (2026-04-02)

Initial public release.

### Features

* Permissions extraction across 30+ ADO security namespaces
* Inline token-to-friendly-name resolution (projects, repos, queries, dashboards,
  iterations, area paths, service endpoints, build/release definitions, plans)
* Reports Allow, Deny, Effective Allow/Deny, and Inherited Allow/Deny separately
* Per-project output files for both permissions and membership reports
* Optional group membership report with member and member-of relationships
* AAD/Entra group recursion via HierarchyQuery API (includes disabled/deleted users)
* User entitlement status and last-accessed date on membership entries
* `ResolvedVia` field distinguishing ADO Membership API vs Hierarchy Group Expansion resolution paths
* CSV output option alongside JSON (`-OutputFormat CSV` or `Both`)
* Structured logging with timestamped entries to console and log file
* Automatic retry with exponential back-off for HTTP 429 and transient errors
* Paginated teams fetch supporting orgs with more than 1,000 teams
* Azure Pipelines YAML with parameterized execution and artifact publishing
* Pipeline commits output back to repository with run tags for audit history
* Run summary with file counts and sizes at completion
* Configurable namespace selection via `ProjectDef.json`

### Security

* PAT stored in ADO Variable Group (secret), not in source
* Pipeline commit author email configurable via parameter (no personal email)
* Read-only tool: no permissions, groups, or resources are modified
