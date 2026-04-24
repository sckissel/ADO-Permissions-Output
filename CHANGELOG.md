---
title: Changelog
description: Version history and notable changes for ADO Permissions Output
---

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
