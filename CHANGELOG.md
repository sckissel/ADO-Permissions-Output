---
title: Changelog
description: Version history and notable changes for ADO Permissions Output
---

## v1.1.3 (2026-05-11)

### Fixed

* **All permission entries silently dropped on PowerShell 7 Linux (regression
  from v1.1.2).** The v1.1.2 perf refactor replaced an O(N) `Where-Object`
  scan over `$ns.actions` with an `$nsActionsByBit` hashtable lookup. The
  bit-decode call sites were updated to cast `[int][Math]::Pow(...)` so the
  lookup-side type matched, but the insertion side
  (`$nsActionsByBit[$act.bit] = $act`) was left untyped. On Windows
  PowerShell the JSON deserializer returned both bits as `[Int32]` and the
  lookup worked. On PowerShell 7 (Linux container) `System.Text.Json`
  deserializes integer JSON values as `[Int64]`, and `Hashtable.Equals()`
  does not coerce `Int32` vs `Int64` with the same numeric value, so every
  `$nsActionsByBit[$raise]` lookup returned `$null` and every Allow / Deny
  / Effective / Inherited bit was silently filtered out. Result: empty
  permissions output for ~36 hours of production runs with no error and no
  warning. Insertion now casts: `$nsActionsByBit[[int]$act.bit] = $act`.
  Affects `Get-PermissionsByNamespace` in `SecurityHelper.psm1`.

* **Empty permissions output produced no file and no warning.** When the
  per-project permissions list was empty (which v1.1.2 silently caused on
  every project), `Get-SecuritybyGroupByNamespace` skipped the file write
  entirely. The pipeline therefore finished successfully with neither a
  CSV nor a Warning indicating that nothing was extracted. Now always
  writes the output file even when empty and emits a Warning naming the
  project so the operator can correlate against the run.

* **Single unresolved identity descriptor terminated the entire run.** The
  identity-resolution else branch in `Get-PermissionsByNamespace` used
  `break "ERROR OCCURRED!"` -- a labeled `break` with no matching enclosing
  label. PowerShell unwinds the stack searching for the label and, finding
  none, terminates the enclosing runspace. A single AAD guest, deleted user,
  or otherwise unresolvable descriptor would silently kill the namespace
  loop for that project (and on PS 7, the script). Replaced with `return`
  from the `ForEach-Object` scriptblock so only the failing ACE is skipped.

### Known Issues

* **`Get-GroupMembershipReport` is the dominant runtime cost.** Customer
  data point: 127 projects took ~3 hours for permissions extract and ~33
  hours for group membership extract. The membership extract makes 2
  baseline `graph/Memberships` GETs per group (down + up) plus per-unmatched-
  descriptor `subjectlookup` POSTs and (with `-recurseAADGroups True`)
  recursive `Contribution/HierarchyQuery` POSTs per nested AAD group. ADO
  graph endpoints throttle per-PAT, so naive `ForEach-Object -Parallel`
  will hit 429s and net little or no gain. Planned remediation in v1.1.4:
  batch `subjectlookup` POSTs (the API accepts an array of `lookupKeys`)
  and add cross-project membership / subject caches so org-level groups
  are resolved once per run instead of once per project.

## v1.1.2 (2026-05-07)

### Fixed

* **ACL prefetch failures were logged at Warning and silently produced empty
  reports.** When the per-namespace `accesscontrollists` REST call threw
  (transient throttling, auth expiry, etc.), the catch block in
  `Get-SecuritybyGroupByNamespace` cached `value=@()` and continued at
  Warning severity, so the pipeline finished green with permissions for that
  namespace missing across every project. Now logged at Error so the failure
  is unmistakable in pipeline output. Empty-cache behavior preserved so a
  single namespace failure does not abort the whole run. Caught by Copilot
  review on PR #5.

* **Identity-resolution failure branch was silently swallowed.** The
  `Get-PermissionsByNamespace` `Write-Host` shadow installed for
  `VerbosePermissionLogging=$false` (the default) also suppressed the
  error-path `Write-Host "Error : ..."` call in the identity-lookup else
  branch. The original line also used `+` concatenation that `Write-Host`
  does not honor, so the message was mangled even when verbose. Replaced
  with `Write-Log -Level 'Error'`, which bypasses the shadow via the
  fully-qualified `Microsoft.PowerShell.Utility\Write-Host` call inside
  `Write-Log`. Caught by Copilot review on PR #5.

* **Deny permission rows referenced wrong action bit.** The Deny decode loop in
  `Get-PermissionsByNamespace` (`SecurityHelper.psm1`) computed `$raise` from
  `$inhAllowplace` instead of `$Denyplace`, so Deny rows reported the action
  bit from a previously-iterated Allow loop rather than the current Deny bit
  position. Pre-existing latent bug. Surfaced by Copilot review on PR #5.
  Output for any namespace with non-zero `deny` will differ from prior runs.

* **Bit-decode hashtable lookup type mismatch.** The perf refactor below
  replaced `$ns.actions | Where-Object { $_.bit -eq $raise }` with an
  `$nsActionsByBit[$raise]` hashtable lookup. Hashtable keys deserialized
  from JSON via `ConvertFrom-Json` are `[Int64]`, but `[Math]::Pow` returns
  `[Double]`, and the hashtable indexer uses `.Equals()` which does not
  coerce types. Without the cast all 6 bit-decode loops would silently
  return `$null` and drop every permission entry. All 6 sites now use
  `$raise = [int][Math]::Pow(2, $place)`.

### Changed

* **Memory-pressure remediation for large orgs.** Several allocations in
  `SecurityHelper.psm1` were per-project or per-ACL when they could be
  per-run or lazily-cached. Reworked to keep the working set flat as the
  project count grows:
  - `$groupInfoByFullDescriptor` is now built once per run from
    `$allGroupInfo` and reused, instead of rebuilt per project.
  - `$aclCacheByNamespace` lazily fetches each namespace's ACL list once
    and reuses it across projects (validated safe: ACL list for a given
    namespace is org-scoped, not project-scoped).
  - `$svcUsersByFullDescriptor` is built per project from the project's
    `$allSvcUsers` and explicitly nulled along with `$allPermissions` and
    `$allSvcUsers` in a per-project GC sweep.
  - Inside `Get-PermissionsByNamespace`, `$ns.actions` is collapsed once
    into `$nsActionsByBit` and reused across all 6 bit-decode loops in
    place of repeated `Where-Object` scans, and `$matchedTokens` is now a
    `[HashSet[string]]` for O(1) membership tests.
  - Per-bit `Write-Host` calls are now gated behind a new
    `$script:VerbosePermissionLogging` flag (off by default) so high-volume
    runs do not spend CPU on host writes that are immediately discarded.

* **New `VerbosePermissionLogging` pipeline parameter.** `main.yml` exposes a
  boolean (default `false`) wired through `SecurityMain.ps1` to
  `Get-SecuritybyGroupByNamespace -VerboseLogging`. Documented in `README.md`.

## v1.1.1 (2026-04-29)

### Changed

* **List<T> conversion for user and group fetching.** `ProjectAndGroup.psm1`
  and `SecurityHelper.psm1` now accumulate users and groups into
  `System.Collections.Generic.List[object]` instead of array `+=` patterns,
  which were O(n^2) and held duplicate intermediate arrays in memory. Reduces
  peak working set on large orgs.
* **`main.yml` pipeline updates** to support the refactored modules.

### Fixed

* **Null `principalName` guard in `ProjectAndGroup.psm1`.** Service identities
  can return a null `principalName`; calling `.ToLower()` on it threw. Now
  null-checked before normalization.
* **`SecurityHelper.psm1` `AddRange` null guard** and removed an unnecessary
  `[object[]]` cast that copied the source list.

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
