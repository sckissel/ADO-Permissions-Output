---
title: Security Policy
description: Security vulnerability reporting guidance for ADO Permissions Output
---

## Reporting Security Vulnerabilities

If you discover a security vulnerability in this project, please report it
responsibly by opening a GitHub Issue with the tag `security`.

Do not include PAT tokens, credentials, or organization-specific data in
public issues or pull requests.

## Security Considerations

* This tool requires a Personal Access Token (PAT) with elevated read permissions.
  Store PATs securely in Azure DevOps Variable Groups marked as secret.
* The tool is read-only. It does not modify any permissions, groups, or resources
  in the target ADO organization.
* Output files may contain user email addresses, group names, and permission
  details. Treat output as sensitive and restrict access appropriately.
* When running in a pipeline, ensure the repository access is restricted to
  authorized personnel since output is committed back to the repo.
