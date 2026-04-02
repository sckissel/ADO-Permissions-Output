---
title: Contributing to ADO Permissions Output
description: Guidelines for contributing to the ADO Permissions Output project
---

## Contributing

Thank you for your interest in this project. Contributions are welcome via issues
and pull requests.

## How to Contribute

* **Report bugs** by opening a GitHub Issue with reproduction steps and pipeline log
  excerpts
* **Request features** by opening an Issue describing the use case and expected
  behavior
* **Submit fixes** via Pull Request against the `main` branch

## Running Locally

```powershell
./SecurityMain.ps1 `
    -PAT "<your-pat-token>" `
    -VSTSMasterAcct "yourorg" `
    -projectName "YourProject" `
    -allProjects "False" `
    -DirRoot "C:\ADOSecurity" `
    -IncludeMembership "True" `
    -RecurseAADGroups "True"
```

Requires PowerShell 7+ (pwsh) and an Azure DevOps PAT with the scopes listed in
the README.

## Coding Conventions

* PowerShell functions use PascalCase
* All REST calls go through `Invoke-AdoRestMethod` (retry/throttle wrapper)
* Log messages use `Write-Log` with `Info`, `Warning`, or `Error` level
* Output structures are `[PSCustomObject]` arrays serialized to JSON

## Pull Request Process

1. Fork the repository
2. Create a feature branch
3. Test with at least one ADO organization (single-project and all-projects modes)
4. Submit a PR with a description of the change and any relevant pipeline output
