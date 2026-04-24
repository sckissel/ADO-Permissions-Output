#
# FileName : ProjectAndGroup.psm1
# Date     : 02/09/2018
# Purpose  : This module provides functions for directory setup, group/user membership reporting,
#            and credential handling for Azure DevOps organizations.
#
# last update 03/31/2026


function Set-DirectoryStructure()
{
    # this function will setup the directory structure for files that this powershell script will need.
    Param(
        [Parameter(Mandatory = $true)]
        $userParams, $dirRoot
    )
 
    # make sure directory structure exists
    if(!(test-path  $dirRoot))
    {
        New-Item -ItemType directory -Path $dirRoot
    }

    if(!(test-path  ($dirRoot + $userParams.SecurityDir) ))
    {
        New-Item -ItemType directory -Path ($dirRoot + $userParams.SecurityDir)
    }

    if(!(test-path  ($dirRoot + $userParams.DumpDirectory) ))
    {
        New-Item -ItemType directory -Path ($dirRoot + $userParams.DumpDirectory)
    }
    
    if(!(test-path  ($dirRoot + $userParams.LogDirectory) ))
    {
        New-Item -ItemType directory -Path ($dirRoot + $userParams.LogDirectory)
    }    
}


function Get-GroupMembershipReport(){
    Param(
        [Parameter(Mandatory = $true)]
        $userParams,
        [Parameter(Mandatory = $true)]
        $outFile,
        [Parameter(Mandatory = $false)]
        $getAllProjects,
        [Parameter(Mandatory = $true)]
        $dirRoot,
        [Parameter(Mandatory = $true)]
        $PAT,
        [Parameter(Mandatory = $true)]
        $VSTSMasterAcct,
        [Parameter(Mandatory = $true)]
        $projectName,
        [Parameter(Mandatory = $false)]
        [bool]$recurseAADGroups = $false,
        [Parameter(Mandatory = $false)]
        [ValidateSet('JSON','CSV','Both')]
        [string]$OutputFormat = 'JSON'
    )

    $authorization = GetVSTSCredential -Token $PAT

    Write-Log -Message "Starting membership report" -Level 'Info' -FunctionName 'Get-GroupMembershipReport'

    # Pre-fetch all users in org with continuation token support for in-memory matching
    $usersUri = $userParams.HTTP_preFix + "://vssps.dev.azure.com/" + $VSTSMasterAcct + "/_apis/graph/users?api-version=6.0-preview.1"
    $uri = $usersUri
    $allUsers = @()
    do {
        Write-Log -Message "Fetching users batch..." -Level 'Info' -FunctionName 'Get-GroupMembershipReport'
        $headers = $null
        $response = Invoke-AdoRestMethod -Uri $uri -Method Get -Headers $authorization -ResponseHeaders ([ref]$headers)
        $allUsers += $response.value
        if ($headers -and $headers["x-ms-continuationtoken"]) {
            $continuation = $headers["x-ms-continuationtoken"]
            $uri = $usersUri + "&continuationToken=" + [System.Uri]::EscapeDataString($continuation)
        }
    } while ($headers -and $headers["x-ms-continuationtoken"])
    Write-Log -Message "Fetched $($allUsers.Count) users" -Level 'Info' -FunctionName 'Get-GroupMembershipReport'

    # Pre-fetch all groups in org with continuation token support
    $groupsUri = $userParams.HTTP_preFix + "://vssps.dev.azure.com/" + $VSTSMasterAcct + "/_apis/graph/groups?api-version=7.0-preview"
    $uri = $groupsUri
    $allGroups = @()
    do {
        Write-Log -Message "Fetching groups batch..." -Level 'Info' -FunctionName 'Get-GroupMembershipReport'
        $headers = $null
        $response = Invoke-AdoRestMethod -Uri $uri -Method Get -Headers $authorization -ResponseHeaders ([ref]$headers)
        $allGroups += $response.value
        if ($headers -and $headers["x-ms-continuationtoken"]) {
            $continuation = $headers["x-ms-continuationtoken"]
            $uri = $groupsUri + "&continuationToken=" + [System.Uri]::EscapeDataString($continuation)
        }
    } while ($headers -and $headers["x-ms-continuationtoken"])
    Write-Log -Message "Fetched $($allGroups.Count) groups" -Level 'Info' -FunctionName 'Get-GroupMembershipReport'

    # Get all teams in org to distinguish teams from groups (paginated)
    $teamsList = @()
    $teamSkip = 0
    $teamBatchSize = 1000
    do {
        $teamBatchUri = $userParams.HTTP_preFix + "://dev.azure.com/" + $VSTSMasterAcct + "/_apis/teams?`$top=$teamBatchSize&`$skip=$teamSkip&api-version=6.1-preview.3"
        $teamBatch = Invoke-AdoRestMethod -Uri $teamBatchUri -Method Get -Headers $authorization
        $teamsList += $teamBatch.value
        $teamSkip += $teamBatchSize
    } while ($teamBatch.value.Count -eq $teamBatchSize)
    $allTeams = [PSCustomObject]@{ value = $teamsList }
    Write-Log -Message "Fetched $($teamsList.Count) teams" -Level 'Info' -FunctionName 'Get-GroupMembershipReport'

    # Get project details to identify project-scoped groups
    $orgUri = $userParams.HTTP_preFix + "://dev.azure.com/" + $VSTSMasterAcct + "/_apis/projects?api-version=5.0"
    $orgProjects = Invoke-AdoRestMethod -uri $orgUri -Method Get -Headers $authorization

    # Pre-fetch user entitlements for status and last-access date
    $entitlementUri = $userParams.HTTP_preFix + "://vsaex.dev.azure.com/" + $VSTSMasterAcct + "/_apis/userentitlements?api-version=6.0-preview.3&`$top=10000"
    $uri = $entitlementUri
    $entitlementLookup = @{}
    do {
        Write-Log -Message "Fetching user entitlements batch..." -Level 'Info' -FunctionName 'Get-GroupMembershipReport'
        $response = Invoke-AdoRestMethod -Uri $uri -Method Get -Headers $authorization
        foreach ($ent in $response.members) {
            if ($ent.user.principalName) {
                $entitlementLookup[$ent.user.principalName.ToLower()] = @{
                    Status           = if ($ent.accessLevel.status) { $ent.accessLevel.status } else { $null }
                    LastAccessedDate = if ($ent.lastAccessedDate) {
                        try { ([datetime]$ent.lastAccessedDate).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'") }
                        catch { $ent.lastAccessedDate }
                    } else { $null }
                }
            }
        }
        $continuationToken = $response.continuationToken
        if ($continuationToken) {
            $uri = $entitlementUri + "&continuationToken=" + [System.Uri]::EscapeDataString($continuationToken)
        }
    } while ($continuationToken)
    Write-Log -Message "Fetched entitlements for $($entitlementLookup.Count) users" -Level 'Info' -FunctionName 'Get-GroupMembershipReport'

    if ($getAllProjects -eq "True") {
        $projectIds = $orgProjects.value | ForEach-Object { $_.id }
    } else {
        $projectNames = $projectName -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        $projectIds = @(($orgProjects.value | Where-Object { $_.Name -in $projectNames }).id)
    }

    # Filter groups to target project(s) by domain
    $prjGroups = $allGroups | Where-Object {
        foreach ($pid in $projectIds) {
            if ($_.domain -eq "vstfs:///Classification/TeamProject/$pid") { return $true }
        }
        return $false
    }
    Write-Log -Message "Processing $($prjGroups.Count) project groups" -Level 'Info' -FunctionName 'Get-GroupMembershipReport'

    # $outputResult and $aadGroupsResolved are declared per-project in the processing loop below

    # Helper: resolve members of a group descriptor (direction=down)
    function Resolve-GroupMembers {
        param($descriptor, $parentName, $projectDisplayName, $groupType, $groupDescription, [bool]$recurseAAD = $false)

        $memberShipUri = $userParams.HTTP_preFix + "://vssps.dev.azure.com/" + $VSTSMasterAcct + "/_apis/Graph/Memberships/" + $descriptor + "?direction=down"
        try {
            $members = Invoke-AdoRestMethod -Uri $memberShipUri -Method Get -Headers $authorization
        }
        catch {
            Write-Log -Message "Failed to get memberships for $parentName : $($_.Exception.Message)" -Level 'Warning' -FunctionName 'Resolve-GroupMembers' -Uri $memberShipUri
            return
        }

        foreach ($item in $members.value) {
            # Try in-memory user match first (fast path)
            $matchedUser = $allUsers | Where-Object { $_.descriptor -eq $item.memberDescriptor }
            if ($matchedUser) {
                $entInfo = $entitlementLookup[$matchedUser.principalName.ToLower()]
                $details = [PSCustomObject]@{
                    ProjectName      = $projectDisplayName
                    GroupName        = $parentName
                    GroupType        = $groupType
                    GroupDescription = $groupDescription
                    Relationship     = "Member"
                    MemberType       = ($matchedUser.subjectKind.Substring(0,1).ToUpper() + $matchedUser.subjectKind.Substring(1).ToLower())
                    DisplayName      = $matchedUser.displayName
                    MailAddress      = $matchedUser.mailAddress
                    PrincipalName    = $matchedUser.principalName
                    Origin           = $matchedUser.origin
                    ResolvedVia      = "ADO Membership API"
                    Status           = if ($entInfo) { $entInfo.Status } else { $null }
                    LastAccessedDate = if ($entInfo) { $entInfo.LastAccessedDate } else { $null }
                }
                $outputResult.Add($details)
            }
            else {
                # Fallback: API lookup for unmatched descriptors (nested groups, service accounts)
                $lookupUri = $userParams.HTTP_preFix + "://vssps.dev.azure.com/" + $VSTSMasterAcct + "/_apis/graph/subjectlookup?api-version=5.1-preview.1"
                $body = @{ 'lookupKeys' = @(@{ 'descriptor' = "$($item.memberDescriptor)" }) } | ConvertTo-Json
                try {
                    $response = Invoke-AdoRestMethod -Uri $lookupUri -Method Post -Headers $authorization -Body $body -ContentType 'application/json'
                }
                catch {
                    Write-Log -Message "Subject lookup failed for descriptor in $parentName : $($_.Exception.Message)" -Level 'Warning' -FunctionName 'Resolve-GroupMembers' -Uri $lookupUri
                    continue
                }

                $memberDetails = $response.value."$($item.memberDescriptor)"
                if (-not $memberDetails) { continue }

                # Determine team vs group
                $memberEntityType = "Group"
                if ($memberDetails.subjectKind -eq "user") {
                    $memberEntityType = "User"
                }
                elseif ($memberDetails.principalName) {
                    $prNameParts = $memberDetails.principalName.Split('\')
                    if ($prNameParts.Count -ge 2) {
                        $pn = $prNameParts[0].Substring(1, $prNameParts[0].Length - 2)
                        $tn = $prNameParts[1]
                        $teamFound = $allTeams.value | Where-Object { ($_.ProjectName -eq $pn) -and ($_.name -eq $tn) }
                        if ($teamFound) { $memberEntityType = "Team" }
                    }
                }

                $isUser = ($memberEntityType -eq "User")
                $entInfo = if ($isUser -and $memberDetails.principalName) { $entitlementLookup[$memberDetails.principalName.ToLower()] } else { $null }
                $details = [PSCustomObject]@{
                    ProjectName      = $projectDisplayName
                    GroupName        = $parentName
                    GroupType        = $groupType
                    GroupDescription = $groupDescription
                    Relationship     = "Member"
                    MemberType       = $memberEntityType
                    DisplayName      = $memberDetails.displayName
                    MailAddress      = $memberDetails.mailAddress
                    PrincipalName    = $memberDetails.principalName
                    Origin           = $memberDetails.origin
                    ResolvedVia      = "ADO Membership API"
                    Status           = if ($entInfo) { $entInfo.Status } else { $null }
                    LastAccessedDate = if ($entInfo) { $entInfo.LastAccessedDate } else { $null }
                }
                $outputResult.Add($details)

                # Recursively resolve AAD groups if enabled — use HierarchyQuery for Entra group members
                if ($recurseAAD -and ($memberDetails.subjectKind -eq "group") -and ($item.memberDescriptor -like "aadgp.*")) {
                    if (-not $aadGroupsResolved.Contains($item.memberDescriptor)) {
                        $aadGroupsResolved.Add($item.memberDescriptor) | Out-Null
                        Write-Log -Message "Recursing into AAD group via HierarchyQuery: $($memberDetails.displayName)" -Level 'Info' -FunctionName 'Resolve-GroupMembers'
                        Resolve-AadGroupMembers -descriptor $item.memberDescriptor -parentName $memberDetails.principalName -projectDisplayName $projectDisplayName
                    }
                }
            }
        }
    }

    # Helper: resolve members of an AAD/Entra group via the Contribution HierarchyQuery API.
    # This returns the real Entra group membership including disabled/deleted users that the
    # Graph Memberships API omits.
    function Resolve-AadGroupMembers {
        param($descriptor, $parentName, $projectDisplayName)

        $hierUri = $userParams.HTTP_preFix + "://dev.azure.com/" + $VSTSMasterAcct + "/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1"
        $pageUrl = $userParams.HTTP_preFix + "://dev.azure.com/" + $VSTSMasterAcct + "/" + $projectDisplayName + "/_settings/permissions?subjectDescriptor=" + $descriptor
        $hierBody = @{
            contributionIds = @("ms.vss-admin-web.org-admin-group-members-data-provider")
            dataProviderContext = @{
                properties = @{
                    subjectDescriptor = $descriptor
                    sourcePage = @{
                        url = $pageUrl
                        routeId = "ms.vss-admin-web.project-admin-hub-route"
                        routeValues = @{
                            project    = $projectDisplayName
                            adminPivot = "permissions"
                            controller = "ContributedPage"
                            action     = "Execute"
                        }
                    }
                }
            }
        } | ConvertTo-Json -Depth 10

        try {
            $response = Invoke-AdoRestMethod -Uri $hierUri -Method Post -Headers $authorization -Body $hierBody -ContentType 'application/json'
        }
        catch {
            Write-Log -Message "HierarchyQuery failed for AAD group $parentName : $($_.Exception.Message)" -Level 'Warning' -FunctionName 'Resolve-AadGroupMembers' -Uri $hierUri
            return
        }

        $identities = $response.dataProviders."ms.vss-admin-web.org-admin-group-members-data-provider".identities
        if (-not $identities) { return }

        foreach ($identity in $identities) {
            $memberType = if ($identity.subjectKind -eq "User") { "User" } elseif ($identity.entityType -eq "Group") { "Group" } else { "User" }
            $email = $identity.mailAddress
            $principal = if ($email) { $email } else { $identity.principalName }
            # Entitlement lookup: try email first, then principalName, then via graph user match
            $entInfo = $null
            $graphUser = $null
            if ($memberType -eq "User") {
                # Cross-reference against pre-fetched Graph users (match by email, principalName, or displayName)
                if ($email) {
                    $graphUser = $allUsers | Where-Object { $_.mailAddress -eq $email } | Select-Object -First 1
                }
                if (-not $graphUser -and $identity.principalName) {
                    $graphUser = $allUsers | Where-Object { $_.principalName -eq $identity.principalName } | Select-Object -First 1
                }
                if (-not $graphUser -and $identity.displayName) {
                    $graphUser = $allUsers | Where-Object { $_.displayName -eq $identity.displayName } | Select-Object -First 1
                }
                # Entitlement lookup: try HierarchyQuery email, then graph user's principalName
                if ($email) { $entInfo = $entitlementLookup[$email.ToLower()] }
                if (-not $entInfo -and $graphUser -and $graphUser.principalName) {
                    $entInfo = $entitlementLookup[$graphUser.principalName.ToLower()]
                }
                if (-not $entInfo -and $graphUser -and $graphUser.mailAddress) {
                    $entInfo = $entitlementLookup[$graphUser.mailAddress.ToLower()]
                }
            }

            # Use the Graph user's UPN as PrincipalName when the HierarchyQuery value is not an email
            $resolvedPrincipal = $principal
            if ($graphUser -and $graphUser.principalName -and $principal -notlike '*@*') {
                $resolvedPrincipal = $graphUser.principalName
            }

            $details = [PSCustomObject]@{
                ProjectName      = $projectDisplayName
                GroupName        = $parentName
                GroupType        = "Group"
                GroupDescription = $null
                Relationship     = "Member"
                MemberType       = $memberType
                DisplayName      = $identity.displayName
                MailAddress      = if ($email) { $email } elseif ($graphUser -and $graphUser.mailAddress) { $graphUser.mailAddress } else { $null }
                PrincipalName    = $resolvedPrincipal
                Origin           = "aad"
                ResolvedVia      = "Hierarchy Group Expansion"
                Status           = if ($entInfo) { $entInfo.Status } else { $null }
                LastAccessedDate = if ($entInfo) { $entInfo.LastAccessedDate } else { $null }
            }
            $outputResult.Add($details)

            # Recurse into nested AAD groups
            if ($memberType -eq "Group" -and $identity.descriptor -and ($identity.descriptor -like "aadgp.*")) {
                if (-not $aadGroupsResolved.Contains($identity.descriptor)) {
                    $aadGroupsResolved.Add($identity.descriptor) | Out-Null
                    Write-Log -Message "Recursing into nested AAD group: $($identity.displayName)" -Level 'Info' -FunctionName 'Resolve-AadGroupMembers'
                    Resolve-AadGroupMembers -descriptor $identity.descriptor -parentName $identity.displayName -projectDisplayName $projectDisplayName
                }
            }
        }
        Write-Log -Message "HierarchyQuery returned $($identities.Count) members for AAD group $parentName" -Level 'Info' -FunctionName 'Resolve-AadGroupMembers'
    }

    # Helper: resolve parent groups of a descriptor (direction=up / Member-Of)
    function Resolve-GroupMemberOf {
        param($descriptor, $groupName, $projectDisplayName, $groupType, $groupDescription)

        $memberOfUri = $userParams.HTTP_preFix + "://vssps.dev.azure.com/" + $VSTSMasterAcct + "/_apis/Graph/Memberships/" + $descriptor + "?direction=up"
        try {
            $parents = Invoke-AdoRestMethod -Uri $memberOfUri -Method Get -Headers $authorization
        }
        catch {
            Write-Log -Message "Failed to get member-of for $groupName : $($_.Exception.Message)" -Level 'Warning' -FunctionName 'Resolve-GroupMemberOf' -Uri $memberOfUri
            return
        }

        foreach ($item in $parents.value) {
            # Try in-memory group match first
            $matchedGroup = $allGroups | Where-Object { $_.descriptor -eq $item.containerDescriptor }
            if ($matchedGroup) {
                # Determine if parent is a team
                $parentType = "Group"
                if ($matchedGroup.principalName) {
                    $parts = $matchedGroup.principalName.Split('\')
                    if ($parts.Count -ge 2) {
                        $pn = $parts[0].Substring(1, $parts[0].Length - 2)
                        $tn = $parts[1]
                        $teamFound = $allTeams.value | Where-Object { ($_.ProjectName -eq $pn) -and ($_.name -eq $tn) }
                        if ($teamFound) { $parentType = "Team" }
                    }
                }

                $details = [PSCustomObject]@{
                    ProjectName      = $projectDisplayName
                    GroupName        = $groupName
                    GroupType        = $groupType
                    GroupDescription = $groupDescription
                    Relationship     = "Member-Of"
                    MemberType       = $parentType
                    DisplayName      = $matchedGroup.displayName
                    MailAddress      = $matchedGroup.mailAddress
                    PrincipalName    = $matchedGroup.principalName
                    Origin           = $matchedGroup.origin
                }
                $outputResult.Add($details)
            }
            else {
                # Fallback: subject lookup for parent groups not in cache (org-level groups)
                $lookupUri = $userParams.HTTP_preFix + "://vssps.dev.azure.com/" + $VSTSMasterAcct + "/_apis/graph/subjectlookup?api-version=5.1-preview.1"
                $body = @{ 'lookupKeys' = @(@{ 'descriptor' = "$($item.containerDescriptor)" }) } | ConvertTo-Json
                try {
                    $response = Invoke-AdoRestMethod -Uri $lookupUri -Method Post -Headers $authorization -Body $body -ContentType 'application/json'
                }
                catch {
                    Write-Log -Message "Subject lookup failed for parent descriptor in $groupName : $($_.Exception.Message)" -Level 'Warning' -FunctionName 'Resolve-GroupMemberOf' -Uri $lookupUri
                    continue
                }

                $parentDetails = $response.value."$($item.containerDescriptor)"
                if (-not $parentDetails) { continue }

                $parentType = "Group"
                if ($parentDetails.principalName) {
                    $parts = $parentDetails.principalName.Split('\')
                    if ($parts.Count -ge 2) {
                        $pn = $parts[0].Substring(1, $parts[0].Length - 2)
                        $tn = $parts[1]
                        $teamFound = $allTeams.value | Where-Object { ($_.ProjectName -eq $pn) -and ($_.name -eq $tn) }
                        if ($teamFound) { $parentType = "Team" }
                    }
                }

                $details = [PSCustomObject]@{
                    ProjectName      = $projectDisplayName
                    GroupName        = $groupName
                    GroupType        = $groupType
                    GroupDescription = $groupDescription
                    Relationship     = "Member-Of"
                    MemberType       = $parentType
                    DisplayName      = $parentDetails.displayName
                    MailAddress      = $parentDetails.mailAddress
                    PrincipalName    = $parentDetails.principalName
                    Origin           = $parentDetails.origin
                }
                $outputResult.Add($details)
            }
        }
    }

    # Group the project groups by project for per-project output files
    $today = Get-Date -Format "MM-dd-yyyy"
    $groupsByProject = $prjGroups | Group-Object -Property {
        $parts = $_.principalName.Split('\')
        $parts[0].Substring(1, $parts[0].Length - 2)
    }

    foreach ($projectGroup in $groupsByProject) {
        $projDisplayName = $projectGroup.Name
        $outputResult = [System.Collections.Generic.List[PSObject]]::new()
        $aadGroupsResolved = [System.Collections.Generic.HashSet[string]]::new()

        foreach ($group in $projectGroup.Group) {
            $prNameParts = $group.principalName.Split('\')
            $shortName = $prNameParts[1]

            $isTeam = $allTeams.value | Where-Object { ($_.ProjectName -eq $projDisplayName) -and ($_.name -eq $shortName) }
            $grpType = if ($isTeam) { "Team" } else { "Group" }
            $grpDesc = if ($group.description) { $group.description } else { $null }

            Write-Host "Processing: $($group.principalName)"

            # Members: who is in this group (direction=down)
            Resolve-GroupMembers -descriptor $group.descriptor -parentName $group.principalName -projectDisplayName $projDisplayName -groupType $grpType -groupDescription $grpDesc -recurseAAD $recurseAADGroups

            # Member-Of: what parent groups this group belongs to (direction=up)
            Resolve-GroupMemberOf -descriptor $group.descriptor -groupName $group.principalName -projectDisplayName $projDisplayName -groupType $grpType -groupDescription $grpDesc
        }

        # Write per-project output (JSON and/or CSV)
        $projectOutFile = $dirRoot + $userParams.SecurityDir + $projDisplayName + "_" + $today + "_" + $outFile
        Write-Log -Message "Writing $($outputResult.Count) membership entries to $projectOutFile" -Level 'Info' -FunctionName 'Get-GroupMembershipReport'
        if ($OutputFormat -in @('JSON','Both')) {
            $outputResult | ConvertTo-Json -Depth 10 | Out-File -FilePath $projectOutFile -Force
        }
        if ($OutputFormat -in @('CSV','Both')) {
            $csvFile = $projectOutFile -replace '\.json$', '.csv'
            $outputResult | Export-Csv -Path $csvFile -NoTypeInformation -Force
            Write-Log -Message "Wrote CSV to $csvFile" -Level 'Info' -FunctionName 'Get-GroupMembershipReport'
        }
    }
}

function GetVSTSCredential () {
    Param(
        $Token
    )

    $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":{0}" -f $token))
    return @{Authorization = ("Basic {0}" -f $base64AuthInfo)}
}