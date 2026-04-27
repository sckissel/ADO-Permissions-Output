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
    $usersUri = $userParams.HTTP_preFix + "://vssps.dev.azure.com/" + $VSTSMasterAcct + "/_apis/graph/users?api-version=7.2-preview.1"
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
    $groupsUri = $userParams.HTTP_preFix + "://vssps.dev.azure.com/" + $VSTSMasterAcct + "/_apis/graph/groups?api-version=7.2-preview.1"
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
        $teamBatchUri = $userParams.HTTP_preFix + "://dev.azure.com/" + $VSTSMasterAcct + "/_apis/teams?`$top=$teamBatchSize&`$skip=$teamSkip&api-version=7.2-preview.3"
        $teamBatch = Invoke-AdoRestMethod -Uri $teamBatchUri -Method Get -Headers $authorization
        $teamsList += $teamBatch.value
        $teamSkip += $teamBatchSize
    } while ($teamBatch.value.Count -eq $teamBatchSize)
    $allTeams = [PSCustomObject]@{ value = $teamsList }
    Write-Log -Message "Fetched $($teamsList.Count) teams" -Level 'Info' -FunctionName 'Get-GroupMembershipReport'

    # Get project details to identify project-scoped groups
    $orgUri = $userParams.HTTP_preFix + "://dev.azure.com/" + $VSTSMasterAcct + "/_apis/projects?api-version=7.2-preview.1"
    $orgProjects = Invoke-AdoRestMethod -uri $orgUri -Method Get -Headers $authorization

    # Pre-fetch user entitlements for status and last-access date
    $entitlementUri = $userParams.HTTP_preFix + "://vsaex.dev.azure.com/" + $VSTSMasterAcct + "/_apis/userentitlements?api-version=7.2-preview.3&`$top=10000"
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
        if ($projectNames.Count -gt 0 -and $projectIds.Count -eq 0) {
            $requested = $projectNames -join ', '
            $message = "No Azure DevOps projects matched the requested project filter(s): $requested"
            Write-Log -Message $message -Level 'Error' -FunctionName 'Get-GroupMembershipReport'
            throw $message
        }
    }

    # Index project id -> name for bucketing per-project output
    $projectIdToName = @{}
    foreach ($p in $orgProjects.value) {
        if ($projectIds -contains $p.id) { $projectIdToName[$p.id] = $p.Name }
    }

    # Per-project scoped group fetch. The org-level graph/groups call does not
    # reliably enumerate built-in well-known project groups (Project Admins,
    # Contributors, Readers, Build Admins, Endpoint Admins, Endpoint Creators,
    # Release Admins, Project Valid Users). The scopeDescriptor variant does.
    $projectScopedGroups = @{}
    foreach ($projId in $projectIds) {
        $scopeUri = $userParams.HTTP_preFix + "://vssps.dev.azure.com/" + $VSTSMasterAcct + "/_apis/graph/descriptors/" + $projId + "?api-version=7.2-preview.1"
        try {
            $scopeResp = Invoke-AdoRestMethod -Uri $scopeUri -Method Get -Headers $authorization
            $scope = $scopeResp.value
        }
        catch {
            Write-Log -Message "Failed to resolve scope descriptor for project $projId : $($_.Exception.Message)" -Level 'Warning' -FunctionName 'Get-GroupMembershipReport' -Uri $scopeUri
            continue
        }
        if (-not $scope) { continue }

        $scopedGroupsBaseUri = $userParams.HTTP_preFix + "://vssps.dev.azure.com/" + $VSTSMasterAcct + "/_apis/graph/groups?scopeDescriptor=" + [System.Uri]::EscapeDataString($scope) + "&api-version=7.2-preview.1"
        $uri = $scopedGroupsBaseUri
        $scopedList = [System.Collections.Generic.List[object]]::new()
        do {
            $headers = $null
            try {
                $resp = Invoke-AdoRestMethod -Uri $uri -Method Get -Headers $authorization -ResponseHeaders ([ref]$headers)
            }
            catch {
                Write-Log -Message "Scoped group fetch failed for project $projId : $($_.Exception.Message)" -Level 'Warning' -FunctionName 'Get-GroupMembershipReport' -Uri $uri
                break
            }
            foreach ($g in $resp.value) { $scopedList.Add($g) }
            if ($headers -and $headers["x-ms-continuationtoken"]) {
                $uri = $scopedGroupsBaseUri + "&continuationToken=" + [System.Uri]::EscapeDataString($headers["x-ms-continuationtoken"])
            }
        } while ($headers -and $headers["x-ms-continuationtoken"])

        $projectScopedGroups[$projId] = $scopedList
        # Union into $allGroups so descriptor lookups in resolve paths can find them
        foreach ($g in $scopedList) {
            if (-not ($allGroups | Where-Object { $_.descriptor -eq $g.descriptor } | Select-Object -First 1)) {
                $allGroups += $g
            }
        }
        Write-Log -Message "Fetched $($scopedList.Count) scoped groups for project $($projectIdToName[$projId])" -Level 'Info' -FunctionName 'Get-GroupMembershipReport'
    }

    # Index all groups by descriptor for fast union with ACL-derived principals
    $groupsByDescriptor = @{}
    foreach ($g in $allGroups) {
        if ($g.descriptor) { $groupsByDescriptor[$g.descriptor] = $g }
    }

    # Fetch security namespaces once for the ACL harvest (matches what the UI shows)
    $namespaces = @()
    $nsUri = $userParams.HTTP_preFix + "://dev.azure.com/" + $VSTSMasterAcct + "/_apis/securitynamespaces?api-version=7.2-preview.1"
    try {
        $nsResp = Invoke-AdoRestMethod -Uri $nsUri -Method Get -Headers $authorization
        $namespaces = $nsResp.value
        Write-Log -Message "Fetched $($namespaces.Count) security namespaces for ACL harvest" -Level 'Info' -FunctionName 'Get-GroupMembershipReport'
    }
    catch {
        Write-Log -Message "Failed to fetch security namespaces; ACL harvest disabled: $($_.Exception.Message)" -Level 'Warning' -FunctionName 'Get-GroupMembershipReport' -Uri $nsUri
    }

    # Fetch ACLs once per namespace with NO token + recurse=true. We filter per project
    # later using token-prefix predicates. This replaces the prior approach of sending
    # a single '$PROJECT:vstfs:///Classification/TeamProject/<id>' token to every
    # namespace, which is only valid for the Project namespace and caused 403s
    # elsewhere (Git, Build, Library, Environment, CSS, etc.).
    $aclsByNamespace = @{}
    foreach ($ns in $namespaces) {
        $aclUri = $userParams.HTTP_preFix + "://dev.azure.com/" + $VSTSMasterAcct +
                  "/_apis/accesscontrollists/$($ns.namespaceId)?recurse=true&includeExtendedInfo=false&api-version=7.2-preview.1"
        try {
            $resp = Invoke-AdoRestMethod -Uri $aclUri -Method Get -Headers $authorization
            $aclsByNamespace[$ns.namespaceId] = $resp.value
        }
        catch {
            Write-Log -Message "ACL harvest failed for namespace $($ns.name): $($_.Exception.Message)" -Level 'Warning' -FunctionName 'Get-GroupMembershipReport' -Uri $aclUri
            $aclsByNamespace[$ns.namespaceId] = @()
        }
    }

    # Classification-node roots per project (used by CSS/Iteration token-prefix match,
    # whose tokens encode 'vstfs:///Classification/Node/<rootGuid>...' rather than
    # the project GUID).
    $projectRootNodeIds = @{}
    foreach ($projId in $projectIds) {
        $projName = $projectIdToName[$projId]
        if (-not $projName) { continue }
        $projectRootNodeIds[$projId] = @{ Area = $null; Iteration = $null }
        foreach ($struct in @('Areas', 'Iterations')) {
            $cnUri = $userParams.HTTP_preFix + "://dev.azure.com/" + $VSTSMasterAcct + "/" +
                     [System.Uri]::EscapeDataString($projName) +
                     "/_apis/wit/classificationnodes/$struct" + "?`$depth=0&api-version=7.2-preview.1"
            try {
                $cn = Invoke-AdoRestMethod -Uri $cnUri -Method Get -Headers $authorization
                if ($cn.identifier) {
                    $key = if ($struct -eq 'Areas') { 'Area' } else { 'Iteration' }
                    $projectRootNodeIds[$projId][$key] = $cn.identifier
                }
            }
            catch {
                Write-Log -Message "Classification-node lookup failed for $projName ($struct): $($_.Exception.Message)" -Level 'Warning' -FunctionName 'Get-GroupMembershipReport' -Uri $cnUri
            }
        }
    }

    # Build the per-project principal list by unioning:
    #   (a) groups whose domain matches the project (project-scoped groups), with
    #   (b) every principal carrying an ACE on any of the project's security tokens
    #       (captures collection-scoped [TEAM FOUNDATION]\* groups and AAD groups
    #       directly granted permissions on the project - matching the UI).
    $prjGroups = [System.Collections.Generic.List[object]]::new()
    foreach ($projId in $projectIds) {
        $projectTag = $projectIdToName[$projId]
        if (-not $projectTag) { continue }
        $seenForProject = [System.Collections.Generic.HashSet[string]]::new()

        # (a) Domain-matched groups
        foreach ($g in $allGroups) {
            if ($g.domain -eq "vstfs:///Classification/TeamProject/$projId") {
                if ($seenForProject.Add($g.descriptor)) {
                    $clone = $g | Select-Object *
                    $clone | Add-Member -NotePropertyName '_projectTag' -NotePropertyValue $projectTag -Force
                    $prjGroups.Add($clone)
                }
            }
        }

        # (a2) Project-scope-descriptor groups (built-in well-known project groups)
        if ($projectScopedGroups.ContainsKey($projId)) {
            foreach ($g in $projectScopedGroups[$projId]) {
                if ($seenForProject.Add($g.descriptor)) {
                    $clone = $g | Select-Object *
                    $clone | Add-Member -NotePropertyName '_projectTag' -NotePropertyValue $projectTag -Force
                    $prjGroups.Add($clone)
                }
            }
        }

        # (b) ACL-derived principals: filter the per-namespace ACL cache down to tokens
        # that belong to this project, then harvest SID descriptors from acesDictionary,
        # translate SID -> graph subjectDescriptor in batches, and union into prjGroups.
        if ($namespaces.Count -gt 0) {
            $sidDescriptors = [System.Collections.Generic.HashSet[string]]::new()
            $areaRoot = if ($projectRootNodeIds.ContainsKey($projId)) { $projectRootNodeIds[$projId].Area } else { $null }
            $iterRoot = if ($projectRootNodeIds.ContainsKey($projId)) { $projectRootNodeIds[$projId].Iteration } else { $null }
            foreach ($ns in $namespaces) {
                $nsAcls = $aclsByNamespace[$ns.namespaceId]
                if (-not $nsAcls -or $nsAcls.Count -eq 0) { continue }
                foreach ($acl in $nsAcls) {
                    $tok = $acl.token
                    if ([string]::IsNullOrEmpty($tok)) { continue }

                    # Token-prefix predicate per namespace (derived from ADO security
                    # namespace token formats). Most namespaces embed the project GUID
                    # directly; CSS/Iteration embed classification-node GUIDs;
                    # VersionControlItems uses the project name.
                    $matches = $false
                    if ($tok.IndexOf($projId, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                        $matches = $true
                    }
                    elseif ($ns.name -eq 'VersionControlItems' -and $projectTag) {
                        if ($tok -eq "`$/$projectTag" -or $tok.StartsWith("`$/$projectTag/", [StringComparison]::OrdinalIgnoreCase)) {
                            $matches = $true
                        }
                    }
                    elseif (($ns.name -eq 'CSS' -or $ns.name -eq 'Iteration')) {
                        $root = if ($ns.name -eq 'CSS') { $areaRoot } else { $iterRoot }
                        if ($root -and $tok.IndexOf($root, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                            $matches = $true
                        }
                    }

                    if (-not $matches) { continue }
                    if ($acl.acesDictionary) {
                        foreach ($aceKey in $acl.acesDictionary.PSObject.Properties.Name) {
                            [void]$sidDescriptors.Add($aceKey)
                        }
                    }
                }
            }

            # Translate SID descriptors to graph subjectDescriptors in batches
            if ($sidDescriptors.Count -gt 0) {
                $sidList = [System.Collections.Generic.List[string]]::new($sidDescriptors)
                $batchSize = 50
                for ($i = 0; $i -lt $sidList.Count; $i += $batchSize) {
                    $take = [Math]::Min($batchSize, $sidList.Count - $i)
                    $slice = $sidList.GetRange($i, $take)
                    $descParam = ($slice -join ',')
                    $idUri = $userParams.HTTP_preFix + "://vssps.dev.azure.com/" + $VSTSMasterAcct +
                            "/_apis/identities?descriptors=" + [System.Uri]::EscapeDataString($descParam) +
                            "&queryMembership=None&api-version=7.2-preview.1"
                    try {
                        $idResp = Invoke-AdoRestMethod -Uri $idUri -Method Get -Headers $authorization
                        foreach ($ident in $idResp.value) {
                            if ($ident.subjectDescriptor -and $groupsByDescriptor.ContainsKey($ident.subjectDescriptor)) {
                                if ($seenForProject.Add($ident.subjectDescriptor)) {
                                    $clone = $groupsByDescriptor[$ident.subjectDescriptor] | Select-Object *
                                    $clone | Add-Member -NotePropertyName '_projectTag' -NotePropertyValue $projectTag -Force
                                    $prjGroups.Add($clone)
                                }
                            }
                        }
                    }
                    catch {
                        Write-Log -Message "Identity translation failed for project $projectTag : $($_.Exception.Message)" -Level 'Warning' -FunctionName 'Get-GroupMembershipReport' -Uri $idUri
                    }
                }
            }
        }
    }
    Write-Log -Message "Processing $($prjGroups.Count) project groups (domain + ACL union)" -Level 'Info' -FunctionName 'Get-GroupMembershipReport'

    # $outputResult and $aadGroupsResolved are declared per-project in the processing loop below

    # Helper: when subjectlookup returns a Project Build Service (or other service
    # identity) with displayName == bare project GUID, resolve the underlying
    # Microsoft.TeamFoundation.ServiceIdentity descriptor and synthesize the
    # friendly "<Project> Build Service (<Org>)" form. Returns the original
    # display name unchanged when it isn't a GUID.
    function Resolve-ServiceIdentityName {
        param($subjectDescriptor, $rawDisplayName)

        # Skip resolution only when the display name clearly does NOT contain a
        # GUID. The previous [guid]::TryParse gate rejected names like
        # "<GUID> Build Service (<Org>)" because they aren't bare GUIDs -- but
        # those still need resolution. A GUID-pattern regex catches both bare
        # GUIDs and GUID-containing names.
        if ($rawDisplayName -notmatch '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}') {
            return $rawDisplayName
        }
        if ([string]::IsNullOrWhiteSpace($subjectDescriptor)) {
            return $rawDisplayName
        }

        try {
            $idUri = $userParams.HTTP_preFix + "://vssps.dev.azure.com/" + $VSTSMasterAcct +
                     "/_apis/identities?subjectDescriptors=" + $subjectDescriptor +
                     "&queryMembership=None&api-version=7.2-preview.1"
            $resp = Invoke-AdoRestMethod -Uri $idUri -Method Get -Headers $authorization
        }
        catch {
            Write-Log -Message "Service identity resolve failed for $subjectDescriptor : $($_.Exception.Message)" -Level 'Warning' -FunctionName 'Resolve-ServiceIdentityName' -Uri $idUri
            return $rawDisplayName
        }

        $sidDescriptor = $resp.value | Select-Object -First 1 -ExpandProperty descriptor -ErrorAction SilentlyContinue
        if (-not $sidDescriptor -or $sidDescriptor -notlike 'Microsoft.TeamFoundation.ServiceIdentity*') {
            return $rawDisplayName
        }

        $svcScope = $sidDescriptor.Split(';', 2)[1]
        if ($svcScope -like 'Build:*') {
            $scopeParts = $svcScope.Split(':')
            if ($scopeParts.Count -ge 3) {
                $projGuidFromScope = $scopeParts[2]
                if ($projectIdToName.ContainsKey($projGuidFromScope)) {
                    return "$($projectIdToName[$projGuidFromScope]) Build Service ($VSTSMasterAcct)"
                }
                return "Project Build Service ($VSTSMasterAcct)"
            }
            return "Project Collection Build Service ($VSTSMasterAcct)"
        }
        return $rawDisplayName
    }

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
                # Service identities (svc.*) such as the Project Build Service have
                # graph/users displayName set to the bare project GUID. Resolve to the
                # friendly "<Project> Build Service (<Org>)" form before emit. Mirrors
                # the fallback path below.
                $resolvedDisplay = $matchedUser.displayName
                if ($matchedUser.descriptor -like 'svc.*') {
                    $resolvedDisplay = Resolve-ServiceIdentityName -subjectDescriptor $matchedUser.descriptor -rawDisplayName $matchedUser.displayName
                }
                $details = [PSCustomObject]@{
                    ProjectName      = $projectDisplayName
                    GroupName        = $parentName
                    GroupType        = $groupType
                    GroupDescription = $groupDescription
                    Relationship     = "Member"
                    MemberType       = ($matchedUser.subjectKind.Substring(0,1).ToUpper() + $matchedUser.subjectKind.Substring(1).ToLower())
                    DisplayName      = $resolvedDisplay
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
                $lookupUri = $userParams.HTTP_preFix + "://vssps.dev.azure.com/" + $VSTSMasterAcct + "/_apis/graph/subjectlookup?api-version=7.2-preview.1"
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

                # Service identities (svc.*) such as the Project Build Service have
                # subjectlookup displayName set to the bare project GUID. Resolve to
                # the friendly "<Project> Build Service (<Org>)" form before emit.
                if ($item.memberDescriptor -like 'svc.*') {
                    $resolvedDisplay = Resolve-ServiceIdentityName -subjectDescriptor $item.memberDescriptor -rawDisplayName $memberDetails.displayName
                    if ($resolvedDisplay -ne $memberDetails.displayName) {
                        $memberDetails | Add-Member -NotePropertyName 'displayName' -NotePropertyValue $resolvedDisplay -Force
                    }
                }

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

                # Recursively resolve nested groups - both AAD (via HierarchyQuery to capture
                # disabled/deleted identities) and VSS/ADO groups (via direct Memberships API).
                # Visited-sets prevent cycles and redundant work.
                if ($memberDetails.subjectKind -eq "group") {
                    if ($recurseAAD -and ($item.memberDescriptor -like "aadgp.*")) {
                        if ($aadGroupsResolved.Add($item.memberDescriptor)) {
                            Write-Log -Message "Recursing into AAD group via HierarchyQuery: $($memberDetails.displayName)" -Level 'Info' -FunctionName 'Resolve-GroupMembers'
                            Resolve-AadGroupMembers -descriptor $item.memberDescriptor -parentName $memberDetails.principalName -projectDisplayName $projectDisplayName
                        }
                    }
                    elseif ($item.memberDescriptor -like "vssgp.*") {
                        if ($vssGroupsResolved.Add($item.memberDescriptor)) {
                            Write-Log -Message "Recursing into nested VSS group: $($memberDetails.displayName)" -Level 'Info' -FunctionName 'Resolve-GroupMembers'
                            Resolve-GroupMembers -descriptor $item.memberDescriptor `
                                -parentName $memberDetails.principalName `
                                -projectDisplayName $projectDisplayName `
                                -groupType "Group" `
                                -groupDescription $null `
                                -recurseAAD $recurseAAD
                        }
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

        $hierUri = $userParams.HTTP_preFix + "://dev.azure.com/" + $VSTSMasterAcct + "/_apis/Contribution/HierarchyQuery?api-version=7.2-preview.1"
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
                $lookupUri = $userParams.HTTP_preFix + "://vssps.dev.azure.com/" + $VSTSMasterAcct + "/_apis/graph/subjectlookup?api-version=7.2-preview.1"
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

    # Group the project groups by project for per-project output files.
    # Use the _projectTag attached during harvest so [TEAM FOUNDATION]\* and aadgp.*
    # principals land in the correct project file rather than bucketing on principalName prefix.
    $today = Get-Date -Format "MM-dd-yyyy"
    $groupsByProject = $prjGroups | Group-Object -Property _projectTag

    foreach ($projectGroup in $groupsByProject) {
        $projDisplayName = $projectGroup.Name
        $outputResult = [System.Collections.Generic.List[PSObject]]::new()
        $aadGroupsResolved = [System.Collections.Generic.HashSet[string]]::new()
        $vssGroupsResolved = [System.Collections.Generic.HashSet[string]]::new()

        foreach ($group in $projectGroup.Group) {
            $prNameParts = $group.principalName.Split('\')
            $shortName = if ($prNameParts.Count -ge 2) { $prNameParts[1] } else { $group.principalName }

            $isTeam = $allTeams.value | Where-Object { ($_.ProjectName -eq $projDisplayName) -and ($_.name -eq $shortName) }
            $grpType = if ($isTeam) { "Team" } else { "Group" }
            $grpDesc = if ($group.description) { $group.description } else { $null }

            Write-Host "Processing: $($group.principalName)"

            # Mark this top-level group as visited so nested references don't re-walk it
            [void]$vssGroupsResolved.Add($group.descriptor)

            # Emit a header row so every group appears in output even when it has no
            # direct members and no parent groups (typical for default project groups
            # like Build Administrators, Endpoint Creators, Readers in fresh projects).
            $headerRow = [PSCustomObject]@{
                ProjectName      = $projDisplayName
                GroupName        = $group.principalName
                GroupType        = $grpType
                GroupDescription = $grpDesc
                Relationship     = "GroupExists"
                MemberType       = "Group"
                DisplayName      = $group.displayName
                MailAddress      = $group.mailAddress
                PrincipalName    = $group.principalName
                Origin           = $group.origin
                ResolvedVia      = "Graph Groups API"
                Status           = $null
                LastAccessedDate = $null
            }
            $outputResult.Add($headerRow)

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