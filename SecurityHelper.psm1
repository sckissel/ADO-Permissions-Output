#
# FileName : SecurityHelper.psm1
# Date     : 03/20/2018
# Purpose  : This module provides functions to extract and report on Azure DevOps security permissions
#             by namespace, group, and user across one or more projects in an organization.
#

# Module-scoped log file path, set via Initialize-Log
$script:LogFilePath = $null

function Initialize-Log {
    <#
    .SYNOPSIS
        Sets the module-scoped log file path for Write-Log output.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogFilePath
    )
    $script:LogFilePath = $LogFilePath
}

function Write-Log {
    <#
    .SYNOPSIS
        Writes a timestamped log entry to both the console (Write-Host) and the log file.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [ValidateSet('Info','Warning','Error')]
        [string]$Level = 'Info',
        [string]$FunctionName = '',
        [string]$Uri = ''
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $logEntry = "[$timestamp] [$Level]"
    if ($FunctionName) { $logEntry += " [$FunctionName]" }
    $logEntry += " $Message"
    if ($Uri) { $logEntry += " | URI: $Uri" }

    # Console output (visible in pipeline logs)
    switch ($Level) {
        'Warning' { Write-Host $logEntry -ForegroundColor Yellow }
        'Error'   { Write-Host $logEntry -ForegroundColor Red }
        default   { Write-Host $logEntry }
    }

    # File output
    if ($script:LogFilePath) {
        $logEntry | Out-File -FilePath $script:LogFilePath -Append -Force
    }
}

function Invoke-AdoRestMethod {
    <#
    .SYNOPSIS
        Wrapper around Invoke-RestMethod with automatic retry logic for HTTP 429 (throttle)
        and transient server errors (500, 502, 503, 504).
    .DESCRIPTION
        Drop-in replacement for Invoke-RestMethod. Supports -ResponseHeaders ([ref]) for
        continuation-token pagination. Retries with exponential back-off on throttle/transient errors.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        [string]$Method = 'Get',
        [hashtable]$Headers,
        [string]$Body,
        [string]$ContentType,
        [ref]$ResponseHeaders,
        [int]$MaxRetries = 3,
        [int]$BaseRetrySeconds = 5
    )

    $attempt = 0
    while ($true) {
        $attempt++
        try {
            $params = @{
                Uri     = $Uri
                Method  = $Method
                Headers = $Headers
            }
            if ($Body) { $params['Body'] = $Body }
            if ($ContentType) { $params['ContentType'] = $ContentType }
            if ($ResponseHeaders) {
                $responseHeaders = $null
                $result = Invoke-RestMethod @params -ResponseHeadersVariable responseHeaders
                $ResponseHeaders.Value = $responseHeaders
            }
            else {
                $result = Invoke-RestMethod @params
            }
            return $result
        }
        catch {
            $statusCode = $null
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }

            if ($statusCode -eq 429 -and $attempt -le $MaxRetries) {
                $retryAfter = $BaseRetrySeconds
                try {
                    $retryHeader = $_.Exception.Response.Headers | Where-Object { $_.Key -eq 'Retry-After' }
                    if ($retryHeader) {
                        [int]::TryParse($retryHeader.Value, [ref]$retryAfter) | Out-Null
                    }
                } catch { }
                Write-Log -Message "HTTP 429 throttled. Retrying in ${retryAfter}s (attempt $attempt of $MaxRetries)." -Level 'Warning' -Uri $Uri
                Start-Sleep -Seconds $retryAfter
            }
            elseif ($statusCode -in @(500, 502, 503, 504) -and $attempt -le $MaxRetries) {
                $delay = $BaseRetrySeconds * $attempt
                Write-Log -Message "HTTP $statusCode transient error. Retrying in ${delay}s (attempt $attempt of $MaxRetries)." -Level 'Warning' -Uri $Uri
                Start-Sleep -Seconds $delay
            }
            else {
                # Non-retryable or retries exhausted - re-throw
                throw
            }
        }
    }
}

function Get-DescriptorFromGroup()
{
    Param(
        [Parameter(Mandatory = $true)]
        $dscriptor
    )

    $b64 = $dscriptor.Split('.')[1]

    # insert random '='
    $Length = $b64.Length
    $RandomChar = 1..($Length - 3) | Get-Random
    $Encoded = $b64.Insert($RandomChar,'=')

    # strip out '='
    $Stripped = $Encoded.Replace('=','')  

    # append appropriate padding
    $ModulusValue = ($Stripped.length % 4)   
        Switch ($ModulusValue) {
            '0' {$Padded = $Stripped}
            '1' {$Padded = $Stripped.Substring(0,$Stripped.Length - 1)}
            '2' {$Padded = $Stripped + ('=' * (4 - $ModulusValue))}
            '3' {$Padded = $Stripped + ('=' * (4 - $ModulusValue))}
        }

    try {
       # Write-Host "Descriptor : " $b64
       $dscrpt = ""
       $dscrpt = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($Padded))
    }
    catch {
        Write-Log -Message "Base64 decode error: $($_.Exception.Message)" -Level 'Error' -FunctionName 'Get-DescriptorFromGroup'
    }
   
    return $dscrpt
}

function Add-GroupInfo {
    param (
        $object, $name, $project, $descriptor, $fulldescriptor, $groupType
    )
    #check for CRLF in description
    $des = $object.description.replace("`n",", ").replace("`r",", ")

    $groupInfo = @{
        GroupName = $name
        Descriptor = $descriptor
        FullDescriptor = $fulldescriptor
        GroupDescriptor = $object.descriptor
        OriginId = $object.OriginId
        Description = $des
        Project = $project
        Url = $object.url
        GroupType = $groupType
    }
    return New-Object PSObject -Property $groupInfo
}

function Add-svcUserInfo {
    param (
        $object, $project, $fulldescriptor
    )

    $svcUserInfo = @{
        SvcUserName = $object.displayName
        Descriptor = $object.descriptor
        FullDescriptor = $fulldescriptor
        OriginId = $object.originId
        PrincipalName = $object.principalName
        Domain = $object.domain
        Project = $project
        Url = $object.url
    }
    return New-Object PSObject -Property $svcUserInfo
}

function Get-QueryFolderChildren {
    param (
        $userParams, $projectInfo, $authorization, $childQuery
    )
    try {
        $queryChildUri = $userParams.HTTP_preFix + "://dev.azure.com/" + $VSTSMasterAcct + "/" + $projectInfo.name + "/_apis/wit/queries/" + $childQuery.id + '?$depth=1&api-version=7.2'
        $queryChildren = Invoke-AdoRestMethod -uri $queryChildUri -Method Get -Headers $authorization
        foreach ($subChildQuery in $queryChildren.children) {
            $global:allQueries += $subChildQuery
            Write-Host "Obtaining token for '$($subChildQuery.Path)'."
            if ($subChildQuery.hasChildren -eq $true) {    
                Get-QueryFolderChildren -userParams $userParams -projectInfo $projectInfo -authorization $authorization -childQuery $subChildQuery
            }                    
        }
    }
    catch {
        Write-Log -Message "Error: $($_.Exception.Message)" -Level 'Error' -FunctionName $MyInvocation.MyCommand.Name
    }
}

function Get-IterationChildren {
    param (
        $object
    )
    foreach ($childIteration in $object) {
        $global:allIterations += $childiteration
        Write-Host "Obtaining token for $($childIteration.path)"
        if ($childIteration.hasChildren -eq $true) {
            Get-IterationChildren -object $childIteration.children
        }        
    }
}

function Get-AreaChildren {
    param (
        $object
    )
    foreach ($childArea in $object) {
        $global:allAreas += $childArea
        Write-Host "Obtaining token for $($childArea.path)"
        if ($childArea.hasChildren -eq $true) {
            Get-areaChildren -object $childArea.children
        }
    }    
}

function Get-TokenData {
    # NOTE: $VSTSMasterAcct and $authorization are inherited from the calling scope
    # (Get-SecuritybyGroupByNamespace). This is by design for PowerShell module scope
    # inheritance but means these helpers cannot be called independently.
    param (
        $userParams, $projectInfo, $Namespace, $Teams
    )

    #Switch to the correct Namespace to get the appropriate output
    switch ($Namespace.name) {
        'DashboardsPrivileges' {
            $allDashboards = @()
            try {
                # Get project Dashboards
                $prjDashboardUri = $userParams.HTTP_preFix + "://dev.azure.com/" + $VSTSMasterAcct + "/" + $projectInfo.name + "/_apis/dashboard/dashboards?api-version=7.2-preview.2"
                $prjDashboards = Invoke-AdoRestMethod -Uri $prjDashboardUri -Method Get -Headers $authorization
                foreach ($db in $prjDashboards.dashboardEntries) {
                    $dbObj = New-Object PSObject -Property @{
                        id = $db.id
                        name = $db.name
                        description = $db.description
                        scope = $db.dashboardScope
                    }
                    $allDashboards += $dbObj
                }                
            } catch {
                Write-Log -Message "Error: $($_.Exception.Message)" -Level 'Error' -FunctionName $MyInvocation.MyCommand.Name
            }
            # Get all Teams in the project
            $prjTeams = $Teams | Where-Object { $_.projectName -eq $projectInfo.name}                
            foreach ($prjTeam in $prjTeams) {
                try {
                    # Get all project Team Dashboards
                    $teamsDashboardUri = $userParams.HTTP_preFix + "://dev.azure.com/" + $VSTSMasterAcct + "/" + $projectInfo.name + "/" + $prjTeam.id + "/_apis/dashboard/dashboards?api-version=7.2-preview.2"
                    $teamDashboards = Invoke-AdoRestMethod -Uri $teamsDashboardUri -Method Get -Headers $authorization
                    foreach ($db in $teamDashboards.dashboardEntries) {
                        $dbObj = New-Object PSObject -Property @{
                            id = $db.id
                            name = $db.name
                            description = $db.description
                            scope = $db.dashboardScope
                        }
                        $allDashboards += $dbObj
                    }                    
                } catch {
                    Write-Log -Message "Error: $($_.Exception.Message)" -Level 'Error' -FunctionName $MyInvocation.MyCommand.Name
                }
            }
            return $allDashboards
            # Project: $Token = "`$/" + $projectInfo.id + "/" + "00000000-0000-0000-0000-000000000000"
            # Project Dashboard: $Token = "`$/" + $projectInfo.id + "/00000000-0000-0000-0000-000000000000/" + $prjDashboards.dashboardEntries.id (FOR EACH)
            # Overall Team Dashoard?: $Token = "`$/" + $projectInfo.id + "/" $prjTeam.Id
            # Dashboards under each Team: $Token = "`$/" + $projectInfo.id + "/" $prjTeam.Id + "/" $teamDashboards.dashboardEntries.id (FOR EACN)
        }
        'Build' {
            try {
                # Get project Build definitions
                $prjBuildsUri = $userParams.HTTP_preFix + "://dev.azure.com/" + $VSTSMasterAcct + "/" + $projectInfo.name + "/_apis/build/definitions?api-version=7.2"
                $prjBuilds = Invoke-AdoRestMethod -uri $prjBuildsUri -Method Get -Headers $authorization
            } catch {
                Write-Log -Message "Error: $($_.Exception.Message)" -Level 'Error' -FunctionName $MyInvocation.MyCommand.Name
            }
            if ($prjBuilds.count -lt 1) {
                return "N/A"
            }
            else {
                return $prjBuilds.value
            }           
        }
        'VersionControlItems'   {
            try {
                # Get project TFS Repos
                $prjRepoUri = $userParams.HTTP_preFix + "://dev.azure.com/" + $VSTSMasterAcct + "/" + $projectInfo.name + "/_apis/git/repositories"
                $prjRepos = Invoke-AdoRestMethod -uri $prjRepoUri -Method Get -Headers $authorization
            }
            catch {
                Write-Log -Message "Error: $($_.Exception.Message)" -Level 'Error' -FunctionName $MyInvocation.MyCommand.Name
            }
            return $prjRepos.value
        }
        'BoardsExternalIntegration' {
            return "N/A"
        }
        'Discussion Threads' {
            return "N/A"
        }
        'Workspaces' {
            return "N/A"
        }
        'VersionControlPrivileges' {
            return "N/A"
        }
        'BuildAdministration' {
            return "N/A"
        }
        'Server' {
            return "N/A"
        }
        'WorkItemQueryFolders' {
            $global:allQueries = @()
            try {
                # Get Shared Queries root folder
                $queryFolderUri = $userParams.HTTP_preFix + "://dev.azure.com/" + $VSTSMasterAcct + "/" + $projectInfo.name + '/_apis/wit/queries?api-version=7.2'
                $queryFolders = Invoke-AdoRestMethod -uri $queryFolderUri -Method Get -Headers $authorization
                $baseFolder = $queryFolders.value | Where-Object { $_.name -eq "Shared Queries"}
                $global:allQueries += $baseFolder
                if ($baseFolder.hasChildren -eq $true) {                    
                    Get-QueryFolderChildren -userParams $userParams -projectInfo $projectInfo -authorization $authorization -childQuery $baseFolder                    
                }
            }
            catch {
                Write-Log -Message "Error: $($_.Exception.Message)" -Level 'Error' -FunctionName $MyInvocation.MyCommand.Name
            }
            return $global:allQueries
            
        }
        'Iteration' {
            $global:allIterations = @()
            try {
                $iterationUri = $userParams.HTTP_preFix + "://dev.azure.com/" + $VSTSMasterAcct + "/" + $projectInfo.name + '/_apis/wit/classificationnodes/iterations?$depth=20&errorPolicy=omit&api-version=7.2'
                $iterations = Invoke-AdoRestMethod -uri $iterationUri -Method Get -Headers $authorization
            }
            catch {
                Write-Log -Message "Error: $($_.Exception.Message)" -Level 'Error' -FunctionName $MyInvocation.MyCommand.Name
            }            
            foreach ($iteration in $iterations) {
                $global:allIterations += $iteration
                Write-Host "Obtaining token for $($iteration.path)"
                if ($iteration.hasChildren -eq $true) {
                    Get-IterationChildren -object $iteration.children
                }
            }
            return $global:allIterations
        }
        'MetaTask' {
            try {
                $metaTaskUri = $userParams.HTTP_preFix + "://dev.azure.com/" + $VSTSMasterAcct + "/" + $projectInfo.name + '/_apis/distributedtask/taskgroups?api-version=7.2-preview.1'
                $metaTasks = Invoke-AdoRestMethod -uri $metaTaskUri -Method Get -Headers $authorization
            }
            catch {
                Write-Log -Message "Error: $($_.Exception.Message)" -Level 'Error' -FunctionName $MyInvocation.MyCommand.Name
            }
            if ($metaTasks.count -lt 1) {
                return "N/A"
            }
            else {
                return $metaTasks.value
            }
            
        }
        'Tagging' {
            return "N/A"
        }
        'CSS' { # Area Paths
            $global:allareas = @()
            try {
                $areaUri = $userParams.HTTP_preFix + "://dev.azure.com/" + $VSTSMasterAcct + "/" + $projectInfo.name + '/_apis/wit/classificationnodes/areas?$depth=20&errorPolicy=omit&api-version=7.2'
                $areas = Invoke-AdoRestMethod -uri $areaUri -Method Get -Headers $authorization
            }
            catch {
                Write-Log -Message "Error: $($_.Exception.Message)" -Level 'Error' -FunctionName $MyInvocation.MyCommand.Name
            }            
            foreach ($area in $areas) {
                $global:allareas += $area
                Write-Host "Obtaining token for $($area.path)"
                if ($area.hasChildren -eq $true) {
                    Get-AreaChildren -object $area.children
                }
            }
            return $global:allareas
        }
        'EventSubscriber' {
            return "N/A"
        }
        'Project' {
            return "N/A"
        }
        'Environment' {
            try {
                $environmentUri = $userParams.HTTP_preFix + "://dev.azure.com/" + $VSTSMasterAcct + "/" + $projectInfo.name + '/_apis/distributedtask/environments?api-version=7.2-preview.1'
                $environments = Invoke-AdoRestMethod -uri $environmentUri -Method Get -Headers $authorization
            }
            catch {
                Write-Log -Message "Error: $($_.Exception.Message)" -Level 'Error' -FunctionName $MyInvocation.MyCommand.Name
            }
            if ($environments.count -eq 0) {
                return "N/A"
            }
            else {
                return $environments.value
            }   
            
        }
        'Library' {
            $libraryTokens = @()
            try {
                $libraryUri = $userParams.HTTP_preFix + "://dev.azure.com/" + $VSTSMasterAcct + "/" + $projectInfo.name + '/_apis/distributedtask/variablegroups?api-version=7.2-preview.2'
                $libraries = Invoke-AdoRestMethod -uri $libraryUri -Method Get -Headers $authorization
                $libraryTokens += $libraries.value
            }
            catch {
                Write-Log -Message "Error: $($_.Exception.Message)" -Level 'Error' -FunctionName $MyInvocation.MyCommand.Name
            }
            try {
                $secureFilesUri = $userParams.HTTP_preFix + "://dev.azure.com/" + $VSTSMasterAcct + "/" + $projectInfo.name + '/_apis/distributedtask/securefiles?api-version=7.2-preview.1'
                $secureFiles = Invoke-AdoRestMethod -uri $secureFilesUri -Method Get -Headers $authorization
                $libraryTokens += $secureFiles.value
            }
            catch {
                Write-Log -Message "Error: $($_.Exception.Message)" -Level 'Error' -FunctionName $MyInvocation.MyCommand.Name
            }
            if ($libraryTokens.count -lt 1) {
                return "N/A"
            }
            else {
                return $libraryTokens
            }            
        }
        'AccountAdminSecurity' {
            return "N/A"
        }
        'Process' {
            try {
                $processUri = $userParams.HTTP_preFix + "://dev.azure.com/" + $VSTSMasterAcct + '/_apis/work/processes?api-version=7.2-preview.2'
                $processes = Invoke-AdoRestMethod -uri $processUri -Method Get -Headers $authorization
            }
            catch {
                Write-Log -Message "Error: $($_.Exception.Message)" -Level 'Error' -FunctionName $MyInvocation.MyCommand.Name
            }
            return $processes.value
        }
        'Plan' {
            try {
                $plansUri = $userParams.HTTP_preFix + "://dev.azure.com/" + $VSTSMasterAcct + "/" + $projectInfo.name + '/_apis/work/plans?api-version=7.2-preview.1'
                $plans = Invoke-AdoRestMethod -uri $plansUri -Method Get -Headers $authorization
            }
            catch {
                Write-Log -Message "Error: $($_.Exception.Message)" -Level 'Error' -FunctionName $MyInvocation.MyCommand.Name
            }
            if ($plans.count -lt 1) {
                return "N/A"
            }
            else {
                return $plans.value
            }
            
        }
        'Collection' {
            return "N/A"
        }
        'ServiceHooks' {
            return "N/A"
        }
        'ServiceEndpoints' {
            try {
                $serviceEndpointsUri = $userParams.HTTP_preFix + "://dev.azure.com/" + $VSTSMasterAcct + "/" + $projectInfo.name + '/_apis/serviceendpoint/endpoints?api-version=7.2-preview.4'
                $serviceEndpoints = Invoke-AdoRestMethod -uri $serviceEndpointsUri -Method Get -Headers $authorization
            }
            catch {
                Write-Log -Message "Error: $($_.Exception.Message)" -Level 'Error' -FunctionName $MyInvocation.MyCommand.Name
            }
            if ($serviceEndpoints.count -lt 1) {
                return "N/A"
            }
            else {
                return $serviceEndpoints.value
            }
        }
        'EventSubscriber' {
            return "N/A"
        }
        'Git Repositories' {
            try {
                # Get project TFS Repos
                $prjRepoUri = $userParams.HTTP_preFix + "://dev.azure.com/" + $VSTSMasterAcct + "/" + $projectInfo.name + "/_apis/git/repositories"
                $prjRepos = Invoke-AdoRestMethod -uri $prjRepoUri -Method Get -Headers $authorization
            }
            catch {
                Write-Log -Message "Error: $($_.Exception.Message)" -Level 'Error' -FunctionName $MyInvocation.MyCommand.Name
            }
            return $prjRepos.value
        }
        'DistributedTask' {
            try {
                $distributedTaskUri = $userParams.HTTP_preFix + "://dev.azure.com/" + $VSTSMasterAcct + "/_apis/distributedtask/pools?api-version=7.2-preview.1"
                $distributedTasks = Invoke-AdoRestMethod -uri $distributedTaskUri -Method Get -Headers $authorization
            }
            catch {
                Write-Log -Message "Error: $($_.Exception.Message)" -Level 'Error' -FunctionName $MyInvocation.MyCommand.Name
            }
            return $distributedTasks.value
        }
        'WorkItemTrackingAdministration' {
            return "N/A"
        }
        'Identity' {
            return "N/A"
        }
        'AuditLog' {
            return "N/A"
        }
        'ReleaseManagement' {
            if ($namespace.namespaceId -eq 'c788c23e-1b46-4162-8f5e-d7585343b5de') {
                try {
                    $releaseManagementUri = $userParams.HTTP_preFix + "://vsrm.dev.azure.com/" + $VSTSMasterAcct + "/"  + $projectInfo.name + "/_apis/release/definitions?api-version=7.2-preview.4"
                    $releaseManagement = Invoke-AdoRestMethod -uri $releaseManagementUri -Method Get -Headers $authorization
                }
                catch {
                    Write-Log -Message "Error: $($_.Exception.Message)" -Level 'Error' -FunctionName $MyInvocation.MyCommand.Name
                }
                if ($releaseManagement.count -lt 1) {
                    return "N/A"
                }
                else {
                    return $releaseManagement.value
                }
            }
            else {
                return "N/A"
            }            
        }
        'AnalyticsViews' {
            try {
                $analyticsViewsUri = $userParams.HTTP_preFix + "://analytics.dev.azure.com/" + $VSTSMasterAcct + "/"  + $projectInfo.name + "/_apis/Analytics/Views"
                $analyticsViews = Invoke-AdoRestMethod -uri $analyticsViewsUri -Method Get -Headers $authorization
            }
            catch {
                Write-Log -Message "Error: $($_.Exception.Message)" -Level 'Error' -FunctionName $MyInvocation.MyCommand.Name
            }
            return $analyticsViews.value
        }
        'Analytics' {
            return "N/A"
        }
    }        
}

#
# this function will get all the namespace permissions for each user and group
#
function Get-SecuritybyGroupByNamespace()
{
    Param(
        [Parameter(Mandatory = $true)]
        $userParams,
        [Parameter(Mandatory = $true)]
        $outFileName,
        [Parameter(Mandatory= $false)]
        $getAllProjects,
        [Parameter(Mandatory= $false)]
        $rawDataDump,
        [Parameter(Mandatory=$true)]
        $dirRoot,
        [Parameter(Mandatory = $true)]
        $PAT,
        [Parameter(Mandatory = $true)]
        $VSTSMasterAcct,
        [Parameter(Mandatory = $true)]
        $projectName,
        [Parameter(Mandatory = $false)]
        [ValidateSet('JSON','CSV','Both')]
        [string]$OutputFormat = 'JSON'
    )

    # Base64-encodes the Personal Access Token (PAT) appropriately
    $authorization = GetVSTSCredential -Token $PAT

    # get list of all security namespaces for organization
    # https://docs.microsoft.com/en-us/rest/api/azure/devops/security/security%20namespaces/query?view=azure-devops-rest-6.1
    # GET https://dev.azure.com/{organization}/_apis/securitynamespaces/{securityNamespaceId}?api-version=7.2-preview.1
    $nsUri = $userParams.HTTP_preFix  + "://dev.azure.com/" + $VSTSMasterAcct + "/_apis/securitynamespaces?api-version=7.2-preview.1"
    $allNamespaces = Invoke-AdoRestMethod -Uri $nsUri -Method Get -Headers $authorization 
        
    # find all Teams in Org (paginated). Needed to determine if group is a team or group
    # GET https://dev.azure.com/{organization}/_apis/teams?api-version=7.2-preview.3        
    $teamsList = @()
    $teamSkip = 0
    $teamBatchSize = 1000
    do {
        $tmUrl = $userParams.HTTP_preFix  + "://dev.azure.com/" + $VSTSMasterAcct + "/_apis/teams?`$top=$teamBatchSize&`$skip=$teamSkip&api-version=7.2-preview.3"
        $teamBatch = Invoke-AdoRestMethod -Uri $tmUrl -Method Get -Headers $authorization
        $teamsList += $teamBatch.value
        $teamSkip += $teamBatchSize
    } while ($teamBatch.value.Count -eq $teamBatchSize)
    $allTeams = [PSCustomObject]@{ value = $teamsList }
    Write-Log -Message "Fetched $($teamsList.Count) teams" -Level 'Info' -FunctionName 'Get-SecuritybyGroupByNamespace'
    
    # get all groups (vssgp AND aadgp) in org. Do NOT filter by subjectTypes on the first
    # page: doing so silently drops AAD groups that are directly ACL'd on a project, and
    # those groups do appear in the Project Settings > Permissions UI.
    $projectUri = $userParams.HTTP_preFix  + "://vssps.dev.azure.com/" + $VSTSMasterAcct + "/_apis/graph/groups?api-version=7.2-preview.1"

    $uri = $projectUri
    $allGroups = @()
    do {
        Write-Output "Calling API to acquire all groups in batches..."
        $headers = $null
        $response = Invoke-AdoRestMethod -Uri $uri -Method Get -Headers $authorization -ResponseHeaders ([ref]$headers)
        $allGroups += $response.value

        if ($headers -and $headers["x-ms-continuationtoken"]) {
            $continuation = $headers["x-ms-continuationtoken"]
            $uri = $projectUri + "&continuationToken=" + [System.Uri]::EscapeDataString($continuation)
        }
    } while ($headers -and $headers["x-ms-continuationtoken"])

    # Get all projects in the organization
    $orgUri = $userParams.HTTP_preFix + "://dev.azure.com/" + $VSTSMasterAcct + "/_apis/projects?api-version=7.2"
    $orgProjects = Invoke-AdoRestMethod -uri $orgUri -Method Get -Headers $authorization 

    if( $getAllProjects -eq "True")
    {
        $groups = $allGroups
        $projectDetails = $orgProjects.Value
    }else {
        # find all groups for given project (supports comma-separated list)
        $groups = $allGroups 
        $projectNames = $projectName -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        $projectDetails = $orgProjects.value | Where-Object { $_.Name -in $projectNames }
        if ($projectNames.Count -gt 0 -and ($null -eq $projectDetails -or @($projectDetails).Count -eq 0)) {
            $requested = $projectNames -join ', '
            Write-Log -Message "No Azure DevOps projects matched the requested project filter(s): $requested" -Level 'Error' -FunctionName 'Get-SecuritybyGroupByNamespace'
            throw "No matching Azure DevOps projects were found for the requested project name(s): $requested"
        }
    }

    # Per-project scope-descriptor group fetch. The org-wide graph/groups call does not
    # reliably return built-in well-known project groups (Project Administrators,
    # Contributors, Readers, Build Administrators, Endpoint Admins/Creators,
    # Release Admins, Project Valid Users). Union those into $groups so $allGroupInfo
    # has full descriptor coverage for ACL name resolution.
    $existingDescriptors = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($g in $groups) { if ($g.descriptor) { [void]$existingDescriptors.Add($g.descriptor) } }
    foreach ($projDetail in $projectDetails) {
        $scopeUri = $userParams.HTTP_preFix + "://vssps.dev.azure.com/" + $VSTSMasterAcct + "/_apis/graph/descriptors/" + $projDetail.id + "?api-version=7.2-preview.1"
        try {
            $scopeResp = Invoke-AdoRestMethod -Uri $scopeUri -Method Get -Headers $authorization
            $scope = $scopeResp.value
        }
        catch {
            Write-Log -Message "Failed to resolve scope descriptor for project $($projDetail.name): $($_.Exception.Message)" -Level 'Warning' -FunctionName 'Get-SecuritybyGroupByNamespace' -Uri $scopeUri
            continue
        }
        if (-not $scope) { continue }

        $scopedGroupsBaseUri = $userParams.HTTP_preFix + "://vssps.dev.azure.com/" + $VSTSMasterAcct + "/_apis/graph/groups?scopeDescriptor=" + [System.Uri]::EscapeDataString($scope) + "&api-version=7.2-preview.1"
        $sgUri = $scopedGroupsBaseUri
        $added = 0
        do {
            $sgHeaders = $null
            try {
                $sgResp = Invoke-AdoRestMethod -Uri $sgUri -Method Get -Headers $authorization -ResponseHeaders ([ref]$sgHeaders)
            }
            catch {
                Write-Log -Message "Scoped group fetch failed for project $($projDetail.name): $($_.Exception.Message)" -Level 'Warning' -FunctionName 'Get-SecuritybyGroupByNamespace' -Uri $sgUri
                break
            }
            foreach ($g in $sgResp.value) {
                if ($g.descriptor -and $existingDescriptors.Add($g.descriptor)) {
                    $groups += $g
                    $added++
                }
            }
            if ($sgHeaders -and $sgHeaders["x-ms-continuationtoken"]) {
                $sgUri = $scopedGroupsBaseUri + "&continuationToken=" + [System.Uri]::EscapeDataString($sgHeaders["x-ms-continuationtoken"])
            }
        } while ($sgHeaders -and $sgHeaders["x-ms-continuationtoken"])
        Write-Log -Message "Unioned $added scoped groups for project $($projDetail.name)" -Level 'Info' -FunctionName 'Get-SecuritybyGroupByNamespace'
    }

    $allGroupInfo = @()
    # loop thru each group
    foreach ($fnd in $groups) {

        # find out if this is a team or project
        $prName = $fnd.principalName.Split('\')
        $pName =  $prName[0].substring(1,$prname[0].length-2)
        $tm = $prName[1]
        $teamFound = $allteams.value | Where-Object {($_.ProjectName -eq $pName) -and ($_.name -eq $tm)}
        If (![string]::IsNullOrEmpty($teamFound)) {
            $grpType = "Team"
            $teamDescriptor = Get-DescriptorFromGroup -dscriptor $fnd.descriptor
            $dscrpt = "Microsoft.TeamFoundation.Identity;" + $teamDescriptor
            $groupInfo = Add-GroupInfo -object $fnd -name $tm -project $pName -descriptor $teamDescriptor -fulldescriptor $dscrpt -groupType $grpType
            $allGroupInfo += $groupInfo
        } else { 
            # Coalesce all Group info into another Object with the descriptor
            $grpType = "Group"
            $groupDescriptor = Get-DescriptorFromGroup -dscriptor $fnd.descriptor
            $dscrpt = "Microsoft.TeamFoundation.Identity;" + $groupDescriptor
            if ($pName -eq "TEAM FOUNDATION") {
                $groupInfo = Add-GroupInfo -object $fnd -name $fnd.PrincipalName -project $pName -descriptor $groupDescriptor -fulldescriptor $dscrpt -groupType $grpType
            }
            else {
                $groupInfo = Add-GroupInfo -object $fnd -name $tm -project $pName -descriptor $groupDescriptor -fulldescriptor $dscrpt -groupType $grpType
            }            
            $allGroupInfo += $groupInfo
        }
    }  

    # get all users
    $usersUri = $userParams.HTTP_preFix  + "://vssps.dev.azure.com/" + $VSTSMasterAcct + "/_apis/graph/users?api-version=7.2-preview.1"
    $uri = $usersUri
    $allUsers = @()
    do {
        Write-Output "Calling API to acquire all users in batches..."
        $headers = $null
        $response = Invoke-AdoRestMethod -Uri $uri -Method Get -Headers $authorization -ResponseHeaders ([ref]$headers)
        $allUsers += $response.value
        
        if ($headers -and $headers["x-ms-continuationtoken"]) {
            $continuation = $headers["x-ms-continuationtoken"]
            $uri = $usersUri + "&continuationToken=" + [System.Uri]::EscapeDataString($continuation)
        }
    } while ($headers -and $headers["x-ms-continuationtoken"])

    $today = Get-Date -Format "MM-dd-yyyy"

    # list of namespaces that are deprecated or do not exist as output to this code as the value returned was 0 ACLs to the namespace.
    $noNamespaces = "ServicingOrchestration","IdentityPicker","Security","Social","DataProvider","WorkItemTrackingConfiguration","CrossProjectWidgetView","WebPlatform","WorkItemsHub","Location","SettingEntries","Test Management","StrongBox","WorkItemTracking","Job","ViewActivityPaneSecurity","Graph","Registry","Favorites","ProjectAnalysisLanguageMetrics","TeamLabSecurity","Proxy","VersionControlItems2","UtilizationPermissions","OrganizationalLevelData","EventPublish","EventSubscription","WorkItemTrackingProvision","PipelineCachePrivileges","ExtensionManagement"
    # Loop through each project, if multiple
    foreach ($projectDetail in $projectDetails) {
        # Coalesce all service users into another object with the descriptor
        $allSvcUsers = @()
        foreach ($userFound in $allUsers) {
            if ($userFound.descriptor -like "svc.*") {
                $svcUserDescriptor = Get-DescriptorFromGroup -dscriptor $userFound.descriptor
                $dscrpt = "Microsoft.TeamFoundation.ServiceIdentity;" + $svcUserDescriptor
                $svcUserInfo = Add-svcUserInfo -object $userFound -project -$projectDetail.Name -fulldescriptor $dscrpt
                $allSvcUsers += $svcUserInfo
            }
        }

        Write-Log -Message "Project Name: $($projectDetail.name)" -Level 'Info' -FunctionName 'Get-SecuritybyGroupByNamespace'
        Write-Log -Message "Project Description: $($projectDetail.description)" -Level 'Info' -FunctionName 'Get-SecuritybyGroupByNamespace'

        # set output file directory and name (JSON output)
        $outFile = $dirRoot + $userParams.SecurityDir + $($projectDetail.name) + "_" + $today + "_" + ($outFileName -replace '\.txt$', '.json')
        Write-Log -Message "OutFile: $outFile" -Level 'Info' -FunctionName 'Get-SecuritybyGroupByNamespace'
        $allPermissions = [System.Collections.Generic.List[PSObject]]::new()
        
        #get Direct permissions
        # find namespace for given category or all categories
        $toDoNamespaces = @()
        if ( 'All' -in $userParams.Namespaces ) {
            foreach ($nsValue in $allNamespaces.value) {
                if ($nsValue.Name -notin $noNamespaces) {
                    $toDoNamespaces += $nsValue
                }
            }
        }else {
            $tempNamespaces = $allNamespaces.value | Where-Object {$_.Name -in $userParams.Namespaces }
            foreach ($nsValue in $tempNamespaces) {
                if ($nsValue.Name -notin $noNamespaces) {
                    $toDoNamespaces += $nsValue
                }
            }            
        }
        foreach ($namespace in $toDoNamespaces) {
            Write-Log -Message "Namespace: $($namespace.Name)" -Level 'Info' -FunctionName 'Get-SecuritybyGroupByNamespace'
            # Get the details for each token (Name, etc) to be matched and output
            $tokenDetails = Get-TokenData -userParams $userParams -projectInfo $projectDetail -Namespace $namespace -Teams $allteams.value
            # Get the permissions for the namespace
            $nsPermissions = Get-PermissionsByNamespace -Namespace $namespace -userParams $userParams -projectInfo $projectDetail -groupInfo $allGroupInfo -users $allUsers -tokenData $tokenDetails -rawDataDump $rawDataDump -outFile $outFile -dirRoot $dirRoot -VSTSMasterAcct $VSTSMasterAcct
            if ($nsPermissions) {
                $allPermissions.AddRange([PSObject[]]$nsPermissions)
            }
        }

        # Write accumulated permissions as JSON and/or CSV
        if ($allPermissions.Count -gt 0) {
            if ($OutputFormat -in @('JSON','Both')) {
                $allPermissions | ConvertTo-Json -Depth 10 | Out-File -FilePath $outFile -Force
                Write-Log -Message "Wrote $($allPermissions.Count) permission entries to $outFile" -Level 'Info' -FunctionName 'Get-SecuritybyGroupByNamespace'
            }
            if ($OutputFormat -in @('CSV','Both')) {
                $csvFile = $outFile -replace '\.json$', '.csv'
                $allPermissions | Export-Csv -Path $csvFile -NoTypeInformation -Force
                Write-Log -Message "Wrote $($allPermissions.Count) permission entries to $csvFile" -Level 'Info' -FunctionName 'Get-SecuritybyGroupByNamespace'
            }
        }
    }
}
       
Function Get-PermissionsByNamespace()
{
    #
    #   this function will get the list of permissions for a given group.
    #   it will get either the direct or extended permissions. In order to get all the permissions
    #   you need to first get the direct permissions and then the extended permissions for each group the
    #   primary group is a memeber of.
    #
    Param(
        [Parameter(Mandatory = $true)]
        $Namespace,
        [Parameter(Mandatory = $true)]
        $userParams,
        [Parameter(Mandatory = $true)]
        $projectInfo,
        [Parameter(Mandatory = $true)]
        $groupInfo,
        [Parameter(Mandatory = $true)]
        $users,
        [Parameter(Mandatory = $true)]
        $tokenData,
        [Parameter(Mandatory = $true)]
        $rawDataDump,
        [Parameter(Mandatory = $true)]
        $outFile,
        [Parameter(Mandatory = $false)]
        $GroupMember,
        [Parameter(Mandatory = $true)]
        $VSTSMasterAcct,
        [Parameter(Mandatory = $true)]
        $dirRoot      
    )

    $projName = $projectInfo.name
    $projectId = $projectInfo.id

    $inheritFrom = ""
    if (![string]::IsNullOrEmpty($GroupMember) )    
    {
        # get descriptor for the group   
        $dscrpt =  Get-DescriptorFromGroup -dscriptor $GroupMember.Descriptor
        $dscrpt = "Microsoft.TeamFoundation.Identity;" + $dscrpt      
        $inheritFrom = $GroupMember.principalName
    }
   
    # find all access control lists for the given namespace and group
    # loop thru each namespace in the list and get security

    # Work on namespace
    $ns =  $Namespace

    $aclListByNamespace = ""
    $permissions = [System.Collections.Generic.List[PSObject]]::new()

    # find all access control lists for the given namespace and group
    try {
        $grpUri = $userParams.HTTP_preFix  + "://dev.azure.com/" + $VSTSMasterAcct + "/_apis/accesscontrollists/" + $ns.namespaceId + "?includeExtendedInfo=True&recurse=True&api-version=7.2-preview.1"
        $aclListByNamespace = Invoke-AdoRestMethod -Uri $grpUri -Method Get -Headers $authorization 
    }
    catch {
        Write-Log -Message "Error in namespace $($ns.name): $($_.Exception.Message)" -Level 'Error' -FunctionName 'Get-PermissionsByNamespace' -Uri $grpUri
    }
    
    $tokenMatches = @()
    # Given the tokenData, which contains all the namespace objects for the project...
    foreach ($obj in $tokenData) {
        switch ($ns.name) {
            'DashboardsPrivileges' {
                $tokenMatches += $aclListByNamespace.value | Where-Object { $_.token -like "*$($obj.id)*" }
            }
            'Build' {
                #aclMatch
                if ($obj.uri) {
                    $defId = $obj.uri.split('/')[-1]
                    $tokenMatches += $aclListByNamespace.value | Where-Object { $_.token -like "$projectId/$defId" }
                }
            }
            'VersionControlItems' {
                $tokenMatches += $aclListByNamespace.value | Where-Object { $_.token -eq "`$/$projName"}
            }
        }
    } 

    # loop thru acesDictionary in namespace and find security not found in token Data (i.e. all Build security)
    foreach ($aclToken in $aclListByNamespace.value) {
        # DO MEMEORY MATCHING HERE: Loop through each token, find in tokenData, output results (This gives us the matched name)
        $match = $false
        switch ($ns.name) {
            'DashboardsPrivileges' {
                if ($aclToken.token -like "`$/$projectId/00000000-0000-0000-0000-000000000000/*") {
                    # Individual Project Dashboards Permissions
                    $tokenMatches.token | ForEach-Object {
                        if ($aclToken.token -eq $_) {
                            $match = $true
                            $matchComponent = ($tokenData | Where-Object { $_.Id -eq $aclToken.token.split('/')[-1] }).name
                            $matchName = "'$matchComponent' - Project Dashboard"
                            Write-Host "TokenData Match: $matchName"
                        }
                    }                    
                } elseif ($aclToken.token -eq "`$/$projectId/00000000-0000-0000-0000-000000000000") {
                    # Project Dashboards Overall Permissions
                    $match = $true
                    $matchName = "'$projName' - General Project Dashboard"                  
                } elseif (($aclToken.token -like "`$/$projectId/*") -and ($aclToken.token -notlike "`$/$projectId/00000000-0000-0000-0000-00000000000*")) { # Team Dashboards
                    $aclTokenSplit = $aclToken.token.split('/')
                    $teamGrpName = ($groupInfo | Where-Object { $_.OriginId -eq $aclTokenSplit[2] }).GroupName
                    if ($aclTokenSplit.count -eq 4) {
                        # Individual Team Dashboards Permissions
                        $tokenMatches.Token | ForEach-Object {
                            $match = $true
                            $matchComponent = ($tokenData | Where-Object { $_.Id -eq $aclTokenSplit[-1] }).name
                            $matchName = "'$matchComponent' - '$TeamGrpName' - Team Dashboard"
                            Write-Host "TokenData Match: $matchName"
                        }                            
                    } else {
                        # Team Dashboards Overpall Permissions
                        $match = $true
                        $matchName = "'$teamGrpName' - General Team Dashboard"
                    }
                }
            } 
            'Build' {
                if ($aclToken.token -eq $projectId) {
                    $match = $true
                    $matchName = "$projName - General Project Build"
                    Write-Host "non-tokenData ACL match: $matchName"                    
                } elseif ($aclToken.token -in $tokenMatches.token) {
                    $match = $true
                    $matchName = $tokenData.Name
                    Write-Host "TokenData Match: $matchName"
                }                           
            }
            'VersionControlItems' {
                if (($aclToken.token -eq "`$/$projName") -and ($aclToken.token -in $tokenMatches.token)) {
                    $match = $true
                    $matchName = "$/$projName"
                    Write-Host "TokenData Match: $matchName"
                } elseif ($aclToken.token -eq "`$") {
                    $match = $true
                    $matchName = "Default TFS Org Permissions"
                    Write-Host "non-tokenData ACL match: $matchName"  
                }
            }
            'BoardsExternalIntegration' {
                if ($aclToken.token -eq "`$/$projectId") {
                    $match = $true
                    $matchName = "'$projName' - Project Boards External Integration"
                    Write-Host "non-tokenData ACL match: $matchName"
                }
            }
            'Discussion Threads' {
                if ($aclToken.token -eq "") {
                    $match = $true
                    $matchName = "Org discussion threads"
                    Write-Host "non-tokenData ACL match: $matchName"
                }
            }
            'Workspaces' {
                if ($aclToken.token -eq "") {
                    $match = $true
                    $matchName = "Org Workspaces"
                    Write-Host "non-tokenData ACL match: $matchName"
                }
            }
            'VersionControlPrivileges' {
                if ($aclToken.token -eq "Global") {
                    $match = $true
                    $matchName = "Org Version Control Privileges"
                    Write-Host "non-tokenData ACL match: $matchName"
                }
            }
            'BuildAdministration' {
                if ($aclToken.token -eq "BuildPrivileges") {
                    $match = $true
                    $matchName = "Org Build Administration"
                    Write-Host "non-tokenData ACL match: $matchName"
                }
            }
            'Server' {
                if ($aclToken.token -eq "FrameworkGlobalSecurity") {
                    $match = $true
                    $matchName = "Org Server"
                    Write-Host "non-tokenData ACL match: $matchName"
                }
            }
            'WorkItemQueryFolders' {
                if ($aclToken.token -eq "`$") {
                    $match = $true
                    $matchName = "Org Shared Queries"
                    Write-Host "non-tokenData ACL match: $matchName"
                }
                elseif ($aclToken.token -like "`$/$projectId/*") {
                    $aclTokenSplit = $aclToken.token.split('/')
                    $matchName = ($tokenData | Where-Object { $_.Id -eq $aclTokenSplit[-1] }).path
                    if ($matchName) {
                        $match = $true
                        Write-Host "TokenData Match: $matchName"
                    }
                }
            }
            'Iteration' {
                $aclTokenSplit = $aclToken.token.split('vstfs:///Classification/Node/').replace(':','')
                $matchName = ($tokenData | Where-Object { $_.Identifier -eq $aclTokenSplit[-1] }).path
                if ($matchName) {
                    $match = $true
                    Write-Host "TokenData Match: $matchName"
                }
            }
            'MetaTask' {
                if ($aclToken.token -eq $projectId) {
                    $match = $true
                    $matchName = "$projName - Project"
                    Write-Host "TokenData Match: $matchName"
                }
                elseif ($aclToken.token -like "$projectId/*") {
                    $aclTokenSplit = $aclToken.token.split('/')
                    $match = $true
                    $matchName = ($tokenData | Where-Object { $_.Id -eq $aclTokenSplit[-1] }).name
                    Write-Host "TokenData Match: $matchName"
                }
            }
            'Tagging' {
                if ($aclToken.token -eq "") {
                    $match = $true
                    $matchName = "Org tagging privileges"
                    Write-Host "non-tokenData ACL match: $matchName"
                }
                elseif ($aclToken.token -eq "/$projectId") {
                    $match = $true
                    $matchName = "$projName - Project"
                    Write-Host "non-tokenData ACL match: $matchName"
                }
            }
            'CSS' {
                $aclTokenSplit = $aclToken.token.split('vstfs:///Classification/Node/').replace(':','')
                $matchName = ($tokenData | Where-Object { $_.Identifier -eq $aclTokenSplit[-1] }).path
                if ($matchName) {
                    $match = $true
                    Write-Host "TokenData Match: $matchName"
                }
            }
            'EventSubscriber' {
                if ($aclToken.token -eq '$SUBSCRIBER') {
                    $match = $true
                    $matchName = 'Org EventSubscriber $SUBSCRIBER' 
                    Write-Host "non-tokenData ACL match: $matchName"
                }
                elseif ($aclToken.token -like "`$SUBSCRIBER:*") {
                    $aclTokenSplit = $aclToken.token.split(':')
                    $matchName = ($allGroupInfo | Where-Object { $_.OriginId -eq $aclTokenSplit[-1] }).GroupName
                    if ($matchName) {
                        $match = $true
                        $matchName = '$SUBSCRIBER:' + $matchName
                        Write-Host "TokenData ACL match: $matchName"
                    }                    
                }
            }
            'Project' {
                if ($aclToken.token -eq "`$PROJECT:vstfs:///Classification/TeamProject/$projectId") {
                    $match = $true
                    $matchName = "$projName - Project"
                    Write-Host "non-tokenData ACL match: $matchName"
                }
            }
            'Environment' {
                if ($tokenData -eq "N/A") {
                    if ($aclToken.token -eq "Environments/$projectId") {
                        $match = $true
                        $matchName = "$projName - Project"
                        Write-Host "non-tokenData ACL match: $matchName"
                    }
                }
                else {
                    if ($aclToken.token -eq "Environments/$projectId") {
                        $match = $true
                        $matchName = "$projName - Project"
                        Write-Host "TokenData Match: $matchName"
                    }
                    elseif ($aclToken.token -like "Environments/$projectId/*") {
                        $aclTokenSplit = $aclToken.token.split('/')
                        $matchName = ($tokenData | Where-Object { $_.id -eq $aclTokenSplit[-1] }).Name
                        if ($matchName) {
                            $match = $true
                            Write-Host "TokenData Match: $matchName"
                        }
                    }
                    elseif ($aclToken.token -notmatch 'Environments/(?im)^[{(]?[0-9A-F]{8}[-]?(?:[0-9A-F]{4}[-]?){3}[0-9A-F]{12}[)}]?$') {
                        $aclTokenSplit = $aclToken.token.split('/')
                        $matchName = ($tokenData | Where-Object { $_.id -eq $aclTokenSplit[-1] }).Name
                        if ($matchName) {
                            $match = $true
                            Write-Host "TokenData Match: $matchName"
                        }
                    }
                }                
            }
            'Library' {
                $aclTokenSplit = $aclToken.token.split('/')
                if ($aclToken.token -eq "Library/00000000-0000-0000-0000-000000000000") {
                    $match = $true
                    $matchName = "Org - Library"
                    Write-Host "non-tokenData ACL match: $matchName"
                }
                elseif ($aclToken.Token -eq "Library/$projectId") {
                    $match = $true
                    $matchName = "$projName - Library"
                    Write-Host "non-tokenData ACL match: $matchName"
                }
                elseif ($aclToken.Token -like "Library/$projectId/VariableGroup/*") {
                    $matchName = ($tokenData | Where-Object { $_.id -eq $aclTokenSplit[-1] }).Name
                    if ($matchName) {
                        $match = $true
                        Write-Host "TokenData Match: $matchName"
                    }
                }
                elseif ($aclToken.Token -like "Library/Collection/VariableGroup/*") {
                    $matchName = ($tokenData | Where-Object { $_.id -eq $aclTokenSplit[-1] }).Name
                    if ($matchName) {
                        $match = $true
                        $matchName = "$matchName - Collection"
                        Write-Host "TokenData Match: $matchName"
                    }
                }
                elseif ($aclToken.Token -like "Library/$projectId/SecureFile/*") {
                    $matchName = ($tokenData | Where-Object { $_.id -eq $aclTokenSplit[-1] }).Name
                    if ($matchName) {
                        $match = $true
                        $matchName = "$matchName - SecureFile"
                        Write-Host "TokenData Match: $matchName"
                    }
                }
            }
            'AccountAdminSecurity' {
                if ($aclToken.Token -eq "/Ownership" ) {
                    $match = $true
                    $matchName = "Org - AccountAdminSecurity"
                    Write-Host "non-tokenData ACL match: $matchName"
                }
            }
            'Process' {
                $aclTokenSplit = $aclToken.token.split(':')
                if ($aclToken.Token -eq '$PROCESS') {
                    $match = $true
                    $matchName = "Org - Process"
                    Write-Host "non-tokenData ACL match: $matchName"
                }
                elseif ($aclToken.Token -like "`$PROCESS:*") {
                    $matchName1 = ($tokenData | Where-Object { $_.typeId -eq $aclTokenSplit[1] }).name
                    $matchName2 = ($tokenData | Where-Object { $_.typeId -eq $aclTokenSplit[-1] }).name
                    if ($matchName1 -and $matchName2) {
                        $match = $true
                        $matchName = $matchName1 + "/" + $matchName2
                        Write-Host "TokenData Match: $matchName"
                    }
                }
            }
            'Plan' {
                $aclTokenSplit = $aclToken.token.split('/')
                if ($aclToken.Token -eq "Plan") {
                    $match = $true
                    $matchName = "Org - Plan"
                    Write-Host "non-tokenData ACL match: $matchName"
                }
                elseif ($aclToken.Token -eq "Plan/$projectId") {
                    $match = $true
                    $matchName = "$projName - Plan"
                    Write-Host "non-tokenData ACL match: $matchName"
                }
                elseif ($aclToken.Token -like "Plan/$projectId/*") {
                    $matchName = ($tokenData | Where-Object { $_.id -eq $aclTokenSplit[-1] }).Name
                    if ($matchName) {
                        $match = $true
                        Write-Host "TokenData Match: $matchName"
                    }
                }
            }
            'Collection' {
                if ($aclToken.Token -eq "NAMESPACE") {
                    $match = $true
                    $matchName = "Org - Collection"
                    Write-Host "non-tokenData ACL match: $matchName"
                }
            }
            'ServiceHooks' {
                if ($aclToken.Token -eq "PublisherSecurity") {
                    $match = $true
                    $matchName = "Org - ServiceHook"
                    Write-Host "non-tokenData ACL match: $matchName"
                }
                elseif ($aclToken.Token -eq "PublisherSecurity/$projectId") {
                    $match = $true
                    $matchName = "$projName - ServiceHook"
                    Write-Host "non-tokenData ACL match: $matchName"
                }
            }
            'ServiceEndpoints' {
                $aclTokenSplit = $aclToken.token.split('/')
                if ($aclToken.Token -eq "endpoints/$projectId") {
                    $match = $true
                    $matchName = "$projName - ServiceEndpoint"
                    Write-Host "non-tokenData ACL match: $matchName"
                }
                elseif ($aclToken.Token -like "endpoints/$projectId*") {
                    $matchName = ($tokenData | Where-Object { $_.id -eq $aclTokenSplit[-1] }).Name
                    if ($matchName) {
                        $match = $true
                        Write-Host "TokenData Match: $matchName"
                    }
                }
                elseif ($aclToken.Token -like "endpoints/collection/*") {
                    $matchName = ($tokenData | Where-Object { $_.id -eq $aclTokenSplit[-1] }).Name
                    if ($matchName) {
                        $match = $true
                        Write-Host "TokenData Match: $matchName"
                    }
                }
            }
            'EventSubscriber' {
                if ($aclToken.Token -eq '$SUBSCRIBER') {
                    $match = $true
                    $matchName = "Org - EventSubscriber"
                    Write-Host "non-tokenData ACL match: $matchName"
                }
                elseif ($aclToken.Token -like "`$SUBSCRIBER:*") {
                    $aclTokenSplit = $aclToken.token.split(':')
                    $matchName = ($groupInfo | Where-Object { $_.OriginId -eq $aclTokenSplit[-1] }).GroupName
                    if ($matchName) {
                        $match = $true
                        Write-Host "TokenData Match: $matchName"
                    }
                }
            }
            'Git Repositories' {
                if ($aclToken.Token -eq "repoV2") {
                    $match = $true
                    $matchName = "Org - Git Repositories"
                    Write-Host "non-tokenData ACL match: $matchName"
                }
                elseif ($aclToken.Token -eq "repoV2/$projectId") {
                    $match = $true
                    $matchName = "$projName - Git Repositories"
                    Write-Host "non-tokenData ACL match: $matchName"
                }
                elseif ($aclToken.Token -like "repoV2/$projectId/*") {
                    $aclTokenSplit = $aclToken.token.split('/')
                    $matchName = ($tokenData | Where-Object { $_.id -eq $aclTokenSplit[-1] }).Name
                    if ($matchName) {
                        $match = $true
                        Write-Host "TokenData Match: $matchName"
                    }
                }
            }
            'DistributedTask' {
                $aclTokenSplit = $aclToken.token.split('/')
                if ($aclToken.Token -eq "AgentClouds") {
                    $match = $true
                    $matchName = "Org - AgentClouds - DistributedTask"
                    Write-Host "non-tokenData ACL match: $matchName"
                }
                elseif ($aclToken.Token -eq "AgentPools") {
                    $match = $true
                    $matchName = "Org - AgentPools - DistributedTask"
                    Write-Host "non-tokenData ACL match: $matchName"
                }
                elseif ($aclToken.Token -like "AgentPools/*") {
                    $matchName = ($tokenData | Where-Object { $_.id -eq $aclTokenSplit[-1] }).Name
                    if ($matchName) {
                        $match = $true
                        Write-Host "TokenData Match: $matchName"
                    }                    
                }
                elseif ($aclToken -eq "AgentQueues/$projectId") {
                    $match = $true
                    $matchName = "$projName - AgentQueues - DistributedTask"
                    Write-Host "non-tokenData ACL match: $matchName"
                }
                elseif ($aclToken.Token -like "AgentQueues/$projectId/*") {
                    $matchName = ($tokenData | Where-Object { $_.id -eq $aclTokenSplit[-1] }).Name
                    if ($matchName) {
                        $match = $true
                        $matchName = "$matchName - AgentQueue"
                        Write-Host "TokenData Match: $matchName"
                    } 
                }
            }
            'WorkItemTrackingAdministration' {
                if ($aclToken.Token -eq "WorkItemTrackingPrivileges") {
                    $match = $true
                    $matchName = "Org - WorkItemTrackingAdministration"
                    Write-Host "non-tokenData ACL match: $matchName"
                }
            }
            'Identity' {
                if ($aclToken.Token -eq $projectId) {
                    $match = $true
                    $matchName = "$projName - Identity"
                    Write-Host "non-tokenData ACL match: $matchName"
                }
                elseif ($aclToken.Token -like "$projectId\*") {
                    $aclTokenSplit = $aclToken.token.split('\')
                    $matchName = ($groupInfo | Where-Object { $_.OriginId -eq $aclTokenSplit[-1] }).GroupName
                    if ($matchName) {
                        $match = $true
                        Write-Host "TokenData Match: $matchName"
                    }
                }
            }
            'AuditLog' {
                if ($aclToken.Token -eq "AllPermissions") {
                    $match = $true
                    $matchName = "Org - AuditLog"
                    Write-Host "non-tokenData ACL match: $matchName"
                }
            }
            'ReleaseManagement' {
                if ($namespace.namespaceId -eq 'c788c23e-1b46-4162-8f5e-d7585343b5de') {
                    if ($aclToken.Token -eq $projectId) {
                        $match = $true
                        $matchName = "$projName - ReleaseManagement"
                        Write-Host "non-tokenData ACL match: $matchName"
                    }
                    elseif ($aclToken.Token -like "$projectId/*") {
                        $aclTokenSplit = $aclToken.token.split('/')
                        if (($aclTokenSplit[-1] -match "[0-9]") -and ($aclTokenSplit.count -gt 1)) {
                            # Find by definition number
                            $matchObj = $tokenData | Where-Object { $_.id -eq $aclTokenSplit[-1] }    
                            $matchName = $matchObj.Path + "\" + $matchObj.Name
                        }
                        else { # Use Token Path
                            $matched = @()
                            for ($r = 1; $r -lt $aclTokenSplit.Count; $r++) {
                                $matched += '\' + $aclTokenSplit[$r]
                            }
                            $matchName = $matched
                        }                    
                        if ($matchName) {
                            $match = $true
                            Write-Host "TokenData Match: $matchName"
                        }
                    }
                }
                else {
                    break
                }                
            }
            'AnalyticsViews' {
                $aclTokenSplit = $aclToken.token.split('/')
                if ($aclToken.Token -eq '$/Shared') {
                    $match = $true
                    $matchName = "Org - AnalyticsViews"
                    Write-Host "non-tokenData ACL match: $matchName"
                }
                elseif ($aclToken.Token -eq "`$/Shared/$projectId") {
                    $match = $true
                    $matchName = "$projName - AnalyticsViews"
                    Write-Host "non-tokenData ACL match: $matchName"
                }
                elseif ($aclToken.Token -like "`$/Shared/$projectId/*") {
                    $matchName = ($tokenData | Where-Object { $_.id -eq $aclTokenSplit[-1] }).Name
                    if ($matchName) {
                        $match = $true
                        $matchName = "$matchName - Shared"
                        Write-Host "TokenData Match: $matchName"
                    } 
                }
                elseif ($aclToken.Token -like "`$/Private/$projectId/*") {
                    $matchName = ($tokenData | Where-Object { $_.id -eq $aclTokenSplit[-1] }).Name
                    if ($matchName) {
                        $match = $true
                        $matchName = "$matchName - Private"
                        Write-Host "TokenData Match: $matchName"
                    } 
                }
            }
            'Analytics' {
                if ($aclToken.Token -eq "`$/$projectId") {
                    $match = $true
                    $matchName = "$projName - Analytics"
                    Write-Host "non-tokenData ACL match: $matchName"
                }
            }
        }        
        
        if ($match) {
            Write-Host "Token: $($aclToken.token)"
        
            # list access control entry for each dictionary 
            $aclToken.acesDictionary.PSObject.Properties | ForEach-Object {

                Write-Host "Descriptor: $($_.value.descriptor)"
                $currentDescriptor = $_.value.descriptor
                $ug = ""

                if ($_.value.descriptor -like "Microsoft.TeamFoundation.Identity*") {
                    $ident = $groupInfo | Where-Object { $_.FullDescriptor -eq $currentDescriptor }

                    # Descriptor that starts with 'Microsoft.TeamFoundation.Identity' not found in list of groups previous gathered. 
                    # Gather name using identity lookup.
                    if (!$ident) {
                        try {
                            $identUri = $userParams.HTTP_preFix  + "://vssps.dev.azure.com/" + $VSTSMasterAcct + "/_apis/identities/?descriptors=" + $currentDescriptor + "&api-version=7.2-preview.1"
                            $id = Invoke-AdoRestMethod -Uri $identUri -Method Get -Headers $authorization
                        }
                        catch {
                            Write-Log -Message "Identity lookup failed: $($_.Exception.Message)" -Level 'Warning' -FunctionName 'Get-PermissionsByNamespace' -Uri $identUri
                        }                        
                        if ($id.value) {
                            $identName = $id.value.providerDisplayName
                            $nameSplit = $identName.Split('\')
                            $sName =  $nameSplit[0].substring(1,$nameSplit[0].length-2)      
                            if ($sName -eq "TEAM FOUNDATION") {
                                $ugRawDataDumpName = "TEAM FOUNDATION_$($nameSplit[1])"
                                $ug = $identName
                                $groupType = "AAD Group"
                            } else {
                                $ug = $ugRawDataDumpName = $nameSplit[1]
                                $groupType = "Group"
                            }
                            $des = $id.value.properties.Description.'$value'
                            Write-Host "GroupName: $ug"
                        } else {
                            $ErrorMessage = $_.Exception.Message
                            $FailedItem = $_.Exception.ItemName
                            Write-Host "Error : " + $ErrorMessage + " iTEM : " + $FailedItem
                            break "ERROR OCCURRED!"
                        }
                    }
                    else {
                        if (($currentDescriptor -like "*0-0-0-0-3") -and ($ident.GroupName -eq "Project Valid Users")) {
                            $ug = $ugRawDataDumpName = $ident.GroupName + " - " + $ident.Project
                        }
                        else {
                            $nameSplit = $ident.GroupName.Split('\')
                            $sName =  $nameSplit[0].substring(1,$nameSplit[0].length-2)                        
                            if ($sName -eq "TEAM FOUNDATION") {
                                $ugRawDataDumpName = "TEAM FOUNDATION_$($nameSplit[1])"
                                $ug = $ident.GroupName
                                $groupType = "AAD Group"
                            }
                            else {
                                $ug = $ugRawDataDumpName = $ident.GroupName
                                $groupType = $ident.GroupType
                            }                        
                        }                    
                        $des = $ident.Description
                        Write-Host "GroupName: $ug"                        
                    }
                } elseif ($_.value.descriptor -like "Microsoft.TeamFoundation.ServiceIdentity*") {
                    $currentUser = $allSvcUsers | Where-Object { $_.FullDescriptor -eq $currentDescriptor }
                    if (-not $currentUser) {
                        # Fallback: project-scoped service identities (e.g. Project Build Service)
                        # are not in the pre-cached svc.* graph users walk. Resolve via identity API.
                        try {
                            $identUri = $userParams.HTTP_preFix + "://vssps.dev.azure.com/" + $VSTSMasterAcct + "/_apis/identities/?descriptors=" + $currentDescriptor + "&api-version=7.2-preview.1"
                            $id = Invoke-AdoRestMethod -Uri $identUri -Method Get -Headers $authorization
                            if ($id.value) {
                                $currentUser = [PSCustomObject]@{
                                    SvcUserName = $id.value.providerDisplayName
                                }
                            }
                        }
                        catch {
                            Write-Log -Message "ServiceIdentity lookup failed for $currentDescriptor : $($_.Exception.Message)" -Level 'Warning' -FunctionName 'Get-PermissionsByNamespace' -Uri $identUri
                        }
                    }
                    if ($currentUser -and $currentUser.SvcUserName) {
                        $ugRawDataDumpName = $ug = $currentUser.SvcUserName
                    }
                    else {
                        $ug = $currentDescriptor
                        $ugRawDataDumpName = "UnresolvedServiceIdentity"
                        Write-Log -Message "Unresolved ServiceIdentity: $currentDescriptor" -Level 'Warning' -FunctionName 'Get-PermissionsByNamespace'
                    }
                    $des = ""
                    Write-Host "User: $ug"
                    $groupType = "User"
                } elseif ($_.value.descriptor -like "Microsoft.IdentityModel.Claims.ClaimsIdentity*") {
                    # ClaimsIdentity descriptors identify individual AAD users granted permissions
                    # directly in the UI. The descriptor is shaped like
                    #   Microsoft.IdentityModel.Claims.ClaimsIdentity;<tenantId>\<upn>
                    # Try several match strategies before falling back to the identity API so the
                    # user's display name and principal name are populated in the CSV/JSON output.
                    $descLastSegment = $currentDescriptor.Split('\')[-1]
                    $currentUser = $users | Where-Object { $_.principalName -eq $descLastSegment } | Select-Object -First 1
                    if (-not $currentUser) {
                        $currentUser = $users | Where-Object { $_.mailAddress -eq $descLastSegment } | Select-Object -First 1
                    }
                    if (-not $currentUser) {
                        $currentUser = $users | Where-Object { $_.descriptor -eq $currentDescriptor } | Select-Object -First 1
                    }
                    if (-not $currentUser) {
                        # Fallback: resolve via identity API (handles users not in the pre-fetched
                        # graph users list, e.g. guests, disabled, or cross-tenant accounts).
                        try {
                            $identUri = $userParams.HTTP_preFix + "://vssps.dev.azure.com/" + $VSTSMasterAcct + "/_apis/identities/?descriptors=" + $currentDescriptor + "&api-version=7.2-preview.1"
                            $id = Invoke-AdoRestMethod -Uri $identUri -Method Get -Headers $authorization
                            if ($id.value) {
                                $currentUser = [PSCustomObject]@{
                                    DisplayName   = $id.value.providerDisplayName
                                    PrincipalName = if ($id.value.properties.Mail.'$value') { $id.value.properties.Mail.'$value' } else { $descLastSegment }
                                }
                            }
                        }
                        catch {
                            Write-Log -Message "ClaimsIdentity lookup failed for $currentDescriptor : $($_.Exception.Message)" -Level 'Warning' -FunctionName 'Get-PermissionsByNamespace' -Uri $identUri
                        }
                    }
                    if ($currentUser -and $currentUser.DisplayName) {
                        $ug = "$($currentUser.DisplayName) ($($currentUser.PrincipalName))"
                        $ugRawDataDumpName = $currentUser.DisplayName
                    }
                    else {
                        # Last-ditch: surface the descriptor's UPN segment so the row is not blank.
                        $ug = $descLastSegment
                        $ugRawDataDumpName = $descLastSegment
                        Write-Log -Message "Unresolved ClaimsIdentity user: $currentDescriptor" -Level 'Warning' -FunctionName 'Get-PermissionsByNamespace'
                    }
                    $des = ""
                    Write-Host "User: $ug"
                    $groupType = "User"
                }
                else {
                    # Unmatched descriptor type (e.g., Service Principals, unknown identity types).
                    # Attempt identity API lookup; fall back to raw descriptor if that fails.
                    $ug = ""
                    $des = ""
                    $groupType = "Unknown"
                    try {
                        $identUri = $userParams.HTTP_preFix  + "://vssps.dev.azure.com/" + $VSTSMasterAcct + "/_apis/identities/?descriptors=" + $currentDescriptor + "&api-version=7.2-preview.1"
                        $id = Invoke-AdoRestMethod -Uri $identUri -Method Get -Headers $authorization
                        if ($id.value) {
                            $ug = $id.value.providerDisplayName
                            $ugRawDataDumpName = $ug
                            # Managed Identities and registered SPs both report SchemaClassName=ServicePrincipal
                            # in ADO. Without Microsoft Graph (out of scope), use the providerDisplayName
                            # to differentiate: MSI names typically end in -msi, contain kubelet/managed-,
                            # or start with msi-.
                            $isMSI = $id.value.providerDisplayName -match '(?i)(-msi$|/msi$|kubelet|^msi-|managed-)'
                            $groupType = if ($id.value.properties.SchemaClassName.'$value' -eq 'ServicePrincipal') {
                                if ($isMSI) { 'Managed Identity' } else { 'Service Principal' }
                            } else { 'Unknown' }
                            Write-Host "Resolved unmatched descriptor: $ug (type: $groupType)"
                        }
                    }
                    catch {
                        Write-Log -Message "Unmatched descriptor lookup failed: $($_.Exception.Message)" -Level 'Warning' -FunctionName 'Get-PermissionsByNamespace' -Uri $identUri
                    }
                    if ([string]::IsNullOrEmpty($ug)) {
                        $ug = $currentDescriptor
                        $ugRawDataDumpName = "UnknownDescriptor"
                        Write-Log -Message "Unresolved descriptor: $currentDescriptor" -Level 'Warning' -FunctionName 'Get-PermissionsByNamespace'
                    }
                }
            
                # get dump of data to process - for debugging
                if (![string]::IsNullOrEmpty($rawDataDump) )                
                {
                    $outname =  $dirRoot + $userParams.DumpDirectory + $projName + "_" + $ugRawDataDumpName + "_" + $ns.name + "_" + $today + "_" + $rawDataDump
                    
                    Write-Output $projName  " - " $ugRawDataDumpName " - " $ns.name | Out-File $outname -Append -NoNewline
                    Write-Output " " | Out-File $outname -Append
                    Write-Output "inheritPermissions: $($aclToken.inheritPermissions)"| Out-File $outname -Append
                    Write-Output "token: $($aclToken.Token)" | Out-File $outname -Append
                    Write-Output "acesDictionary: $($_.Name)" | Out-File $outname -Append
                    $ace = ConvertTo-Json -InputObject $_.Value -Depth 42
                    Write-Output $ace | Out-File $outname -Append     
                }
            
                # check allow permissions
                if($_.Value.allow -gt 0 )
                {                           
                    $permAllow = [convert]::ToString($_.Value.allow,2)
                    # loop thru the decoded base 2 number and check the bit. if 1(on) then that permission is set
                    for ($a =  $permAllow.Length-1; $a -ge 0; $a--) 
                    {
                        # need to traverse the string in reverse to match the action list
                        $Allowplace = ( ($a - $permAllow.Length) * -1 )-1

                        if( $permAllow.Substring($a,1) -ge 1)
                        {
                            
                            # find bit in action list
                            $raise = [Math]::Pow(2, $Allowplace)
                            $bit = $ns.actions | Where-Object {$_.bit -eq $raise }

                            if ($bit) {
                                Write-Host "  $($bit.displayName) : Allow"
                                $permissions.Add([PSCustomObject]@{
                                    Namespace      = $ns.name
                                    Project        = $projName
                                    Object         = $matchName
                                    Type           = $groupType
                                    UserGroupName  = $ug
                                    Description    = $des
                                    PermissionType = 'Allow'
                                    Permission     = $bit.displayName
                                    Bit            = $bit.bit
                                    PermissionName = $bit.Name
                                    DecodedValue   = $permAllow
                                    RawData        = $_.Value.allow
                                    InheritedFrom  = $inheritFrom
                                })
                            }
                        }
                    }
                }

                # check effective allow permissions -and ($lastDescriptor -ne $_.Value.descriptor)
                if (![string]::IsNullOrEmpty($_.Value.extendedInfo.effectiveAllow )  )
                {                   
                    if( ($_.Value.extendedInfo.effectiveAllow -gt 0)  )
                    {
                        $effAllow = [convert]::ToString($_.Value.extendedInfo.effectiveAllow,2)
                        # make sure allow and effective allow are not the same
                        if( $permAllow -ne $effAllow)
                        {
                            # loop thru the decoded base 2 number and check the bit. if 1(on) then that permission is set
                            for ($a =  $effAllow.Length-1; $a -ge 0; $a--) 
                            {
                                # need to traverse the string in reverse to match the action list
                                $effAllowplace = ( ($a - $effAllow.Length) * -1 )-1

                                if( $effAllow.Substring($a,1) -ge 1)
                                {
                                    $raise = [Math]::Pow(2, $effAllowplace)
                                    $bit = $ns.actions | Where-Object {$_.bit -eq $raise }
                                    
                                    if ($bit) {
                                        Write-Host "  $($bit.displayName) : Allow(Effective)"
                                        $permissions.Add([PSCustomObject]@{
                                            Namespace      = $ns.name
                                            Project        = $projName
                                            Object         = $matchName
                                            Type           = $groupType
                                            UserGroupName  = $ug
                                            Description    = $des
                                            PermissionType = 'Allow(Effective)'
                                            Permission     = $bit.displayName
                                            Bit            = $bit.bit
                                            PermissionName = $bit.Name
                                            DecodedValue   = $effAllow
                                            RawData        = $_.Value.extendedInfo.effectiveAllow
                                            InheritedFrom  = $inheritFrom
                                        })
                                    }                           
                                }
                            }
                        }
                    }
                }

                # check inherited allow permissions -and ($lastDescriptor -ne $_.Value.descriptor)
                if (![string]::IsNullOrEmpty($_.Value.extendedInfo.inheritedAllow )   )
                {                   

                    # Write-Host $_.Value.descriptor
                    if( ($_.Value.extendedInfo.inheritedAllow -gt 0)  )
                    {
            
                        $inhAllow = [convert]::ToString($_.Value.extendedInfo.inheritedAllow,2)

                        # loop thru the decoded base 2 number and check the bit. if 1(on) then that permission is set
                        for ($a =  $inhAllow.Length-1; $a -ge 0; $a--) 
                        {
                            # need to traverse the string in reverse to match the action list
                            $inhAllowplace = ( ($a - $inhAllow.Length) * -1 )-1

                            if( $inhAllow.Substring($a,1) -ge 1)
                            {
                                $raise = [Math]::Pow(2, $inhAllowplace)
                                $bit = $ns.actions | Where-Object {$_.bit -eq $raise }

                                if ($bit) {
                                    Write-Host "  $($bit.displayName) : Allow(Inherited)"
                                    $permissions.Add([PSCustomObject]@{
                                        Namespace      = $ns.name
                                        Project        = $projName
                                        Object         = $matchName
                                        Type           = $groupType
                                        UserGroupName  = $ug
                                        Description    = $des
                                        PermissionType = 'Allow(Inherited)'
                                        Permission     = $bit.displayName
                                        Bit            = $bit.bit
                                        PermissionName = $bit.Name
                                        DecodedValue   = $inhAllow
                                        RawData        = $_.Value.extendedInfo.inheritedAllow
                                        InheritedFrom  = $inheritFrom
                                    })
                                }
                            }
                        }
                    }
                }

                # check deny
                if($_.Value.deny -gt 0 )
                {
                
                    $permDeny = [convert]::ToString($_.Value.deny,2)
                
                    # loop thru the decoded base 2 number and check the bit. if 1(on) then that permission is set
                    for ($a =  $permDeny.Length-1; $a -ge 0; $a--) 
                    {
                        # need to traverse the string in reverse to match the action list
                        $Denyplace = ( ($a - $permDeny.Length) * -1 )-1

                        if( $permDeny.Substring($a,1) -ge 1)
                        {
                            $raise = [Math]::Pow(2, $inhAllowplace)
                            $bit = $ns.actions | Where-Object {$_.bit -eq $raise }

                            if ($bit) {
                                Write-Host "  $($bit.displayName) : Deny"
                                $permissions.Add([PSCustomObject]@{
                                    Namespace      = $ns.name
                                    Project        = $projName
                                    Object         = $matchName
                                    Type           = $groupType
                                    UserGroupName  = $ug
                                    Description    = $des
                                    PermissionType = 'Deny'
                                    Permission     = $bit.displayName
                                    Bit            = $bit.bit
                                    PermissionName = $bit.Name
                                    DecodedValue   = $permDeny
                                    RawData        = $_.Value.deny
                                    InheritedFrom  = $inheritFrom
                                })
                            }
                        }
                    }
                }

                # check effective deny permissions 
                if (![string]::IsNullOrEmpty($_.Value.extendedInfo.effectiveDeny )  )
                {                   
                    
                    # Write-Host $_.Value.descriptor
                    if( ($_.Value.extendedInfo.effectiveDeny -gt 0)  )
                    {
                                            
                        $effDeny = [convert]::ToString($_.Value.extendedInfo.effectiveDeny,2)

                        # loop thru the decoded base 2 number and check the bit. if 1(on) then that permission is set
                        for ($a =  $effDeny.Length-1; $a -ge 0; $a--) 
                        {
                            # need to traverse the string in reverse to match the action list
                            $EffDenyplace = ( ($a - $effDeny.Length) * -1 )-1

                            if( $effDeny.Substring($a,1) -ge 1)
                            {
                                
                                $raise = [Math]::Pow(2, $EffDenyplace)
                                $bit = $ns.actions | Where-Object {$_.bit -eq $raise }

                                if ($bit) {
                                    Write-Host "  $($bit.displayName) : Deny(Effective)"
                                    $permissions.Add([PSCustomObject]@{
                                        Namespace      = $ns.name
                                        Project        = $projName
                                        Object         = $matchName
                                        Type           = $groupType
                                        UserGroupName  = $ug
                                        Description    = $des
                                        PermissionType = 'Deny(Effective)'
                                        Permission     = $bit.displayName
                                        Bit            = $bit.bit
                                        PermissionName = $bit.Name
                                        DecodedValue   = $effDeny
                                        RawData        = $_.Value.extendedInfo.effectiveDeny
                                        InheritedFrom  = $inheritFrom
                                    })
                                }
                            }
                        }
                    }
                }

                # check inherited deny permissions 
                if (![string]::IsNullOrEmpty($_.Value.extendedInfo.InheritedDeny )  )
                {                   
                    
                    # Write-Host $_.Value.descriptor
                    if( ($_.Value.extendedInfo.InheritedDeny -gt 0)  )
                    {
                                            
                        $inhDeny = [convert]::ToString($_.Value.extendedInfo.InheritedDeny,2)

                        # loop thru the decoded base 2 number and check the bit. if 1(on) then that permission is set
                        for ($a =  $inhDeny.Length-1; $a -ge 0; $a--) 
                        {
                            # need to traverse the string in reverse to match the action list
                            $EffDenyplace = ( ($a - $inhDeny.Length) * -1 )-1

                            if( $inhDeny.Substring($a,1) -ge 1)
                            {
                                
                                $raise = [Math]::Pow(2, $EffDenyplace)
                                $bit = $ns.actions | Where-Object {$_.bit -eq $raise }

                                if ($bit) {
                                    Write-Host "  $($bit.displayName) : Deny(Inherited)"
                                    $permissions.Add([PSCustomObject]@{
                                        Namespace      = $ns.name
                                        Project        = $projName
                                        Object         = $matchName
                                        Type           = $groupType
                                        UserGroupName  = $ug
                                        Description    = $des
                                        PermissionType = 'Deny(Inherited)'
                                        Permission     = $bit.displayName
                                        Bit            = $bit.bit
                                        PermissionName = $bit.Name
                                        DecodedValue   = $inhDeny
                                        RawData        = $_.Value.extendedInfo.InheritedDeny
                                        InheritedFrom  = $inheritFrom
                                    })
                                }
                            }
                        }
                    }
                }    
            }
        }
    }        

    return $permissions
}
              
function Get-GroupMembership(){

    param (
        [Parameter(Mandatory = $true)]
        $userParams,
        [Parameter(Mandatory = $true)]
        $fndGroup,
        [Parameter(Mandatory = $true)]
        $PAT
    )
    
    # Base64-encodes the Personal Access Token (PAT) appropriately
    $authorization = GetVSTSCredential -Token $PAT
                
    #GET https://vssps.dev.azure.com/{organization}/_apis/graph/Memberships/{subjectDescriptor}?api-version=7.2-preview.1
    $memberUri = $userParams.HTTP_preFix +  "://vssps.dev.azure.com/" + $VSTSMasterAcct + "/_apis/graph/Memberships/" + $fndGroup.descriptor +"?direction=Up&api-version=7.2-preview.1"
    $Memberof = Invoke-AdoRestMethod -Uri $memberUri -Method Get -Headers $authorization    

   
    return $MemberOf

}