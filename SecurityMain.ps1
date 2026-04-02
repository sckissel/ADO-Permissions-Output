#
# FileName  : SecurityMain.ps1
# Date      : 02/08/2018
# Author    : Arthur A. Garcia / Scott Kissel
# Purpose   : Extracts Azure DevOps security permissions by namespace, group, and user.
#             Outputs JSON files for auditing and reporting. Designed for unattended
#             pipeline execution with PAT authentication.
# last Update: 03/31/2026

param (
    [Parameter(Mandatory=$true, HelpMessage="Enter the PAT Token for ADO authentication")]
    [string]$PAT,
    [Parameter(Mandatory=$true, HelpMessage="Enter the ADO organization name")]
    [string]$VSTSMasterAcct,
    [Parameter(Mandatory=$true, HelpMessage="Enter the ADO project name")]
    [string]$projectName,
    [Parameter(Mandatory=$false, HelpMessage="Enter True or False for obtaining permissions from all projects in the ADO Org")]
    [string]$allProjects,
    [Parameter(Mandatory=$true, HelpMessage="Enter the root working path for the output files")]
    [string]$DirRoot,
    [Parameter(Mandatory=$false, HelpMessage="Set to True to include group membership report")]
    [string]$IncludeMembership,
    [Parameter(Mandatory=$false, HelpMessage="Set to True to recursively resolve members of AAD groups nested in ADO groups")]
    [string]$RecurseAADGroups,
    [Parameter(Mandatory=$false, HelpMessage="Output format: JSON (default), CSV, or Both")]
    [ValidateSet('JSON','CSV','Both')]
    [string]$OutputFormat = 'JSON'
)

#import modules
$modName = $PSScriptRoot + "\SecurityHelper.psm1"
Write-Host "Importing $modName"
Import-Module -Name $modName -Force

$modName = $PSScriptRoot + "\ProjectAndGroup.psm1"
Write-Host "Importing $modName" 
Import-Module -Name $modName -Force

# get parameter data for scripts
$UserDataFile = $PSScriptRoot + "\ProjectDef.json"
$userParameters = Get-Content -Path $UserDataFile | ConvertFrom-Json

# make sure directory structure exists
Write-Host "Calling 'Set-DirectoryStructure'"
Set-DirectoryStructure -userParams $userParameters -DirRoot $DirRoot

# Initialize structured logging
$logFile = $DirRoot + $userParameters.LogDirectory + "SecurityHelper_" + (Get-Date -Format "MM-dd-yyyy") + ".log"
Initialize-Log -LogFilePath $logFile
Write-Log -Message "=== ADO Permissions Extraction Started ===" -Level 'Info' -FunctionName 'SecurityMain'
Write-Log -Message "Organization: $VSTSMasterAcct | Project: $projectName | AllProjects: $allProjects" -Level 'Info' -FunctionName 'SecurityMain'

# Get all groups and their permissions
Write-Log -Message "Calling 'Get-SecurityGroupByNamespace'" -Level 'Info' -FunctionName 'SecurityMain'
Get-SecuritybyGroupByNamespace -userParams $userParameters  -rawDataDump $userParameters.rawDataFile  -getAllProjects $allProjects  -outFileName $userParameters.GroupFileName -PAT $PAT -VSTSMasterAcct $VSTSMasterAcct -projectName $projectName -dirRoot $DirRoot -OutputFormat $OutputFormat

# Optionally get group membership report
if ($IncludeMembership -eq "True") {
    Write-Log -Message "Calling 'Get-GroupMembershipReport'" -Level 'Info' -FunctionName 'SecurityMain'
    Get-GroupMembershipReport -userParams $userParameters -outFile $userParameters.MembershipFileName -getAllProjects $allProjects -dirRoot $DirRoot -PAT $PAT -VSTSMasterAcct $VSTSMasterAcct -projectName $projectName -recurseAADGroups ($RecurseAADGroups -eq "True") -OutputFormat $OutputFormat
    Write-Log -Message "Group membership report complete" -Level 'Info' -FunctionName 'SecurityMain'
}

Write-Log -Message "=== ADO Permissions Extraction Complete ===" -Level 'Info' -FunctionName 'SecurityMain'

# Run summary
$runEnd = Get-Date
$securityDir = $DirRoot + $userParameters.SecurityDir
if (Test-Path $securityDir) {
    $outputFiles = Get-ChildItem -Path $securityDir -File
    $permFiles = $outputFiles | Where-Object { $_.Name -like '*_Permissions.*' }
    $memberFiles = $outputFiles | Where-Object { $_.Name -like '*_Membership.*' }
    $totalSizeKB = [math]::Round(($outputFiles | Measure-Object -Property Length -Sum).Sum / 1KB, 1)
    Write-Log -Message "--- Run Summary ---" -Level 'Info' -FunctionName 'SecurityMain'
    Write-Log -Message "Organization: $VSTSMasterAcct | Project: $projectName | AllProjects: $allProjects" -Level 'Info' -FunctionName 'SecurityMain'
    Write-Log -Message "Permission files: $($permFiles.Count) | Membership files: $($memberFiles.Count) | Total output: ${totalSizeKB} KB" -Level 'Info' -FunctionName 'SecurityMain'
    foreach ($f in $outputFiles) {
        Write-Log -Message "  $($f.Name) ($([math]::Round($f.Length / 1KB, 1)) KB)" -Level 'Info' -FunctionName 'SecurityMain'
    }
    Write-Log -Message "Output directory: $securityDir" -Level 'Info' -FunctionName 'SecurityMain'
    Write-Log -Message "Log file: $logFile" -Level 'Info' -FunctionName 'SecurityMain'
}


