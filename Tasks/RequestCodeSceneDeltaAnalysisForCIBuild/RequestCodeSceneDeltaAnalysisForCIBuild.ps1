[CmdletBinding()]
param()

function Get-Pipeline-Context {
    if(![string]::IsNullOrEmpty($env:BUILD_SOURCESDIRECTORY))
    {
        Write-VstsTaskVerbose "Build pipeline context detected"
        return "build"
    }
    else
    {
        Write-VstsTaskVerbose "Release pipeline context detected"
        return "release"
    }
}

function Get-AzureDevOpsAPIHeader {
    if (!([string]::IsNullOrEmpty($configuration.azureDevOpsAPItoken))) {
        Write-VstsTaskVerbose "Using provided Personal Access Token..."
        # Base64-encodes the Personal Access Token (PAT) appropriately
        $user = ""
        $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user,$configuration.azureDevOpsAPItoken)))
        $restApiHeader = @{Authorization=("Basic {0}" -f $base64AuthInfo)}
    }
    elseif (!([string]::IsNullOrEmpty($env:SYSTEM_ACCESSTOKEN))) {
        Write-VstsTaskVerbose "Using shared VSTS OAuth token $($env:SYSTEM_ACCESSTOKEN)..."
        $restApiHeader = @{Authorization = "Bearer $env:SYSTEM_ACCESSTOKEN"}
    }
    else {
        Write-Error "No token provided! Either provide Personal Access Token or enable Allow scripts to access OAuth token in your environment settings."
    }
    return $restApiHeader
}

function Get-Releases {
    param (
        [Parameter(Mandatory=$true)]$releaseDefinitionId,
        [Parameter(Mandatory=$true)]$configuration
    )
    $header = Get-AzureDevOpsAPIHeader
    $releaseApiBaseUri = "$($configuration.teamFoundationServerUri)DefaultCollection/$($configuration.teamProject)/_apis/release/"
    $releaseApiVersion = "5.0"
    $requestUri = "$($releaseApiBaseUri)releases?definitionId=$($releaseDefinitionId)&api-version=$($releaseApiVersion)"
    $response = Invoke-RestMethod -Uri $requestUri -Method Get -ContentType "application/json" -Headers $header
    $releases = $response.value
    Write-VstsTaskVerbose "Found $($releases.Count) releases for the given release definition."
    return $releases
}

function Get-PreviousEnvironmentRelease {
    param (
        [Parameter(Mandatory=$true)]$releases,
        [Parameter(Mandatory=$true)]$currentReleaseId,
        [Parameter(Mandatory=$true)]$environmentName,
        [Parameter(Mandatory=$true)]$configuration
    )
    $header = Get-AzureDevOpsAPIHeader
    $releaseApiBaseUri = "$($configuration.teamFoundationServerUri)DefaultCollection/$($configuration.teamProject)/_apis/release/"
    $releaseApiVersion = "5.0"
    # Look through all releases for the latest one deployed to the given environment
    Write-VstsTaskVerbose "Looking for latest deployment to $environmentName..."
    foreach ($release in $releases) {
        Write-VstsTaskVerbose "Looking into release with ID $($release.id)..."
        if ([int]($release.id) -ge [int]$currentReleaseId) {
            Write-Host "Skipping current or newer release."
            continue
        }
        $requestUri = "$($releaseApiBaseUri)/releases/$($release.id)?api-version=$($releaseApiVersion)"
        $response = Invoke-RestMethod -Uri $requestUri -Method Get -ContentType "application/json" -Headers $header
        $environments = $response.environments
        $found = $false
        Write-VstsTaskVerbose "Looking into each environment..."
        foreach ($environment in $environments){
            Write-VstsTaskVerbose "Looking into environtment: $($environment.name): $($environment.status)"
            if (($environment.name -eq "$environmentName") -and ($environment.status -ne "notStarted") -and ($environment.status -ne "scheduled") -and ($environment.status -ne "canceled")) {
                $found = $true
                break
            }
        }
        if ($found) {
            Write-VstsTaskVerbose "Found previous deployment in release $($release.id)"
            return $release.id
        }
    }
}

function Get-EnvironmentCommits {
    param (
        [Parameter(Mandatory=$true)]$currentReleaseId,
        [Parameter(Mandatory=$true)]$previousReleaseId,
        [Parameter(Mandatory=$true)]$configuration
    )
    $header = Get-AzureDevOpsAPIHeader
    $releaseApiBaseUri = "$($configuration.teamFoundationServerUri)DefaultCollection/$($configuration.teamProject)/_apis/release/"
    $releaseApiVersion = "5.0-preview"
    $requestUri = "$($releaseApiBaseUri)/releases/$($currentReleaseId)/changes?baseReleaseId=$previousReleaseId&api-version=$($releaseApiVersion)"
    $response = Invoke-RestMethod -Uri $requestUri -Method Get -ContentType "application/json" -Headers $header
    return $response.value
}

function Get-ChangeCommits {
    param (
        [Parameter(Mandatory=$true)]$change,
        [Parameter(Mandatory=$true)]$configuration
    )
    switch ($configuration.pipelineContext) {
        "build" {
            $header = Get-AzureDevOpsAPIHeader
            $buildApiBaseUri = "$($configuration.taskDefinitionsUri)$($configuration.teamProject)/_apis/build/"
            $buildApiVersion = "5.0"
            $requestUri = "$($buildApiBaseUri)builds/$($change.buildId)/changes?api-version=$($buildApiVersion)"
            $response = Invoke-RestMethod -Uri $requestUri -Method GET -Headers $header
            $commits = $response.value
        }
        "release" {
            $releases = Get-Releases -releaseDefinitionId $change.releaseDefinitionId -configuration $configuration
            $previousReleaseId = Get-PreviousEnvironmentRelease -releases $releases -environmentName $change.environmentName -currentReleaseId $change.releaseId -configuration $configuration
            $commits = Get-EnvironmentCommits -currentReleaseId $change.releaseId -previousReleaseId $previousReleaseId -configuration $configuration
            Write-Host $previousReleaseId | ConvertTo-Json -Depth 10
        }
        Default {}
    }
    return $commits
}

function Get-RiskVerdict {
    param (
        [Parameter(Mandatory=$true)]$risk,
        [Parameter(Mandatory=$true)]$threshold
    )
    if ($risk -ge $threshold)  { 
        return $true
    }
    else {
        return $false
    }
}

function Set-Statuses {
    param (
        [Parameter(Mandatory=$true)]$analysisResult,
        [Parameter(Mandatory=$true)]$configuration,
        [Parameter(Mandatory=$true)]$rules
    )

    $statuses = @{
        risk = @{
            statusContextName = "delivery-risk"
            description = "Delivery risk: $($analysisResult.result.risk) - $($analysisResult.result.description)"
            targetUrl = $configuration.codeSceneBaseUrl + $analysisResult.view
            publish = $rules.publishDeliveryRiskStatus
        }
        goals = @{
            statusContextName = "planned-goals"
            description = "Planned goals"
            targetUrl = $configuration.codeSceneBaseUrl + $analysisResult.view
            publish = $rules.publishPlannedGoalsStatus
        }
        codeHealth = @{
            statusContextName = "code-health"
            description = "Code health"
            targetUrl = $configuration.codeSceneBaseUrl + $analysisResult.view
            publish = $rules.publishCodeHealthStatus
        }
    }
    $statuses.risk.failed = Get-RiskVerdict -risk $analysisResult.result.risk -threshold $rules.riskLevelThreshold.value
    $statuses.goals.failed = [boolean]($analysisResult.result.'quality-gates'.'violates-goal')
    $statuses.codeHealth.failed = [boolean]($analysisResult.result.'quality-gates'.'degrades-in-code-health')
    $statuses.risk.state = $changeStatusStates.Item($statuses.risk.failed)
    $statuses.goals.state = $changeStatusStates.Item($statuses.goals.failed)
    $statuses.codeHealth.state = $changeStatusStates.Item($statuses.codeHealth.failed)
    $statusWarnings = @{}
    foreach ($warning in $analysisResult.result.warnings) {
        $statusWarnings."$($warning.category)" = $warning.details
    }
    if ($statuses.risk.failed) { $statuses.risk.description = "Delivery risk: $($analysisResult.result.risk) - $($analysisResult.result.description)" }
    if ($statuses.goals.failed) { $statuses.goals.description = "Planned goals quality gate: Failed - $($statusWarnings.'Violates Goals')" }
    if ($statuses.codeHealth.failed) { $statuses.codeHealth.description = "Code health quality gate: Failed - $($statusWarnings.'Degrades in Code Health')" }
    return $statuses
}

function Request-DeltaAnalysis {
    param (
        [Parameter(Mandatory=$true)]$change,
        [Parameter(Mandatory=$true)]$configuration,
        [Parameter(Mandatory=$true)]$rules
    )
    $commitIds = @()
    foreach ($commit in $change.commits) {
        $commitIds += $commit.id
    }
    Write-VstsTaskVerbose "Commit Id(s):                      $($commitIds)"
    $deltaAnalysisApiUri = "$($configuration.codeSceneBaseUrl)/$($configuration.projectRESTEndpoint)"
    $credentialsPair = "$($configuration.codeSceneAPIUserName):$($configuration.codeSceneAPIPassword)"
    $basicToken = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credentialsPair))
    $header = @{ Authorization = "Basic $($basicToken)" }
    $body = @{
        commits = $commitIds
        repository = $change.repositoryName
        coupling_threshold_percent = $rules.couplingThreshold.value
        use_biomarkers = $rules.useBiomarkers.value
    }
    $payload = $body | ConvertTo-Json
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Write-VstsTaskVerbose "Requesting CodeScene Delta Analysis"
    $response = Invoke-RestMethod -Uri $deltaAnalysisApiUri -Method POST -Body $payload -ContentType "application/json " -Headers $header
    $responseJsonString = $response | ConvertTo-Json -Depth 10
    return $response
}

$changeStatusStates = @{
    $true = "failed"
    $false = "succeeded"
}

Trace-VstsEnteringInvocation $MyInvocation
try {
    import-module "Microsoft.TeamFoundation.DistributedTask.Task.TestResults"
    $change = @{}
    $rules = @{}
    $configuration = @{}

    $rules.useBiomarkers = @{ value = $true }
    $rules.riskLevelThreshold = @{ value = Get-VstsInput -Name riskLevelThreshold -AsInt }
    $rules.couplingThreshold = @{ value = Get-VstsInput -Name couplingThreshold -AsInt }
    $rules.publishDeliveryRiskStatus = Get-VstsInput -Name publishDeliveryRiskStatus -AsBool
    $rules.publishPlannedGoalsStatus = Get-VstsInput -Name publishPlannedGoalsStatus -AsBool
    $rules.publishCodeHealthStatus = Get-VstsInput -Name publishCodeHealthStatus -AsBool

    $configuration.azureDevOpsAPItoken = Get-VstsInput -Name azureDevOpsAPItoken # Azure DevOps PAT to be used for local debugging. For more details, please see https://docs.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate?view=azure-devops#create-personal-access-tokens-to-authenticate-access
    $configuration.codeSceneBaseUrl = Get-VstsInput -Name codeSceneBaseUrl
    $configuration.projectRESTEndpoint = Get-VstsInput -Name projectRESTEndpoint
    $configuration.codeSceneAPIUserName = Get-VstsInput -Name codeSceneAPIUserName
    $configuration.codeSceneAPIPassword = Get-VstsInput -Name codeSceneAPIPassword
    $configuration.taskDefinitionsUri = $env:SYSTEM_TASKDEFINITIONSURI
    $configuration.teamFoundationServerUri = $env:SYSTEM_TEAMFOUNDATIONSERVERURI
    $configuration.teamProject = $env:SYSTEM_TEAMPROJECT
    $configuration.pipelineContext = Get-Pipeline-Context
    
    $change.repositoryName = $env:BUILD_REPOSITORY_NAME
    $change.repositoryId = $env:BUILD_REPOSITORY_ID
    $change.sourceBranch = $env:BUILD_SOURCEBRANCH
    $change.buildId = $env:BUILD_BUILDID
    $change.releaseId = $env:RELEASE_RELEASEID
    $change.releaseDefinitionId = $env:RELEASE_DEFINITIONID
    $change.environmentName = $env:RELEASE_ENVIRONMENTNAME

    Write-VstsTaskVerbose "Repository name:                   $($change.repositoryName)"
    Write-VstsTaskVerbose "Source branch:                     $($change.sourceBranch)"
    Write-VstsTaskVerbose "Risk level threshold:              $($rules.riskLevelThreshold)"
    Write-VstsTaskVerbose "Publish delivery risk status:      $($rules.publishDeliveryRiskStatus)"
    Write-VstsTaskVerbose "Publish planned goals status:      $($rules.publishPlannedGoalsStatus)"
    Write-VstsTaskVerbose "Publish code health status:        $($rules.publishCodeHealthStatus)"
    Write-VstsTaskVerbose "Coupling threshold:                $($rules.couplingThreshold)"
    Write-VstsTaskVerbose "Task definitions uri:              $($configuration.taskDefinitionsUri)"
    Write-VstsTaskVerbose "Team project:                      $($configuration.teamProject)"

    $change.commits = Get-ChangeCommits -change $change -configuration $configuration
    $analysisResult = Request-DeltaAnalysis -change $change -configuration $configuration -rules $rules
    
    $statuses = Set-Statuses -analysisResult $analysisResult -rules $rules -configuration $configuration

    foreach($status in $statuses.GetEnumerator()) {
        Write-VstsTaskVerbose "Status context name:               $($status.Value.statusContextName)"
        Write-VstsTaskVerbose "Status description:                $($status.Value.description)"
        Write-VstsTaskVerbose "Status state:                      $($status.Value.state)"
        Write-VstsTaskVerbose "Status target url:                 $($status.Value.targetUrl)"
        if ($status.Value.publish) {
            Write-Host ($status | ConvertTo-Json)
        }
    }


    # if ($change.sourceBranch -like "*pull*") {
    #     $change.id = (($change.sourceBranch).Replace("refs/pull/","")).replace("/merge","")

    #     Write-VstsTaskVerbose "Pull request id:                   $($change.id)"

    #     $change.commits = Get-changeCommits -change $change -configuration $configuration
    #     $change.currentIterationId = Get-LatestchangeIteration -change $change -configuration $configuration
    #     $analysisResult = Request-DeltaAnalysis -change $change -configuration $configuration -rules $rules
    #     $statuses = Set-Statuses -analysisResult $analysisResult -rules $rules -configuration $configuration

    #     foreach($status in $statuses.GetEnumerator()) {
    #         Write-VstsTaskVerbose "Status context name:               $($status.Value.statusContextName)"
    #         Write-VstsTaskVerbose "Status description:                $($status.Value.description)"
    #         Write-VstsTaskVerbose "Status state:                      $($status.Value.state)"
    #         Write-VstsTaskVerbose "Status target url:                 $($status.Value.targetUrl)"
    #         if ($status.Value.publish) {
    #             Update-changeIterationStatus -change $change -status $status -configuration $configuration
    #         }
    #     }
    # }
    # else {
    #     Write-Host "Not a pull request build!"
    # }
} finally {
    Trace-VstsLeavingInvocation $MyInvocation
}