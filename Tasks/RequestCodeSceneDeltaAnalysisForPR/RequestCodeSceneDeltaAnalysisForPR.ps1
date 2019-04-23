[CmdletBinding()]
param()

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

function Update-PullRequestStatus {
    param (
        [Parameter(Mandatory=$true)]$pullRequest,
        [Parameter(Mandatory=$true)]$configuration
    )

    $statusApiVersion = "4.1-preview.1"
    $statusApiUri = "$($configuration.taskDefinitionsUri)$($configuration.teamProject)/_apis/git/repositories/$($pullRequest.repositoryName)/pullRequests/$($pullRequest.id)/statuses?api-version=$($statusApiVersion)"
    $status = @{
        state = $pullRequest.statusState
        description = $pullRequest.statusDescription
        context = @{
            name = $pullRequest.statusContextName
        }
    }
    if ($pullRequest.statusTargetUrl) {
        $status.targetUrl = $pullRequest.statusTargetUrl
    }
    $header = Get-AzureDevOpsAPIHeader
    $statusBody = $status | ConvertTo-Json
    Write-VstsTaskVerbose "Updating pull request status"
    $response = Invoke-RestMethod -Uri $statusApiUri -Method POST -Body $statusBody -ContentType "application/json " -Headers $header > $null
    return $response
}

function Get-PullRequestCommits {
    param (
        [Parameter(Mandatory=$true)]$pullRequest,
        [Parameter(Mandatory=$true)]$configuration
    )

    $repositoriesApiBaseUri = "$($configuration.taskDefinitionsUri)DefaultCollection/_apis/git/repositories/"
    $repositoriesApiVersion = "5.0"
    $requestUri = "$($repositoriesApiBaseUri)$($pullRequest.repositoryId)/pullRequests/$($pullRequest.id)/commits?api-version=$($repositoriesApiVersion)"
    $header = Get-AzureDevOpsAPIHeader
    Write-VstsTaskVerbose "Fetching pull request commits"
    $response = Invoke-RestMethod -Uri $requestUri -Method GET -Headers $header
    $commits = $response.value
    return $commits
}

function Set-Failures {
    param (
        [Parameter(Mandatory=$true)]$analysisResult,
        [Parameter(Mandatory=$true)]$rules
    )

    $_failures = @()

    if (($analysisResult.result.risk -gt $rules.riskLevelThreshold.value) -and $rules.failOnHighRisk.value)  { $_failures += $rules.failOnHighRisk.failureName }
    if ($analysisResult.result.'quality-gates'.'degrades-in-code-health' -and $rules.failOnCodeHealthDecline.value) { $_failures += $rules.failOnCodeHealthDecline.failureName }
    if ($analysisResult.result.'quality-gates'.'violates-goal' -and $rules.failOnViolatedGoal.value) { $_failures += $rules.failOnViolatedGoal.failureName }
    return $_failures
}

function Set-TestAnalysisResults {
    param (
        [Parameter(Mandatory=$true)]$analysisResult
    )

    $analysisResult.result.risk = 8
    $analysisResult.result.'quality-gates'.'degrades-in-code-health' = $true
    $analysisResult.result.'quality-gates'.'violates-goal' = $true

    return $analysisResult
}

function Request-DeltaAnalysis {
    param (
        [Parameter(Mandatory=$true)]$pullRequest,
        [Parameter(Mandatory=$true)]$configuration,
        [Parameter(Mandatory=$true)]$rules
    )
    $commitIds = @()
    foreach ($commit in $pullRequest.commits) {
        $commitIds += $commit.commitId
    }
    $deltaAnalysisApiUri = "$($configuration.codeSceneBaseUrl)/$($configuration.projectRESTEndpoint)"
    $credentialsPair = "$($configuration.codeSceneAPIUserName):$($configuration.codeSceneAPIPassword)"
    $basicToken = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credentialsPair))
    $header = @{ Authorization = "Basic $($basicToken)" }
    $payload = @{
        commits = $commitIds
        repository = $pullRequest.repositoryName
        coupling_threshold_percent = $rules.couplingThreshold.value
        use_biomarkers = $rules.useBiomarkers.value
    }
    $body = $payload | ConvertTo-Json
    Write-VstsTaskVerbose "Requesting CodeScene Delta Analysis"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $response = Invoke-RestMethod -Uri $deltaAnalysisApiUri -Method POST -Body $body -ContentType "application/json " -Headers $header
    return $response
}

Trace-VstsEnteringInvocation $MyInvocation
try {
    $pullRequest = @{}
    $rules = @{}
    $configuration = @{}
    $pullRequestStatusContextName = "CodeScene Delta Analysis"
    $configuration.azureDevOpsAPItoken = Get-VstsInput -Name azureDevOpsAPItoken # Azure DevOps PAT to be used for local debugging. For more details, please see https://docs.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate?view=azure-devops#create-personal-access-tokens-to-authenticate-access

    $rules.useBiomarkers = @{ value = $true }
    $rules.riskLevelThreshold = @{ value = Get-VstsInput -Name riskLevelThreshold -AsInt }
    $rules.failOnHighRisk = @{ value = Get-VstsInput -Name failOnHighRisk -AsBool }
    $rules.failOnViolatedGoal = @{ value = Get-VstsInput -Name failOnViolatedGoal -AsBool }
    $rules.failOnCodeHealthDecline = @{ value = Get-VstsInput -Name failOnCodeHealthDecline -AsBool }
    $rules.couplingThreshold = @{ value = Get-VstsInput -Name couplingThreshold -AsInt }
    $rules.failOnHighRisk.failureName = "riskLevel"
    $rules.failOnViolatedGoal.failureName = "violatedGoal"
    $rules.failOnCodeHealthDecline.failureName = "codeHealthDecline"

    $configuration.codeSceneBaseUrl = Get-VstsInput -Name codeSceneBaseUrl
    $configuration.projectRESTEndpoint = Get-VstsInput -Name projectRESTEndpoint
    $configuration.codeSceneAPIUserName = Get-VstsInput -Name codeSceneAPIUserName
    $configuration.codeSceneAPIPassword = Get-VstsInput -Name codeSceneAPIPassword
    $configuration.taskDefinitionsUri = $env:SYSTEM_TASKDEFINITIONSURI
    $configuration.teamProject = $env:SYSTEM_TEAMPROJECT
    
    $pullRequest.repositoryName = $env:BUILD_REPOSITORY_NAME
    $pullRequest.repositoryId = $env:BUILD_REPOSITORY_ID
    $pullRequest.sourceBranch = $env:BUILD_SOURCEBRANCH

    Write-VstsTaskVerbose "Repository name:                   $($pullRequest.repositoryName)"
    Write-VstsTaskVerbose "Source branch:                     $($pullRequest.sourceBranch)"
    Write-VstsTaskVerbose "Risk level threshold:              $($rules.riskLevelThreshold)"
    Write-VstsTaskVerbose "Fail on high delivery risk level:  $($rules.failOnHighRisk)"
    Write-VstsTaskVerbose "Fail on violated goal:             $($rules.failOnViolatedGoal)"
    Write-VstsTaskVerbose "Fail on code health decline:       $($rules.failOnCodeHealthDecline)"
    Write-VstsTaskVerbose "Coupling threshold:                $($rules.couplingThreshold)"
    Write-VstsTaskVerbose "Task definitions uri:              $($configuration.taskDefinitionsUri)"
    Write-VstsTaskVerbose "Team project:                      $($configuration.teamProject)"

    if ($pullRequest.sourceBranch -like "*pull*") {
        $pullRequest.id = (($pullRequest.sourceBranch).Replace("refs/pull/","")).replace("/merge","")

        Write-VstsTaskVerbose "Pull request id:                   $($pullRequest.id)"

        $pullRequest.statusState = "pending"
        $pullRequest.statusDescription = "CodeScene Delta Analysis ongoing..."
        $pullRequest.statusContextName = $pullRequestStatusContextName
        Update-PullRequestStatus -pullRequest $pullRequest -configuration $configuration
        $pullRequest.commits = Get-PullRequestCommits -pullRequest $pullRequest -configuration $configuration
        $analysisResult = Request-DeltaAnalysis -pullRequest $pullRequest -configuration $configuration -rules $rules
        # $analysisResult = Set-TestAnalysisResults -analysisResult $analysisResult
        $failures = Set-Failures -analysisResult $analysisResult -rules $rules
        if ($failures.Length -gt 0) {
            $pullRequest.statusState = "failed"
            $pullRequest.statusDescription = "CodeScene Delta Analysis failed: $($analysisResult.result.description)"
            if ($failures -eq $rules.failOnHighRisk.failureName) { $pullRequest.statusDescription += " | Risk level is too high: $($analysisResult.result.risk)" }
            if ($failures -eq $rules.failOnViolatedGoal.failureName) { $pullRequest.statusDescription += " | Goals violated" }
            if ($failures -eq $rules.failOnCodeHealthDecline.failureName) { $pullRequest.statusDescription += " | Code health has declined" }
        }
        else {
            $pullRequest.statusState = "succeeded"
            $pullRequest.statusDescription = "CodeScene Delta Analysis passed"
        }
        $pullRequest.statusTargetUrl = $configuration.codeSceneBaseUrl + $analysisResult.view
        Update-PullRequestStatus -pullRequest $pullRequest -configuration $configuration
    }
    else {
        Write-Host "Not a pull request build!"
    }
} finally {
    Trace-VstsLeavingInvocation $MyInvocation
}
