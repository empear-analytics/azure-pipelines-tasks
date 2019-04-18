[CmdletBinding()]
param()

function Get-AzureDevOpsAPIHeader {
    if (!([string]::IsNullOrEmpty($configuration.azureDevOpsAPItoken))) {
        Write-Host "Using provided Personal Access Token..."
        # Base64-encodes the Personal Access Token (PAT) appropriately
        $user = ""
        $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user,$configuration.azureDevOpsAPItoken)))
        $restApiHeader = @{Authorization=("Basic {0}" -f $base64AuthInfo)}
    }
    elseif (!([string]::IsNullOrEmpty($env:SYSTEM_ACCESSTOKEN))) {
        Write-Host "Using shared VSTS OAuth token $($env:SYSTEM_ACCESSTOKEN)..."
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
    Invoke-RestMethod -Uri $statusApiUri -Method POST -Body $statusBody -ContentType "application/json " -Headers $header
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
        coupling_threshold_percent = $rules.couplingThreshold
        use_biomarkers = "true"
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
    $pullRequestOptionalStatusContextName = "CodeSveneDeltaAnalysisOptional"
    $pullRequestRequiredStatusContextName = "CodeSveneDeltaAnalysisRequired"
    $configuration.azureDevOpsAPItoken = Get-VstsInput -Name azureDevOpsAPItoken # Azure DevOps PAT to be used for local debugging. For more details, please see https://docs.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate?view=azure-devops#create-personal-access-tokens-to-authenticate-access

    $rules.riskLevelThreshold = Get-VstsInput -Name riskLevelThreshold -AsInt
    $rules.riskLevelRequired = Get-VstsInput -Name riskLevelRequired -AsBool
    $rules.couplingThreshold = Get-VstsInput -Name couplingThreshold -AsInt

    $configuration.codeSceneBaseUrl = Get-VstsInput -Name codeSceneBaseUrl
    $configuration.projectRESTEndpoint = Get-VstsInput -Name projectRESTEndpoint
    $configuration.codeSceneAPIUserName = Get-VstsInput -Name codeSceneAPIUserName
    $configuration.codeSceneAPIPassword = Get-VstsInput -Name codeSceneAPIPassword
    $configuration.taskDefinitionsUri = $env:SYSTEM_TASKDEFINITIONSURI
    $configuration.teamProject = $env:SYSTEM_TEAMPROJECT
    
    $pullRequest.repositoryName = $env:BUILD_REPOSITORY_NAME
    $pullRequest.repositoryId = $env:BUILD_REPOSITORY_ID
    $pullRequest.sourceBranch = $env:BUILD_SOURCEBRANCH

    Write-VstsTaskVerbose "Repository name:         $($pullRequest.repositoryName)"
    Write-VstsTaskVerbose "Source branch:           $($pullRequest.sourceBranch)"
    Write-VstsTaskVerbose "Risk level threshold:    $($rules.riskLevelThreshold)"
    Write-VstsTaskVerbose "Risk level is required:  $($rules.riskLevelRequired)"
    Write-VstsTaskVerbose "Coupling threshold:      $($rules.couplingThreshold)"

    if ($pullRequest.sourceBranch -like "*pull*") {
        $pullRequest.id = (($pullRequest.sourceBranch).Replace("refs/pull/","")).replace("/merge","")

        Write-VstsTaskVerbose "Repository name:      $($pullRequest.repositoryName)"
        Write-VstsTaskVerbose "Source branch:        $($pullRequest.sourceBranch)"
        Write-VstsTaskVerbose "Task definitions uri: $($taskDefinitionsUri)"
        Write-VstsTaskVerbose "Team project:         $($teamProject)"
        Write-VstsTaskVerbose "Pull request id:      $($pullRequest.id)"

        $pullRequest.statusState = "pending"
        $pullRequest.statusDescription = "CodeScene Delta Analysis ongoing..."
        if ($rules.riskLevelRequired) { # Add more requirements here
            $pullRequest.statusContextName = $pullRequestRequiredStatusContextName
        }
        else {
            $pullRequest.statusContextName = $pullRequestOptionalStatusContextName
        }
        Update-PullRequestStatus -pullRequest $pullRequest -configuration $configuration
        $pullRequest.commits = Get-PullRequestCommits -pullRequest $pullRequest -configuration $configuration
        $analysisResult = Request-DeltaAnalysis -pullRequest $pullRequest -configuration $configuration -rules $rules
        if ($analysisResult.result.risk -gt $rules.riskLevelThreshold) { # Add more asserts here
            $pullRequest.statusState = "failed"
            $pullRequest.statusDescription = "CodeScene Delta Analysis failed"
        }
        else {
            $pullRequest.statusState = "succeeded"
            $pullRequest.statusDescription = "CodeScene Delta Analysis passed"
            $pullRequest.statusTargetUrl = $configuration.codeSceneBaseUrl + $analysisResult.view
        }
        Update-PullRequestStatus -pullRequest $pullRequest -configuration $configuration
    }
    else {
        Write-Host "Not a pull request build!"
    }
} finally {
    Trace-VstsLeavingInvocation $MyInvocation
}
