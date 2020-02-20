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

function Get-AzureDevOpsUser {
    param (
        [Parameter(Mandatory=$true)]$configuration
    )

    $apiVersion = "6.0-preview.3"
    $apiUrl = "https://app.vssps.visualstudio.com/_apis/profile/profiles/me?api-version=$($apiVersion)"
    $header = Get-AzureDevOpsAPIHeader
    Write-VstsTaskVerbose "Fetching pull request iterations"
    $response = Invoke-RestMethod -Uri $apiUrl -Method GET -Headers $header
    return $response
}

function Get-LatestPullRequestIteration {
    param (
        [Parameter(Mandatory=$true)]$pullRequest,
        [Parameter(Mandatory=$true)]$configuration
    )

    $apiVersion = "5.0"
    $apiUrl = "$($configuration.taskDefinitionsUri)$($configuration.teamProject)/_apis/git/repositories/$($pullRequest.repositoryId)/pullRequests/$($pullRequest.id)/iterations?includeCommits=true&api-version=$($apiVersion)"
    $header = Get-AzureDevOpsAPIHeader
    Write-VstsTaskVerbose "Fetching pull request iterations"
    $response = Invoke-RestMethod -Uri $apiUrl -Method GET -Headers $header
    $iterations = $response.value
    $latestIterationId = 0
    foreach ($iteration in $iterations.GetEnumerator()) {
        if ($iteration.id -gt $latestIterationId) { $latestIterationId = $iteration.id }
    }
    return $latestIterationId
}

function Update-PullRequestIterationStatus {
    param (
        [Parameter(Mandatory=$true)]$pullRequest,
        [Parameter(Mandatory=$true)]$status,
        [Parameter(Mandatory=$true)]$configuration
    )

    $statusApiVersion = "5.0-preview.1"
    $statusApiUri = "$($configuration.taskDefinitionsUri)$($configuration.teamProject)/_apis/git/repositories/$($pullRequest.repositoryName)/pullRequests/$($pullRequest.id)/iterations/$($pullRequest.currentIterationId)/statuses?api-version=$($statusApiVersion)"
    $body = @{
        state = $status.Value.state
        description = $status.Value.description
        context = @{
            genre = $configuration.statusGenre
            name = $status.Value.statusContextName
        }
    }
    if ($status.Value.targetUrl) {
        $body.targetUrl = $status.Value.targetUrl
    }
    $header = Get-AzureDevOpsAPIHeader
    $payload = $body | ConvertTo-Json
    Write-VstsTaskVerbose "Updating pull request iteration status"
    Invoke-RestMethod -Uri $statusApiUri -Method POST -Body $payload -ContentType "application/json " -Headers $header > $null
}

function Test-IsCodeChange {
    param (
        [Parameter(Mandatory=$true)]$warningDescription,
        [Parameter(Mandatory=$true)]$rules
    )
    $extension = ($warningDescription -split ("\."))[-1]
    if ($extension -in $rules.sourceCodeFileExtensions) {
        return $true
    }
    return $false
}

function Get-PullRequestThreads {
    param (
        [Parameter(Mandatory=$true)]$pullRequest,
        [Parameter(Mandatory=$true)]$configuration
    )
    $activeThreads = @()
    $header = Get-AzureDevOpsAPIHeader
    $threadApiVersion = "5.1"
    $threadApiUri = "$($configuration.taskDefinitionsUri)$($configuration.teamProject)/_apis/git/repositories/$($pullRequest.repositoryName)/pullRequests/$($pullRequest.id)/threads?api-version=$($threadApiVersion)"
    $threads = Invoke-RestMethod -Uri $threadApiUri -Method GET -ContentType "application/json " -Headers $header
    foreach ($thread in $threads.value) {
        if (!$thread.isDeleted) {
            $activeThreads += $thread
        }
    }
    return $activeThreads
}

function Remove-ThreadCommentsFromUser {
    param (
        [Parameter(Mandatory=$true)]$threads,
        [Parameter(Mandatory=$true)]$configuration
    )
    $header = Get-AzureDevOpsAPIHeader
    $apiVersion = "6.0-preview.1"
    foreach ($thread in $threads) {
        foreach ($comment in $thread.comments){
            if ($comment.author.uniqueName -eq $configuration.user.emailAddress) {
                $uri = "$($configuration.taskDefinitionsUri)$($configuration.teamProject)/_apis/git/repositories/$($pullRequest.repositoryName)/pullRequests/$($pullRequest.id)/threads/$($thread.id)/comments/$($comment.id)?api-version=$($apiVersion)"
                Write-VstsTaskVerbose "Removing comment $($comment.id) from thread $($thread.id)"
                $threads = Invoke-RestMethod -Uri $uri -Method Delete -ContentType "application/json " -Headers $header   
            }         
        }
    }
}

function Add-PullRequestThread {
    param (
        [Parameter(Mandatory=$true)]$pullRequest,
        [Parameter(Mandatory=$true)]$configuration,
        [Parameter(Mandatory=$true)]$analysisResult,
        [Parameter(Mandatory=$true)]$rules
    )
    $threadApiVersion = "5.1"
    $threadApiUri = "$($configuration.taskDefinitionsUri)$($configuration.teamProject)/_apis/git/repositories/$($pullRequest.repositoryName)/pullRequests/$($pullRequest.id)/threads?api-version=$($threadApiVersion)"
    $threads = @()
    if (Get-RiskVerdict -risk $analysisResult.result.risk -threshold $rules.riskLevelThreshold.value) {
        $threadStatus = "active"
    }
    else {
        $threadStatus = "byDesign"
    }
    $threads += @{
        comments = @(
            @{
                parentCommentId = 0
                content = $analysisResult.result.description
                commentType = "codeChange"
            }
        )
        status = $threadStatus
    }

    if ($analysisResult.result.warnings.Count -gt 0) {
        foreach ($warning in $analysisResult.result.warnings.GetEnumerator()) {
            if ($rules.threadSettings.Item($warning.category)) {
                foreach ($detail in $warning.details) {
                    $content = $warning.category
                    $pathArray = $detail.Split('/')
                    $pathArray = $pathArray | Select-Object -Skip 1
                    $path = '/' + ($pathArray -join '/')
                    $thread = @{
                        comments = @()
                        threadContext = @{}
                        status = "active"
                    }
                    if ((Test-IsCodeChange -warningDescription $path -rules $rules) -and ($warning.category -ne "Absence of Expected Change Pattern")) {
                        $threadContext = @{
                            filePath = $detail
                        }
                        $thread.threadContext = $threadContext
                    }
                    else {
                        $content += " - " + $detail
                    }
                    $thread.comments += @{
                        parentCommentId = 0
                        content = $content
                        commentType = "codeChange"
                    }
                    $threads += $thread
                }
            }
        }
    }

    if ($analysisResult.result.'code-health-delta-descriptions'.Count -gt 0) {
        foreach ($codeHealtDeltaDescription in $analysisResult.result.'code-health-delta-descriptions'.GetEnumerator()) {
            if ($rules.threadSettings.Item("code-health-delta-descriptions")) {
                $content = "### Code health changes - " + $codeHealtDeltaDescription.name
                $path =  $codeHealtDeltaDescription.'detailed-name'
                $pathArray = $path.Split('/')
                $pathArray = $pathArray | Select-Object -Skip 1
                $detailedName = '/' + ($pathArray -join '/')
                $thread = @{
                    comments = @()
                    threadContext = @{}
                    status = "byDesign"
                }
                if (Test-IsCodeChange -warningDescription $detailedName -rules $rules) {
                    $threadContext = @{
                        filePath = $detailedName
                    }
                    $thread.threadContext = $threadContext
                }
                foreach ($item in $codeHealtDeltaDescription.degraded) {
                    $content += "`r`n- **" + $item + "**"
                    $thread.status = 'active'
                }
                foreach ($item in $codeHealtDeltaDescription.improved) {
                    $content += "`r`n- " + $item
                }
                $thread.comments += @{
                    parentCommentId = 0
                    content = $content
                    commentType = "codeChange"
                }
                $threads += $thread
            }
        }
    }

    if ($analysisResult.result.improvements.Count -gt 0) {
        foreach ($improvement in $analysisResult.result.improvements.GetEnumerator()) {
            $threads += @{
                comments = @(
                    @{
                        parentCommentId = 0
                        content = $improvement
                        commentType = "codeChange"
                    }
                )
                status = "byDesign"
            }
        }
    }

    $header = Get-AzureDevOpsAPIHeader
    foreach ($thread in $threads){
        $payload = $thread | ConvertTo-Json -Depth 10
        Write-VstsTaskVerbose "Adding pull request comment thread"
        Invoke-RestMethod -Uri $threadApiUri -Method POST -Body $payload -ContentType "application/json " -Headers $header > $null
    }
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
            description = "Delivery risk: $($analysisResult.result.risk)"
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
    $statuses.risk.state = $pullRequestStatusStates.Item($statuses.risk.failed)
    $statuses.goals.state = $pullRequestStatusStates.Item($statuses.goals.failed)
    $statuses.codeHealth.state = $pullRequestStatusStates.Item($statuses.codeHealth.failed)
    $statusWarnings = @{}
    foreach ($warning in $analysisResult.result.warnings) {
        $statusWarnings."$($warning.category)" = $warning.details
    }
    return $statuses
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
    Write-VstsTaskVerbose "Commit Id(s):                      $($commitIds)"
    $deltaAnalysisApiUri = "$($configuration.codeSceneBaseUrl)/$($configuration.projectRESTEndpoint)"
    # $deltaAnalysisApiUri = "https://stsingaporeinternaltest.azurewebsites.net/api/CodeSceneDeltaAnalysisMock"
    $credentialsPair = "$($configuration.codeSceneAPIUserName):$($configuration.codeSceneAPIPassword)"
    $basicToken = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credentialsPair))
    $header = @{ Authorization = "Basic $($basicToken)" }
    $body = @{
        commits = $commitIds
        repository = $pullRequest.repositoryName
        coupling_threshold_percent = $rules.couplingThreshold.value
        use_biomarkers = $rules.useBiomarkers.value
    }
    $payload = $body | ConvertTo-Json
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Write-VstsTaskVerbose "Requesting CodeScene Delta Analysis"
    $response = Invoke-RestMethod -Uri $deltaAnalysisApiUri -Method POST -Body $payload -ContentType "application/json " -Headers $header
    Write-VSTSTaskVerbose ($response | ConvertTo-Json)
    return $response
}

$pullRequestStatusStates = @{
    $true = "failed"
    $false = "succeeded"
}

Trace-VstsEnteringInvocation $MyInvocation
try {
    $pullRequest = @{}
    $rules = @{}
    $configuration = @{}

    $rules.useBiomarkers = @{ value = $true }
    $rules.riskLevelThreshold = @{ value = Get-VstsInput -Name riskLevelThreshold -AsInt }
    $rules.couplingThreshold = @{ value = Get-VstsInput -Name couplingThreshold -AsInt }
    $rules.publishDeliveryRiskStatus = Get-VstsInput -Name publishDeliveryRiskStatus -AsBool
    $rules.publishPlannedGoalsStatus = Get-VstsInput -Name publishPlannedGoalsStatus -AsBool
    $rules.publishCodeHealthStatus = Get-VstsInput -Name publishCodeHealthStatus -AsBool
    $rules.removeOldComments = Get-VstsInput -Name removeOldComments -AsBool
    
    $sourceCodeFileExtensions = (Get-VstsInput -Name sourceCodeFileExtensions).Replace(".", "")
    $sourceCodeFileExtensions = $sourceCodeFileExtensions.Replace(" ", "")
    $sourceCodeFileExtensions = $sourceCodeFileExtensions.Replace("*", "")

    $rules.sourceCodeFileExtensions = $sourceCodeFileExtensions -split (",")
    
    $threadSettings = @{
        "Modifies Hotspot" = $true;
        "Absence of Expected Change Pattern" = $true;
        "Degrades in Code Health" = $true;
        "Violates Goals" = $true;
        "code-health-delta-descriptions" = $true
    }

    $rules.threadSettings = $threadSettings

    $configuration.azureDevOpsAPItoken = Get-VstsInput -Name azureDevOpsAPItoken # Azure DevOps PAT to be used for local debugging. For more details, please see https://docs.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate?view=azure-devops#create-personal-access-tokens-to-authenticate-access
    $configuration.codeSceneBaseUrl = Get-VstsInput -Name codeSceneBaseUrl
    $configuration.projectRESTEndpoint = Get-VstsInput -Name projectRESTEndpoint
    $configuration.codeSceneAPIUserName = Get-VstsInput -Name codeSceneAPIUserName
    $configuration.codeSceneAPIPassword = Get-VstsInput -Name codeSceneAPIPassword
    $configuration.statusGenre = "codescene-delta-analysis"
    $configuration.taskDefinitionsUri = $env:SYSTEM_TASKDEFINITIONSURI
    $configuration.teamProject = $env:SYSTEM_TEAMPROJECT
    $configuration.user = Get-AzureDevOpsUser -configuration $configuration
    
    $pullRequest.repositoryName = $env:BUILD_REPOSITORY_NAME
    $pullRequest.repositoryId = $env:BUILD_REPOSITORY_ID
    $pullRequest.sourceBranch = $env:BUILD_SOURCEBRANCH

    Write-VstsTaskVerbose "Repository name:                   $($pullRequest.repositoryName)"
    Write-VstsTaskVerbose "Source branch:                     $($pullRequest.sourceBranch)"
    Write-VstsTaskVerbose "Risk level threshold:              $($rules.riskLevelThreshold)"
    Write-VstsTaskVerbose "Publish delivery risk status:      $($rules.publishDeliveryRiskStatus)"
    Write-VstsTaskVerbose "Publish planned goals status:      $($rules.publishPlannedGoalsStatus)"
    Write-VstsTaskVerbose "Publish code health status:        $($rules.publishCodeHealthStatus)"
    Write-VstsTaskVerbose "Coupling threshold:                $($rules.couplingThreshold)"
    Write-VstsTaskVerbose "Task definitions uri:              $($configuration.taskDefinitionsUri)"
    Write-VstsTaskVerbose "Team project:                      $($configuration.teamProject)"

    if ($pullRequest.sourceBranch -like "*pull*") {
        $pullRequest.id = (($pullRequest.sourceBranch).Replace("refs/pull/","")).replace("/merge","")

        Write-VstsTaskVerbose "Pull request id:                   $($pullRequest.id)"

        $pullRequest.commits = Get-PullRequestCommits -pullRequest $pullRequest -configuration $configuration
        $pullRequest.currentIterationId = Get-LatestPullRequestIteration -pullRequest $pullRequest -configuration $configuration
        $analysisResult = Request-DeltaAnalysis -pullRequest $pullRequest -configuration $configuration -rules $rules
        $statuses = Set-Statuses -analysisResult $analysisResult -rules $rules -configuration $configuration

        foreach($status in $statuses.GetEnumerator()) {
            Write-VstsTaskVerbose "Status context name:               $($status.Value.statusContextName)"
            Write-VstsTaskVerbose "Status description:                $($status.Value.description)"
            Write-VstsTaskVerbose "Status state:                      $($status.Value.state)"
            Write-VstsTaskVerbose "Status target url:                 $($status.Value.targetUrl)"
            if ($status.Value.publish) {
                Update-PullRequestIterationStatus -pullRequest $pullRequest -status $status -configuration $configuration
            }
        }
        if ($rules.removeOldComments) {
            $activeThreads = Get-PullRequestThreads -pullRequest $pullRequest -configuration $configuration
            Remove-ThreadCommentsFromUser -threads $activeThreads -configuration $configuration
        }

        Add-PullRequestThread -pullRequest $pullRequest -configuration $configuration -rules $rules -analysisResult $analysisResult
    }
    else {
        Write-Host "Not a pull request build!"
    }
} finally {
    Trace-VstsLeavingInvocation $MyInvocation
}