[CmdletBinding()]
param()

function New-Rules {
    $rules = @{}

    $rules.useBiomarkers = @{ value = $true }
    $rules.riskLevelThreshold = @{ value = Get-VstsInput -Name riskLevelThreshold -AsInt }
    $rules.couplingThreshold = @{ value = Get-VstsInput -Name couplingThreshold -AsInt }
    $rules.failTestCaseOnDeliveryRiskFail = Get-VstsInput -Name failTestCaseOnDeliveryRiskFail -AsBool
    $rules.failTestCasePlannedGoalsFail = Get-VstsInput -Name failTestCasePlannedGoalsFail -AsBool
    $rules.failTestCaseCodeHealthFail = Get-VstsInput -Name failTestCaseCodeHealthFail -AsBool

    return $rules
}

function New-Configuration {
    $configuration = @{}

    $configuration.azureDevOpsAPItoken = Get-VstsInput -Name azureDevOpsAPItoken # Azure DevOps PAT to be used for local debugging. For more details, please see https://docs.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate?view=azure-devops#create-personal-access-tokens-to-authenticate-access
    $configuration.codeSceneBaseUrl = Get-VstsInput -Name codeSceneBaseUrl
    $configuration.projectRESTEndpoint = Get-VstsInput -Name projectRESTEndpoint
    $configuration.codeSceneAPIUserName = Get-VstsInput -Name codeSceneAPIUserName
    $configuration.codeSceneAPIPassword = Get-VstsInput -Name codeSceneAPIPassword
    $configuration.taskDefinitionsUri = $env:SYSTEM_TASKDEFINITIONSURI
    $configuration.teamFoundationServerUri = $env:SYSTEM_TEAMFOUNDATIONSERVERURI
    $configuration.teamProject = $env:SYSTEM_TEAMPROJECT
    $configuration.pipelineContext = Get-Pipeline-Context

    return $configuration
}

function New-Context {
    $context = @{}
    
    $context.repositoryName = $env:BUILD_REPOSITORY_NAME
    $context.repositoryId = $env:BUILD_REPOSITORY_ID
    $context.sourceBranch = $env:BUILD_SOURCEBRANCH
    $context.buildId = $env:BUILD_BUILDID
    $context.buildDefinitionId = $env:BUILD_DEFINITIONID
    $context.buildDefinitionName = $env:BUILD_DEFINITIONNAME
    $context.releaseId = $env:RELEASE_RELEASEID
    $context.releaseDefinitionId = $env:RELEASE_DEFINITIONID
    $context.releaseDefinitionName = $env:RELEASE_DEFINITIONNAME
    $context.environmentName = $env:RELEASE_ENVIRONMENTNAME
    $context.releaseUri = $env:RELEASE_RELEASEURI
    $context.environmentUri = $env:RELEASE_ENVIRONMENTURI

    return $context
}
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
            return $release
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

function Get-Commits {
    param (
        [Parameter(Mandatory=$true)]$context,
        [Parameter(Mandatory=$true)]$configuration
    )
    switch ($configuration.pipelineContext) {
        "build" {
            $header = Get-AzureDevOpsAPIHeader
            $buildApiBaseUri = "$($configuration.taskDefinitionsUri)$($configuration.teamProject)/_apis/build/"
            $buildApiVersion = "5.0"
            $requestUri = "$($buildApiBaseUri)builds/$($context.buildId)/changes?api-version=$($buildApiVersion)"
            $response = Invoke-RestMethod -Uri $requestUri -Method GET -Headers $header
            $commits = $response.value
        }
        "release" {
            $releases = Get-Releases -releaseDefinitionId $context.releaseDefinitionId -configuration $configuration
            $previousRelease = Get-PreviousEnvironmentRelease -releases $releases -environmentName $context.environmentName -currentReleaseId $context.releaseId -configuration $configuration
            $commits = Get-EnvironmentCommits -currentReleaseId $context.releaseId -previousReleaseId $previousRelease.id -configuration $configuration
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

function Request-DeltaAnalysis {
    param (
        [Parameter(Mandatory=$true)]$context,
        [Parameter(Mandatory=$true)]$configuration,
        [Parameter(Mandatory=$true)]$rules
    )
    $commitIds = @()
    foreach ($commit in $context.commits) {
        $commitIds += $commit.id
    }
    Write-VstsTaskVerbose "Commit Id(s):                      $($commitIds)"
    $deltaAnalysisApiUri = "$($configuration.codeSceneBaseUrl)/$($configuration.projectRESTEndpoint)"
    $credentialsPair = "$($configuration.codeSceneAPIUserName):$($configuration.codeSceneAPIPassword)"
    $basicToken = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credentialsPair))
    $header = @{ Authorization = "Basic $($basicToken)" }
    $body = @{
        commits = $commitIds
        repository = $context.repositoryName
        coupling_threshold_percent = $rules.couplingThreshold.value
        use_biomarkers = $rules.useBiomarkers.value
    }
    $payload = $body | ConvertTo-Json
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Write-VstsTaskVerbose "Requesting CodeScene Delta Analysis"
    $response = Invoke-RestMethod -Uri $deltaAnalysisApiUri -Method POST -Body $payload -ContentType "application/json" -Headers $header
    return $response
}

function New-VSTestRun {
    param (
        [Parameter(Mandatory=$true)]$configuration,
        [Parameter(Mandatory=$true)]$context,
        [Parameter(Mandatory=$true)]$timer
    )
    $testRun = @{
        state = "InProgress"
        automated = $true
        errorMessage = ""
        build = @{
            id = $context.buildId
        }
        startDate = $timer.analysisRunStarted
    }
    switch ($configuration.pipelineContext) {
        "build" {
            $testRun.name = "CodeScene Delta Analysis - $($context.buildDefinitionName)"
        }
        "release" {
            $testRun.name = "CodeScene Delta Analysis - $($context.releaseDefinitionName)"
            $testRun.releaseUri = $context.releaseUri
            $testRun.releaseEnvironmentUri = $context.environmentUri
        }
        Default {}
    }
    $header = Get-AzureDevOpsAPIHeader
    $testApiBaseUri = "$($configuration.taskDefinitionsUri)$($configuration.teamProject)/_apis/test/"
    $testApiVersion = "5.0"
    $requestUri = "$($testApiBaseUri)runs?api-version=$($testApiVersion)"
    $body = $testRun | ConvertTo-Json
    return Invoke-RestMethod -Uri $requestUri -Method POST -Body $body -ContentType "application/json" -Headers $header
}

function Complete-VSTestRun {
    param (
        [Parameter(Mandatory=$true)]$configuration,
        [Parameter(Mandatory=$true)]$testRunId,
        [Parameter(Mandatory=$true)]$context,
        [Parameter(Mandatory=$true)]$timer
    )
    $testRun = @{
        state = "Completed"
        completedDate = $timer.analysisRunCompleted
    }
    $header = Get-AzureDevOpsAPIHeader
    $testApiBaseUri = "$($configuration.taskDefinitionsUri)$($configuration.teamProject)/_apis/test/"
    $testApiVersion = "5.0"
    $requestUri = "$($testApiBaseUri)runs/$($testRunId)?api-version=$($testApiVersion)"
    $body = $testRun | ConvertTo-Json
    Invoke-RestMethod -Uri $requestUri -Method PATCH -Body $body -ContentType "application/json" -Headers $header > $null
}

function Add-VSTestResults {
    param (
        [Parameter(Mandatory=$true)]$analysisResult,
        [Parameter(Mandatory=$true)]$configuration,
        [Parameter(Mandatory=$true)]$testRunId,
        [Parameter(Mandatory=$true)]$rules,
        [Parameter(Mandatory=$true)]$context
    )
    $resultsWarnings = @{}
    foreach ($warning in $analysisResult.result.warnings) {
        $resultsWarnings."$($warning.category)" = $warning.details
    }
    $deliveryRiskFailed = Get-RiskVerdict -risk $analysisResult.result.risk -threshold $rules.riskLevelThreshold.value
    $deliveryRiskOutcome = $testResultOutcomes.Item($deliveryRiskFailed)
    switch ($configuration.pipelineContext) {
        "build" { $testNamePostFix = $context.buildDefinitionId }
        "release" { $testNamePostFix = $context.releaseDefinitionId }
        Default {}
    }
    $testResults = @(
        @{
            testCaseTitle = "Delivery Risk"
            errorMessage = "Delivery risk: $($analysisResult.result.risk) - $($analysisResult.result.description)"
            outcome = $deliveryRiskOutcome
            automatedTestName = "CodeScene.DeltaAnalysis.DeliveryRisk.$($testNamePostFix)"
            state = "Completed"
            computerName = "CodeScene Delta Analysis"
            automatedTestType = "UnitTest"
            owner = @{
                displayName = "CodeScene"
            }
        },
        @{
            testCaseTitle = "Planned Goals"
            errorMessage = "$($resultsWarnings.'Violates Goals')"
            outcome = $testResultOutcomes.Item([boolean]($analysisResult.result.'quality-gates'.'violates-goal'))
            automatedTestName = "CodeScene.DeltaAnalysis.PlannedGoals.$($testNamePostFix)"
            state = "Completed"
            computerName = "CodeScene Delta Analysis"
            automatedTestType = "UnitTest"
            owner = @{
                displayName = "CodeScene"
            }
        },
        @{
            testCaseTitle = "Code Health"
            errorMessage = "$($resultsWarnings.'Degrades in Code Health')"
            outcome = $testResultOutcomes.Item([boolean]($analysisResult.result.'quality-gates'.'degrades-in-code-health'))
            automatedTestName = "CodeScene.DeltaAnalysis.CodeHealth$($testNamePostFix)"
            state = "Completed"
            computerName = "CodeScene Delta Analysis"
            automatedTestType = "UnitTest"
            owner = @{
                displayName = "CodeScene"
            }
        }
    )
    $header = Get-AzureDevOpsAPIHeader
    $testApiBaseUri = "$($configuration.taskDefinitionsUri)$($configuration.teamProject)/_apis/test/"
    $testApiVersion = "5.0"
    $requestUri = "$($testApiBaseUri)runs/$($testRunId)/results?api-version=$($testApiVersion)"
    $body = $testResults | ConvertTo-Json
    Invoke-RestMethod -Uri $requestUri -Method POST -Body $body -ContentType "application/json" -Headers $header > $null
}

function Publish-AnalysisResults {

}

$testResultOutcomes = @{
    $true = "failed"
    $false = "passed"
}

Trace-VstsEnteringInvocation $MyInvocation
try {
    $rules = New-Rules
    $configuration = New-Configuration
    $context = New-Context

    $timer = @{}

    Write-VstsTaskVerbose "Repository name:                   $($context.repositoryName)"
    Write-VstsTaskVerbose "Source branch:                     $($context.sourceBranch)"
    Write-VstsTaskVerbose "Risk level threshold:              $($rules.riskLevelThreshold)"
    Write-VstsTaskVerbose "Fail on delivery risk:             $($rules.failTestCaseOnDeliveryRiskFail)"
    Write-VstsTaskVerbose "Fail on planned goals:             $($rules.failTestCasePlannedGoalsFail)"
    Write-VstsTaskVerbose "Fail on code health:               $($rules.failTestCaseCodeHealthFail)"
    Write-VstsTaskVerbose "Coupling threshold:                $($rules.couplingThreshold)"
    Write-VstsTaskVerbose "Task definitions uri:              $($configuration.taskDefinitionsUri)"
    Write-VstsTaskVerbose "Team project:                      $($configuration.teamProject)"

    $context.commits = Get-Commits -context $context -configuration $configuration
    $timer.analysisRunStarted = [Xml.XmlConvert]::ToString((get-date),[Xml.XmlDateTimeSerializationMode]::Utc)
    $testRun = New-VSTestRun -configuration $configuration -context $context -timer $timer
    $analysisResult = Request-DeltaAnalysis -context $context -configuration $configuration -rules $rules
    $timer.analysisRunCompleted = [Xml.XmlConvert]::ToString((get-date),[Xml.XmlDateTimeSerializationMode]::Utc)
    Add-VSTestResults -analysisResult $analysisResult -rules $rules -configuration $configuration -testRunId $testRun.id -context $context
    Complete-VSTestRun -configuration $configuration -context $context -timer $timer -testRunId $testRun.id
} finally {
    Trace-VstsLeavingInvocation $MyInvocation
}