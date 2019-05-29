[CmdletBinding()]
param()

function New-Rules {
    $rules = @{}

    $rules.useBiomarkers = @{ value = $true }
    $rules.riskLevelThreshold = @{ value = Get-VstsInput -Require -Name riskLevelThreshold -AsInt }
    $rules.couplingThreshold = @{ value = Get-VstsInput -Require -Name couplingThreshold -AsInt }
    $rules.failTestCaseOnDeliveryRiskFail = Get-VstsInput -Require -Name failTestCaseOnDeliveryRiskFail -AsBool
    $rules.failTestCasePlannedGoalsFail = Get-VstsInput -Require -Name failTestCasePlannedGoalsFail -AsBool
    $rules.failTestCaseCodeHealthFail = Get-VstsInput -Require -Name failTestCaseCodeHealthFail -AsBool

    return $rules
}

function New-Configuration {
    $configuration = @{}

    $configuration.azureDevOpsAPItoken = Get-VstsInput -Require -Name azureDevOpsAPItoken # Azure DevOps PAT to be used for local debugging. For more details, please see https://docs.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate?view=azure-devops#create-personal-access-tokens-to-authenticate-access
    $configuration.codeSceneBaseUrl = Get-VstsInput -Require -Name codeSceneBaseUrl
    $configuration.projectRESTEndpoint = Get-VstsInput -Require -Name projectRESTEndpoint
    $configuration.codeSceneAPIUserName = Get-VstsInput -Require -Name codeSceneAPIUserName
    $configuration.codeSceneAPIPassword = Get-VstsInput -Require -Name codeSceneAPIPassword
    $configuration.taskDefinitionsUri = $env:SYSTEM_TASKDEFINITIONSURI
    $configuration.teamFoundationServerUri = $env:SYSTEM_TEAMFOUNDATIONSERVERURI
    $configuration.teamProject = $env:SYSTEM_TEAMPROJECT
    $configuration.pipelineContext = Get-Pipeline-Context
    $configuration.azureDevOpsAuthHeader = Get-AzureDevOpsAuthHeader

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

function Get-AzureDevOpsAuthHeader {
    if (!([string]::IsNullOrEmpty($configuration.azureDevOpsAPItoken))) {
        Write-VstsTaskVerbose "Using provided Personal Access Token."
        # Base64-encodes the Personal Access Token (PAT) appropriately
        $user = ""
        $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user,$configuration.azureDevOpsAPItoken)))
        $authHeader = @{Authorization=("Basic {0}" -f $base64AuthInfo)}
    }
    elseif (!([string]::IsNullOrEmpty($env:SYSTEM_ACCESSTOKEN))) {
        Write-VstsTaskVerbose "Using shared VSTS OAuth token."
        $authHeader = @{Authorization = "Bearer $env:SYSTEM_ACCESSTOKEN"}
    }
    else {
        Write-Error "No token provided! Either provide Personal Access Token or enable Allow scripts to access OAuth token in your environment settings."
    }
    return $authHeader
}

function Get-Releases {
    param (
        [Parameter(Mandatory=$true)]$releaseDefinitionId,
        [Parameter(Mandatory=$true)]$configuration
    )
    $releaseApiBaseUri = "$($configuration.teamFoundationServerUri)DefaultCollection/$($configuration.teamProject)/_apis/release/"
    $releaseApiVersion = "5.0"
    $requestUri = "$($releaseApiBaseUri)releases?definitionId=$($releaseDefinitionId)&api-version=$($releaseApiVersion)"
    Write-VstsTaskVerbose "Looking for releases in the current release definition..."
    $response = Invoke-RestMethod -Uri $requestUri -Method Get -ContentType "application/json" -Headers $configuration.azureDevOpsAuthHeader
    $releases = $response.value
    Write-VstsTaskVerbose "Found $($releases.Count) releases for the given current definition."
    return $releases
}

function Get-PreviousEnvironmentRelease {
    param (
        [Parameter(Mandatory=$true)]$releases,
        [Parameter(Mandatory=$true)]$currentReleaseId,
        [Parameter(Mandatory=$true)]$environmentName,
        [Parameter(Mandatory=$true)]$configuration
    )
    Write-VstsTaskVerbose "Looking for the latest deployment to $environmentName..."
    $releaseApiBaseUri = "$($configuration.teamFoundationServerUri)DefaultCollection/$($configuration.teamProject)/_apis/release/"
    $releaseApiVersion = "5.0"
    # Look through all releases for the latest one deployed to the given environment
    foreach ($release in $releases) {
        Write-VstsTaskVerbose "Looking into release with ID $($release.id)..."
        if ([int]($release.id) -ge [int]$currentReleaseId) {
            Write-VstsTaskVerbose "Skipping current or newer release."
            continue
        }
        $requestUri = "$($releaseApiBaseUri)/releases/$($release.id)?api-version=$($releaseApiVersion)"
        $response = Invoke-RestMethod -Uri $requestUri -Method Get -ContentType "application/json" -Headers $configuration.azureDevOpsAuthHeader
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
    $releaseApiBaseUri = "$($configuration.teamFoundationServerUri)DefaultCollection/$($configuration.teamProject)/_apis/release/"
    $releaseApiVersion = "5.0-preview"
    $requestUri = "$($releaseApiBaseUri)/releases/$($currentReleaseId)/changes?baseReleaseId=$previousReleaseId&api-version=$($releaseApiVersion)"
    $response = Invoke-RestMethod -Uri $requestUri -Method Get -ContentType "application/json" -Headers $configuration.azureDevOpsAuthHeader
    return $response.value
}

function Get-Commits {
    param (
        [Parameter(Mandatory=$true)]$context,
        [Parameter(Mandatory=$true)]$configuration
    )
    Write-Host "Gathering commits..."
    switch ($configuration.pipelineContext) {
        "build" {
            Write-VstsTaskVerbose "Getting commits for build $($context.buildId)"
            $buildApiBaseUri = "$($configuration.taskDefinitionsUri)$($configuration.teamProject)/_apis/build/"
            $buildApiVersion = "5.0"
            $requestUri = "$($buildApiBaseUri)builds/$($context.buildId)/changes?api-version=$($buildApiVersion)"
            $response = Invoke-RestMethod -Uri $requestUri -Method GET -Headers $configuration.azureDevOpsAuthHeader
            $commits = $response.value
        }
        "release" {
            Write-VstsTaskVerbose "Getting commits for release $($context.releaseId)"
            $releases = Get-Releases -releaseDefinitionId $context.releaseDefinitionId -configuration $configuration
            $previousRelease = Get-PreviousEnvironmentRelease -releases $releases -environmentName $context.environmentName -currentReleaseId $context.releaseId -configuration $configuration
            $commits = Get-EnvironmentCommits -currentReleaseId $context.releaseId -previousReleaseId $previousRelease.id -configuration $configuration
        }
        Default {}
    }
    Write-VstsTaskVerbose "Found $($commits.Count) commits."
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

function ConvertTo-Hashtable {
    param (
        [Parameter(Mandatory=$true)]$object
    )
    $hashTable = @{}
    foreach ($element in $object) {
        $hashTable."$($element.category)" = $element.details
    }
    return $hashTable
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
    Write-Host "Requesting CodeScene Delta Analysis..."
    Write-VstsTaskVerbose "Commit Id(s): $($commitIds)"
    $deltaAnalysisApiUri = "$($configuration.codeSceneBaseUrl)/$($configuration.projectRESTEndpoint)"
    # ========= NB! For testing purposes only! Remove before completing PR! =========
    # $deltaAnalysisApiUri = "https://stsingaporeinternaltest.azurewebsites.net/api/CodeSceneDeltaAnalysisMock"
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
    $response = Invoke-RestMethod -Uri $deltaAnalysisApiUri -Method POST -Body $payload -ContentType "application/json" -Headers $header
    $response.result.warnings = ConvertTo-Hashtable -object $response.result.warnings
    Write-Host "CodeScene DeltaAnalysis Done."
    Write-VstsTaskVerbose "Delivery risk: $($response.result.risk) - $($response.result.description)"
    Write-VstsTaskVerbose "Planned Goals: $($testResultOutcomes.Item([boolean]($response.result.'quality-gates'.'violates-goal')))"
    Write-VstsTaskVerbose "Code Health: $($testResultOutcomes.Item([boolean]($response.result.'quality-gates'.'degrades-in-code-health')))"
    return $response
}

function New-VSTestRun {
    param (
        [Parameter(Mandatory=$true)]$configuration,
        [Parameter(Mandatory=$true)]$context,
        [Parameter(Mandatory=$true)]$timer
    )
    Write-VstsTaskVerbose "Starting a new test run..."
    $testRunData = @{
        state = "InProgress"
        automated = $true
        errorMessage = ""
        build = @{
            id = $context.buildId
        }
        startDate = [Xml.XmlConvert]::ToString(($timer.analysisRunStarted),[Xml.XmlDateTimeSerializationMode]::Utc)
    }
    switch ($configuration.pipelineContext) {
        "build" {
            $testRunData.name = "CodeScene Delta Analysis - $($context.buildDefinitionName)"
        }
        "release" {
            $testRunData.name = "CodeScene Delta Analysis - $($context.releaseDefinitionName)"
            $testRunData.releaseUri = $context.releaseUri
            $testRunData.releaseEnvironmentUri = $context.environmentUri
        }
        Default {}
    }
    $testApiBaseUri = "$($configuration.taskDefinitionsUri)$($configuration.teamProject)/_apis/test/"
    $testApiVersion = "5.0"
    $requestUri = "$($testApiBaseUri)runs?api-version=$($testApiVersion)"
    $body = $testRunData | ConvertTo-Json
    $testRun = Invoke-RestMethod -Uri $requestUri -Method POST -Body $body -ContentType "application/json" -Headers $configuration.azureDevOpsAuthHeader
    Write-VstsTaskVerbose "Test run with id $($testRun.id) started."
    return $testRun
}

function Complete-VSTestRun {
    param (
        [Parameter(Mandatory=$true)]$configuration,
        [Parameter(Mandatory=$true)]$testRunId,
        [Parameter(Mandatory=$true)]$context,
        [Parameter(Mandatory=$true)]$timer
    )
    Write-VstsTaskVerbose "Completing test run..."
    $report = New-PlainTextAnalysisReport -context $context -analysisResult $analysisResult -timer $timer
    $testRunData = @{
        state = "Completed"
        completedDate = [Xml.XmlConvert]::ToString(($timer.analysisRunCompleted),[Xml.XmlDateTimeSerializationMode]::Utc)
        errorMessage = $report.short
    }
    $testApiBaseUri = "$($configuration.taskDefinitionsUri)$($configuration.teamProject)/_apis/test/"
    $testApiVersion = "5.0"
    $requestUri = "$($testApiBaseUri)runs/$($testRunId)?api-version=$($testApiVersion)"
    $body = $testRunData | ConvertTo-Json
    Invoke-RestMethod -Uri $requestUri -Method PATCH -Body $body -ContentType "application/json" -Headers $configuration.azureDevOpsAuthHeader > $null
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($report.full)
    $encoded = [System.Convert]::ToBase64String($bytes)
    $testRunAttachmentBody = @{
        stream = $encoded
        fileName = "report.txt"
        comment = "Test attachment upload"
        attachmentType = "GeneralAttachment"
    }
    $testApiVersion = "5.0-preview.1"
    $requestUri = "$($testApiBaseUri)runs/$($testRunId)/attachments?api-version=$($testApiVersion)"
    $body = $testRunAttachmentBody | ConvertTo-Json
    Invoke-RestMethod -Uri $requestUri -Method POST -Body $body -ContentType "application/json" -Headers $configuration.azureDevOpsAuthHeader > $null    
    Write-VstsTaskVerbose "Test run completed."
}

function Add-VSTestResults {
    param (
        [Parameter(Mandatory=$true)]$analysisResult,
        [Parameter(Mandatory=$true)]$configuration,
        [Parameter(Mandatory=$true)]$testRunId,
        [Parameter(Mandatory=$true)]$rules,
        [Parameter(Mandatory=$true)]$context,
        [Parameter(Mandatory=$true)]$timer
    )
    Write-VstsTaskVerbose "Adding test results..."
    $timePerTest = [int]((New-TimeSpan -Start $timer.analysisRunStarted.Ticks -End $timer.analysisRunCompleted.Ticks).TotalMilliseconds / 3)
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
            durationInMs = $timePerTest
            computerName = "CodeScene Delta Analysis"
            automatedTestType = "UnitTest"
            owner = @{
                displayName = "CodeScene"
            }
        },
        @{
            testCaseTitle = "Planned Goals"
            errorMessage = $($analysisResult.result.warnings.'Violates Goals')
            outcome = $testResultOutcomes.Item([boolean]($analysisResult.result.'quality-gates'.'violates-goal'))
            automatedTestName = "CodeScene.DeltaAnalysis.PlannedGoals.$($testNamePostFix)"
            state = "Completed"
            durationInMs = $timePerTest
            computerName = "CodeScene Delta Analysis"
            automatedTestType = "UnitTest"
            owner = @{
                displayName = "CodeScene"
            }
        },
        @{
            testCaseTitle = "Code Health"
            errorMessage = $($analysisResult.result.warnings.'Degrades in Code Health')
            outcome = $testResultOutcomes.Item([boolean]($analysisResult.result.'quality-gates'.'degrades-in-code-health'))
            automatedTestName = "CodeScene.DeltaAnalysis.CodeHealth$($testNamePostFix)"
            state = "Completed"
            durationInMs = $timePerTest
            computerName = "CodeScene Delta Analysis"
            automatedTestType = "UnitTest"
            owner = @{
                displayName = "CodeScene"
            }
        }
    )
    $testApiBaseUri = "$($configuration.taskDefinitionsUri)$($configuration.teamProject)/_apis/test/"
    $testApiVersion = "5.0"
    $requestUri = "$($testApiBaseUri)runs/$($testRunId)/results?api-version=$($testApiVersion)"
    $body = $testResults | ConvertTo-Json
    Invoke-RestMethod -Uri $requestUri -Method POST -Body $body -ContentType "application/json" -Headers $configuration.azureDevOpsAuthHeader > $null
    Write-VstsTaskVerbose "Test results added."
}

function New-PlainTextAnalysisReport {
    param (
        [Parameter(Mandatory=$true)]$context,
        [Parameter(Mandatory=$true)]$analysisResult,
        [Parameter(Mandatory=$true)]$timer
    )
    $report = @{}
    $shortReport = "For more information, see attachments."
    $shortReport += "`r`n"
    $shortReport += "Delivery risk: $($analysisResult.result.risk)`r`n$($analysisResult.result.description)"
    if ($analysisResult.result.warnings.Count -gt 0) {
        $shortReport += "`r`n"
        $shortReport += "Warnings:"
        foreach ($warning in $analysisResult.result.warnings.GetEnumerator()) {
            $shortReport += "`r`n"
            $shortReport += " - $($warning.Key)"
        }
    }
    $report.short = $shortReport
    $fullReport = "=== Delta Analysis Report ==="
    $fullReport += "`r`n"
    $commitIds = @()
    foreach ($commit in $context.commits) {
        $commitIds += $commit.id
    }
    $commitIds = $commitIds -join "`r`n"

    $tableData = @{
        "Project" = $context.releaseDefinitionName
        "Repository" = $context.repositoryName
        "Commits" = $commitIds
        "Analyzed At" = $timer.analysisRunCompleted
        "Risk Classification (1-10)" = $analysisResult.result.risk
        "Description" = $analysisResult.result.description
    }
    
    $tabName = "CodeScene Delta Analysis Report"
    $table = New-Object system.Data.DataTable “$tabName”

    #Define Columns
    $col1 = New-Object system.Data.DataColumn Name,([string])
    $col2 = New-Object system.Data.DataColumn Value,([string])

    #Add the Columns
    $table.columns.add($col1)
    $table.columns.add($col2)

    foreach ($entry in $tableData.GetEnumerator()) {
        $row = $table.NewRow()
        $row.Name = $entry.Key 
        $row.Value = $entry.Value
        $table.Rows.Add($row)
    }
    $fullReport += ($table | Format-Table -AutoSize -HideTableHeaders) | Out-String
    if ($analysisResult.result.warnings.Count -gt 0) {
        $fullReport += "`r`n"
        $fullReport += "--- Warnings ---"
        foreach ($warning in $analysisResult.result.warnings.GetEnumerator()) {
            $fullReport += "`r`n"
            $fullReport += "- $($warning.Key)"
            foreach ($detail in $warning.Value) {
                $fullReport += "`r`n`t$($detail)"
            }
            $fullReport += "`r`n"
        }
    }
    if ($analysisResult.result.improvements.Count -gt 0) {
        $fullReport += "`r`n"
        $fullReport += "--- Improvements ---"
        foreach ($improvement in $analysisResult.result.improvements.GetEnumerator()) {
            $fullReport += "`r`n"
            $fullReport += "- $($improvement)"
        }
    }
    $report.full = $fullReport
    return $report
}

function New-HtmlAnalysisReport {
    param (
        [Parameter(Mandatory=$true)]$context,
        [Parameter(Mandatory=$true)]$analysisResult,
        [Parameter(Mandatory=$true)]$timer
    )
    $commitIds = @()
    foreach ($commit in $context.commits) {
        $commitIds += $commit.id
    }
    $commitIds = $commitIds -join "`r`n"

    $tableData = @{
        "Project" = $context.releaseDefinitionName
        "Repository" = $context.repositoryName
        "Commits" = $commitIds
        "Analyzed At" = $timer.analysisRunCompleted
        "Risk Classification (1-10)" = $analysisResult.result.risk
        "Description" = $analysisResult.result.description
    }
    $reportData = @()
    foreach ($entry in $tableData.GetEnumerator()) {
        $reportDataItem = New-Object PSCustomObject
        $reportDataItem | Add-Member -MemberType NoteProperty -Name Key -Value $entry.Key
        $reportDataItem | Add-Member -MemberType NoteProperty -Name Value -Value $entry.Value
    
        $reportData += $reportDataItem
    }
    # if ($analysisResult.result.warnings.Count -gt 0) {
    #     $fullReport += "`r`n"
    #     $fullReport += "--- Warnings ---"
    #     foreach ($warning in $analysisResult.result.warnings.GetEnumerator()) {
    #         $fullReport += "`r`n"
    #         $fullReport += "- $($warning.Key)"
    #         foreach ($detail in $warning.Value) {
    #             $fullReport += "`r`n`t$($detail)"
    #         }
    #         $fullReport += "`r`n"
    #     }
    # }
    # if ($analysisResult.result.improvements.Count -gt 0) {
    #     $fullReport += "`r`n"
    #     $fullReport += "--- Improvements ---"
    #     foreach ($improvement in $analysisResult.result.improvements.GetEnumerator()) {
    #         $fullReport += "`r`n"
    #         $fullReport += "- $($improvement)"
    #     }
    # }
    switch ($configuration.pipelineContext) {
        "build" {
            $reportSubTitle = $context.buildDefinitionName
        }
        "release" {
            $reportSubTitle = $context.releaseDefinitionName
        }
        Default {}
    }
    # Generate html file
    $a = "<style>"
    $a = $a + "BODY{background-color:white;font-family:`"Helvetica Neue`",Helvetica,Arial,sans-serif;}"
    $a = $a + "TABLE{border-width: 1px;border-style: none;border-color: black;border-collapse: collapse;}"
    $a = $a + "TH{display:none;}"
    $a = $a + "TD{border-width: 1px;padding: 0px;border-style: none;border-color: black;padding:5px;font-size: 12px;}"
    $a = $a + "tr:nth-child(even){background-color: #dcdcdc}"
    $a = $a + "</style>"
    $a = $a + "<title>$($reportSubTitle)</title>"

    $html = $reportData | ConvertTo-HTML -head $a -body "<H1>CodeScene Delta Analysis Result</H1><H3>$($reportSubTitle)</H3>" -PostContent "HejHej"
    $html -replace '&gt;','>' -replace '&lt;','<' -replace '&#39;',"'" -replace '&quot;','"' | Out-File "C:\Users\tobia\Downloads\report.htm"
    return $report
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
    $timer.analysisRunStarted = Get-Date
    $testRun = New-VSTestRun -configuration $configuration -context $context -timer $timer
    $analysisResult = Request-DeltaAnalysis -context $context -configuration $configuration -rules $rules
    $timer.analysisRunCompleted = Get-Date
    Add-VSTestResults -analysisResult $analysisResult -rules $rules -configuration $configuration -testRunId $testRun.id -context $context -timer $timer
    Complete-VSTestRun -configuration $configuration -context $context -timer $timer -testRunId $testRun.id
    # $htmlReport = New-HtmlAnalysisReport -context $context -analysisResult $analysisResult -timer $timer
} finally {
    Trace-VstsLeavingInvocation $MyInvocation
}