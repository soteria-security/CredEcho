function Invoke-CredEchoTriage {
    <#
    .SYNOPSIS
    Finds Microsoft Entra ID accounts whose passwords an attacker confirmed valid, then scores
    which of those accounts were subsequently accessed by someone other than their owner.

    .DESCRIPTION
    An adversary submits a fabricated client identifier to the Entra token endpoint using the
    Resource Owner Password Credentials grant. Because the security token service returns
    different errors depending on whether the username exists and whether the password is
    correct, the response itself functions as a credential oracle. The attacker learns which
    stolen credentials remain live without ever completing a sign-in, so no success-based alert
    fires.

    CredEcho runs three phases.

    Phase one derives its own target list. It queries the unified audit log for UserLoginFailed
    operations under record type azureActiveDirectoryStsLogon across the search window, keeps
    the records whose error code falls in the post-password class, and then keeps those whose
    application identifier does not correspond to a service principal in the tenant. Those are
    the validation events. Username oracle events are counted separately and reported as
    campaign context, because they establish the scale of the probing without naming an account
    whose password was confirmed.

    Phase two scores baseline-relative novelty rather than the existence of a subsequent
    sign-in. Flagging every successful sign-in after the validation timestamp would flag every
    active user in the tenant, because the legitimate owner also signs in. Three windows are
    built per account: a baseline period ending immediately before that account's first
    validation event, the validation window itself, and everything from the validation timestamp
    forward.

    Phase three collects follow-on persistence actions regardless of the sign-in verdict, since
    an actor who validated a credential months ago and registered their own authenticator
    remains visible in the directory audit log after the corresponding sign-in record has aged
    out.

    CredEcho is read only. It performs no remediation of any kind: no password resets, no token
    revocation, no session invalidation, and no blocking. It produces investigative leads and
    nothing else. Acting on those leads is a separate, deliberate decision for the analyst.

    .PARAMETER OutputDirectory
    Directory that receives AccountVerdicts.csv, ValidationEvents.csv, FlaggedSignIns.csv,
    FollowOnActions.csv, and TriageResults.json. Created when it does not exist.

    .PARAMETER SearchStartTime
    Start of the search window. Defaults to 180 days before the end time, which matches the
    default retention for Microsoft Entra audit records under Purview Audit Standard.

    .PARAMETER SearchEndTime
    End of the search window. Defaults to the current time in UTC.

    .PARAMETER BaselineDays
    Length of the per-account baseline period that ends immediately before that account's first
    validation event. Defaults to 90.

    .PARAMETER ChunkDays
    Size of each audit log query slice. Defaults to 30. A single audit log query over a long
    range returns unreliable volumes.

    .PARAMETER CorroborationAccountThreshold
    Number of distinct accounts that must have signed in successfully with an application
    identifier during the baseline period for that identifier to be treated as legitimate even
    though no service principal exists for it. Defaults to 3.

    .PARAMETER TenantWideCorroboration
    Widens the corroboration corpus from the accounts CredEcho already pulled to every
    successful sign-in in the tenant across the baseline window. This is the stronger form of
    the control and it costs a full additional set of audit log queries.

    .PARAMETER AllowedApplicationId
    Application identifiers to exclude from the validation event test, so a known internal
    client can be suppressed without editing code.

    .PARAMETER Account
    Explicit account list to triage, for a set supplied from outside the tool. Supplements phase
    one rather than replacing it. When no validation timestamp can be derived for a supplied
    account, the start of the search window is used and the output records that the timestamp
    was assumed.

    .PARAMETER AttackerIpAddress
    Source addresses to seed the indicator set from external intelligence, for use when the
    validation events themselves have aged out. Supplements the indicators derived from phase
    one.

    .PARAMETER AttackerUserAgent
    User agent strings to seed the indicator set from external intelligence. Supplements the
    indicators derived from phase one.

    .PARAMETER IncludeSignInEnrichment
    Additionally pulls Entra sign-in logs for the trailing 30 days to obtain
    authenticationRequirement, conditionalAccessStatus, authenticationProtocol, clientAppUsed,
    riskLevelDuringSignIn, and autonomousSystemNumber. None of these exist in the unified audit
    log. Sign-in records are correlated to audit records on source address within
    SignInCorrelationMinutes.

    .PARAMETER SignInCorrelationMinutes
    Correlation window between an audit record and a sign-in log record on matching source
    address. Defaults to 5.

    .PARAMETER PostPasswordErrorCode
    Error codes reachable only after the submitted password validates, as a table of code to
    name. Override this to add the further codes that Microsoft password spray analytics also
    treat as post-password.

    .PARAMETER UsernameOracleErrorCode
    Error codes reachable without a valid password, as a table of code to name. These are
    counted as campaign context and never produce triage targets.

    .PARAMETER FollowOnOperation
    Table of operation name to category for phase three.

    .PARAMETER Delimiter
    Field delimiter for the delimited output files. Defaults to a semicolon.

    .PARAMETER IncludeHtmlReport
    Additionally writes TriageReport.html to the output directory, alongside the delimited files
    and the JSON summary. The report is self-contained: it opens from a file URI with networking
    disabled, and it carries no external stylesheet, no web font, no content delivery network
    script, and no image file. Use New-CredEchoReport to re-render the same report later from the
    saved TriageResults.json without querying the tenant again.

    .PARAMETER UpnFilterChunkSize
    Number of account names sent in a single userPrincipalNameFilters array. Defaults to 25.

    .PARAMETER PollSeconds
    Interval between audit log query status polls. Defaults to 20.

    .PARAMETER QueryTimeoutMinutes
    Maximum time to wait for a single audit log query to reach a terminal state. Defaults
    to 120.

    .EXAMPLE
    Connect-MgGraph -Scopes 'AuditLogsQuery-Entra.Read.All', 'AuditLogsQuery-Exchange.Read.All', 'Application.Read.All'
    Invoke-CredEchoTriage -OutputDirectory 'C:\Cases\1042'

    Runs the default triage across the trailing 180 days and writes all five artifacts. This is
    the normal starting point when the only thing known is that a credential validation
    campaign touched the tenant.

    .EXAMPLE
    Invoke-CredEchoTriage -OutputDirectory 'C:\Cases\1042' -IncludeHtmlReport

    Adds TriageReport.html to the output. The file is self-contained, so it opens from a file URI
    with networking disabled and prints to PDF from the browser print dialog with every account
    card expanded.

    .EXAMPLE
    Connect-MgGraph -Scopes 'AuditLogsQuery-Entra.Read.All', 'AuditLogsQuery-Exchange.Read.All', 'Application.Read.All', 'AuditLog.Read.All'
    Invoke-CredEchoTriage -OutputDirectory 'C:\Cases\1042' -IncludeSignInEnrichment -TenantWideCorroboration -Verbose

    Adds sign-in log enrichment, which is what makes the multifactor authentication,
    Conditional Access, legacy client, risk level, and Resource Owner Password Credentials
    signals available, and widens the application corroboration control to the whole tenant.
    Enrichment only reaches the trailing 30 days, because that is all the sign-in logs retain.

    .EXAMPLE
    Invoke-CredEchoTriage -OutputDirectory 'C:\Cases\1042' -Account 'jdoe@contoso.com', 'asmith@contoso.com' -AttackerIpAddress '185.220.101.44' -AttackerUserAgent 'python-requests/2.32.3'

    Triages an account list supplied from outside the tool and seeds the indicator set from
    external intelligence. Use this shape when the validation events have already aged out of
    the audit log, so phase one cannot derive the indicators on its own. Both overrides
    supplement phase one and neither replaces it.

    .EXAMPLE
    Invoke-CredEchoTriage -OutputDirectory 'C:\Cases\1042' -SearchStartTime ([datetime]'2026-01-01') -SearchEndTime ([datetime]'2026-03-31') -BaselineDays 120 -AllowedApplicationId '11111111-2222-3333-4444-555555555555' -CorroborationAccountThreshold 5

    Scopes the search to a known campaign period, lengthens the baseline, suppresses a known
    internal client by identifier, and raises the corroboration threshold.

    .NOTES
    Required Microsoft Graph scopes:

      AuditLogsQuery-Entra.Read.All      Sign-in and directory audit records. Least privilege
                                         for the Entra workload, and the documented least
                                         privileged permission on both the create query and the
                                         list records operations.
      AuditLogsQuery.Read.All            Broad alternative to the above, covering every
                                         workload. Documented as a higher privileged option.
      AuditLogsQuery-Exchange.Read.All   Inbox rule and mailbox follow-on actions in phase
                                         three.
      Application.Read.All               Service principal enumeration for the application
                                         registration test. Verified as the documented least
                                         privileged permission for GET /servicePrincipals.
                                         Directory.Read.All is a higher privileged alternative
                                         and is not required.
      AuditLog.Read.All                  Sign-in log enrichment only, and only when
                                         IncludeSignInEnrichment is specified.

    Scope limitations, and what this tool cannot tell you:

      Read only. CredEcho performs no remediation. There is no password reset, no token
      revocation, no session invalidation, and no blocking anywhere in this module. Output is
      investigative leads only.

      The post-password classification of error code 700016 rests on independent research
      published in July 2026 and not on Microsoft documentation. Microsoft documents what each
      error code means and has never documented the order in which the security token service
      validates a request, so this is observed implementation behavior rather than a contract
      and it can change without notice. Error code 50055 is more doubtful still, because
      Microsoft's own password spray detection content classifies it both as a failure and as a
      success. Every validation event therefore carries an ErrorConfidence value of Documented,
      Observed, or Ambiguous, and leads should be weighted accordingly.

      The application registration test runs against the application identifier alone, because
      the unified audit log carries no application display name. A client identifier that is not
      a well formed GUID is not recorded in that field at all, so those records are retained as
      validation events precisely because they cannot be tested.

      The unified audit log carries no autonomous system number and no geolocation, so
      infrastructure novelty falls back to an IPv4 /24 or IPv6 /48 prefix. That is a coarse
      proxy: a large hosting provider or a carrier grade NAT range will place unrelated traffic
      in the same prefix. Prefix matches are scored one tier below exact address matches.

      Without IncludeSignInEnrichment there is no multifactor authentication state, no
      Conditional Access result, no client application, no risk level, and no way to see that a
      Resource Owner Password Credentials grant succeeded, because none of those fields exist in
      the unified audit log. With it, enrichment still reaches only the trailing 30 days, since
      Entra sign-in logs retain 30 days on Entra ID P1 and P2. An absent enrichment match is
      therefore not evidence of anything.

      Corroboration counts distinct accounts across the successful sign-ins CredEcho retrieved.
      Without TenantWideCorroboration that corpus is limited to the accounts already under
      triage, which suppresses fewer identifiers than a genuine tenant-wide count would and so
      leaves more false positives in the output rather than fewer.

      Audit record availability bounds everything. Microsoft Entra audit records are retained
      180 days under Purview Audit Standard, and one year by default for users licensed for E5
      or the Purview Suite. Records for guest users and unlicensed users fall back to 180 days.
      A campaign older than the tenant's retention is invisible to this tool, and phase three
      exists because directory audit evidence of persistence outlives the sign-in evidence of
      access.

      The AuditLogQuery API is documented as available in the global service only, and not in
      the US Government or 21Vianet clouds.

    Requires PowerShell 5.1 or later and the Microsoft.Graph.Authentication module. CredEcho
    does not call Connect-MgGraph on the caller's behalf.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '',
        Justification = 'The rule matches the parameter names UsernameOracleErrorCode and PostPasswordErrorCode on the substrings Username and Password. Both carry error code lookup tables. Neither accepts a credential, and this module never handles one.')]
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory)]
        [string] $OutputDirectory,

        [datetime] $SearchEndTime = [datetime]::UtcNow,

        [datetime] $SearchStartTime = [datetime]::UtcNow.AddDays(-180),

        [ValidateRange(1, 3650)]
        [int] $BaselineDays = 90,

        [ValidateRange(1, 180)]
        [int] $ChunkDays = 30,

        [ValidateRange(1, 1000)]
        [int] $CorroborationAccountThreshold = 3,

        [switch] $TenantWideCorroboration,

        [string[]] $AllowedApplicationId = @(),

        [string[]] $Account = @(),

        [string[]] $AttackerIpAddress = @(),

        [string[]] $AttackerUserAgent = @(),

        [switch] $IncludeSignInEnrichment,

        [ValidateRange(1, 1440)]
        [int] $SignInCorrelationMinutes = 5,

        [hashtable] $PostPasswordErrorCode = $script:CredEchoPostPasswordError,

        [hashtable] $UsernameOracleErrorCode = $script:CredEchoUsernameOracleError,

        [System.Collections.IDictionary] $FollowOnOperation = $script:CredEchoFollowOnOperation,

        [string] $Delimiter = ';',

        [switch] $IncludeHtmlReport,

        [ValidateRange(1, 200)]
        [int] $UpnFilterChunkSize = 25,

        [ValidateRange(1, 300)]
        [int] $PollSeconds = 20,

        [ValidateRange(1, 1440)]
        [int] $QueryTimeoutMinutes = 120
    )

    $searchStart = $SearchStartTime.ToUniversalTime()
    $searchEnd = $SearchEndTime.ToUniversalTime()
    if ($searchStart -ge $searchEnd) {
        throw "SearchStartTime ($($searchStart.ToString('u'))) must precede SearchEndTime ($($searchEnd.ToString('u')))."
    }

    [void] (Test-CredEchoGraphContext -AnyOfScope @('AuditLogsQuery-Entra.Read.All', 'AuditLogsQuery.Read.All') -Capability 'reading Entra audit records from the unified audit log')
    [void] (Test-CredEchoGraphContext -AnyOfScope @('Application.Read.All', 'Application.ReadWrite.All', 'Directory.Read.All', 'Directory.ReadWrite.All', 'Application.ReadWrite.OwnedBy') -Capability 'enumerating service principals for the application registration test')
    $canReadExchange = Test-CredEchoGraphContext -AnyOfScope @('AuditLogsQuery-Exchange.Read.All', 'AuditLogsQuery.Read.All') -Capability 'reading Exchange audit records for phase three follow-on actions' -Optional
    $canEnrich = $false
    if ($IncludeSignInEnrichment) {
        $canEnrich = Test-CredEchoGraphContext -AnyOfScope @('AuditLog.Read.All') -Capability 'reading Entra sign-in logs for enrichment' -Optional
    }

    $auditArgument = @{
        ChunkDays           = $ChunkDays
        PollSeconds         = $PollSeconds
        QueryTimeoutMinutes = $QueryTimeoutMinutes
    }

    # Phase one. Failed STS logons across the search window, tenant-wide.
    Write-Verbose 'Phase one: retrieving UserLoginFailed records.'
    $failedRecord = @(
        Get-CredEchoAuditRecord -StartTime $searchStart -EndTime $searchEnd `
            -RecordTypeFilter @($script:CredEchoStsRecordType) -OperationFilter @('UserLoginFailed') `
            -Label 'CredEcho phase one' @auditArgument |
            ConvertFrom-CredEchoLogonRecord -UsernameOracleError $UsernameOracleErrorCode -PostPasswordError $PostPasswordErrorCode
    )
    Write-Verbose "Retrieved $($failedRecord.Count) failed logon records."

    $candidate = @($failedRecord | Where-Object { $_.ErrorClass -eq 'PostPassword' })
    $suppliedAccount = @($Account | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim().ToLowerInvariant() })

    $candidateAccount = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($record in $candidate) {
        if (-not [string]::IsNullOrWhiteSpace([string] $record.UserPrincipalName)) { [void] $candidateAccount.Add([string] $record.UserPrincipalName) }
    }
    foreach ($upn in $suppliedAccount) { [void] $candidateAccount.Add($upn) }

    Write-Verbose "$($candidate.Count) post-password records naming $($candidateAccount.Count) candidate accounts, before the application registration test."

    # Successful logons. The earliest post-password record fixes how far back the baseline has
    # to reach, and the same query range covers every account's post-validation window.
    $earliestCandidate = @($candidate | Where-Object { $null -ne $_.TimeStamp } | ForEach-Object { $_.TimeStamp } | Sort-Object)
    $successStart = $searchStart.AddDays(-$BaselineDays)
    if ($earliestCandidate.Count -gt 0) { $successStart = $earliestCandidate[0].AddDays(-$BaselineDays) }

    $successRecord = New-Object 'System.Collections.Generic.List[psobject]'

    if ($candidateAccount.Count -gt 0) {
        $accountList = @($candidateAccount)
        $chunkCount = [System.Math]::Ceiling($accountList.Count / [double] $UpnFilterChunkSize)
        Write-Verbose "Retrieving successful logons for $($accountList.Count) accounts in $($chunkCount) filter chunks from $($successStart.ToString('u'))."

        for ($offset = 0; $offset -lt $accountList.Count; $offset += $UpnFilterChunkSize) {
            $slice = @($accountList[$offset..([System.Math]::Min($offset + $UpnFilterChunkSize - 1, $accountList.Count - 1))])
            Get-CredEchoAuditRecord -StartTime $successStart -EndTime $searchEnd `
                -RecordTypeFilter @($script:CredEchoStsRecordType) -OperationFilter @('UserLoggedIn') `
                -UserPrincipalNameFilter $slice -Label 'CredEcho successes' @auditArgument |
                ConvertFrom-CredEchoLogonRecord -UsernameOracleError $UsernameOracleErrorCode -PostPasswordError $PostPasswordErrorCode |
                ForEach-Object { $successRecord.Add($_) }
        }
    }

    if ($TenantWideCorroboration) {
        Write-Verbose 'Retrieving tenant-wide successful logons for the corroboration control.'
        Get-CredEchoAuditRecord -StartTime $successStart -EndTime $searchEnd `
            -RecordTypeFilter @($script:CredEchoStsRecordType) -OperationFilter @('UserLoggedIn') `
            -Label 'CredEcho corroboration' @auditArgument |
            ConvertFrom-CredEchoLogonRecord -UsernameOracleError $UsernameOracleErrorCode -PostPasswordError $PostPasswordErrorCode |
            ForEach-Object { $successRecord.Add($_) }
    }

    Write-Verbose "Retrieved $($successRecord.Count) successful logon records."

    $knownApplication = Get-CredEchoKnownApplication -BaselineSuccess $successRecord.ToArray() `
        -CorroborationAccountThreshold $CorroborationAccountThreshold -AllowedApplicationId $AllowedApplicationId

    $validation = Get-CredEchoValidationEvent -LogonRecord $failedRecord -KnownApplication $knownApplication

    Write-Verbose "Phase one produced $($validation.ValidationEventCount) validation events naming $($validation.ValidatedAccountCount) accounts. Suppressed identifiers: $($validation.SuppressedByRegistrationCount) registered, $($validation.SuppressedByCorroborationCount) corroborated, $($validation.SuppressedByAllowlistCount) allowlisted."

    $targetAccount = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($upn in @($validation.ValidatedAccount)) { [void] $targetAccount.Add($upn) }
    foreach ($upn in $suppliedAccount) { [void] $targetAccount.Add($upn) }

    # Optional sign-in log enrichment, scoped to the trailing 30 days that the sign-in logs hold.
    $enrichment = @()
    if ($canEnrich -and $targetAccount.Count -gt 0) {
        $enrichStart = $searchEnd.AddDays(-30)
        if ($enrichStart -lt $searchStart) { $enrichStart = $searchStart }
        Write-Verbose "Retrieving sign-in log enrichment from $($enrichStart.ToString('u')) to $($searchEnd.ToString('u'))."
        $enrichment = @(Get-CredEchoSignInEnrichment -StartTime $enrichStart -EndTime $searchEnd -UserPrincipalName @($targetAccount))
        Write-Verbose "Retrieved $($enrichment.Count) sign-in log records for enrichment."
    }

    # Phase three. Collected before scoring, because a persistence action combined with any
    # flagged sign-in escalates an account to Confirmed.
    $followOnAction = @()
    if ($targetAccount.Count -gt 0 -and $FollowOnOperation.Count -gt 0) {
        $followOnStart = $searchStart
        if ($null -ne $validation.FirstValidation) { $followOnStart = $validation.FirstValidation }

        $recordTypeFilter = @($script:CredEchoFollowOnRecordType)
        if (-not $canReadExchange) {
            $recordTypeFilter = @('azureActiveDirectory')
            Write-Warning 'Phase three is limited to directory audit records. Inbox rule, mailbox forwarding, mailbox permission, and transport rule actions require AuditLogsQuery-Exchange.Read.All or AuditLogsQuery.Read.All.'
        }

        Write-Verbose "Phase three: retrieving follow-on actions from $($followOnStart.ToString('u'))."
        $accountList = @($targetAccount)
        $rawFollowOn = New-Object 'System.Collections.Generic.List[psobject]'

        for ($offset = 0; $offset -lt $accountList.Count; $offset += $UpnFilterChunkSize) {
            $slice = @($accountList[$offset..([System.Math]::Min($offset + $UpnFilterChunkSize - 1, $accountList.Count - 1))])
            foreach ($record in (Get-CredEchoAuditRecord -StartTime $followOnStart -EndTime $searchEnd `
                        -RecordTypeFilter $recordTypeFilter -OperationFilter @($FollowOnOperation.Keys) `
                        -UserPrincipalNameFilter $slice -Label 'CredEcho phase three' @auditArgument)) {

                $auditData = $record['auditData']
                $operation = [string] $record['operation']
                $actor = @([string] $record['userPrincipalName'], [string] $auditData['UserId']) |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and $_ -ne 'Unknown' } | Select-Object -First 1
                $actorIp = @([string] $auditData['ActorIpAddress'], [string] $auditData['ClientIP'], [string] $record['clientIp']) |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1

                $rawFollowOn.Add([pscustomobject]@{
                        UserPrincipalName = $(if ($actor) { $actor.ToLowerInvariant() } else { $null })
                        TimeStamp         = $(if ($null -ne $record['createdDateTime']) { ([datetime] $record['createdDateTime']).ToUniversalTime() } else { $null })
                        Operation         = $operation
                        Category          = [string] $FollowOnOperation[$operation]
                        RecordType        = [string] $record['auditLogRecordType']
                        IpAddress         = $actorIp
                        TargetObject      = [string] $record['objectId']
                        RecordId          = [string] $record['id']
                        IsTargetAccount   = $targetAccount.Contains([string] $actor)
                    })
            }
        }

        $followOnAction = @($rawFollowOn | Sort-Object -Property UserPrincipalName, TimeStamp)
        Write-Verbose "Phase three collected $($followOnAction.Count) follow-on actions."
    }

    # Phase two.
    $attackerIpSeed = @($AttackerIpAddress | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() })
    $attackerAgentSeed = @($AttackerUserAgent | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() })

    $tierRank = @{ 'Confirmed' = 3; 'Probable' = 2; 'Possible' = 1 }
    $flaggedSignIn = New-Object 'System.Collections.Generic.List[psobject]'
    $accountVerdict = New-Object 'System.Collections.Generic.List[psobject]'

    foreach ($upn in @($targetAccount | Sort-Object)) {
        $accountValidation = @($validation.ValidationEvent | Where-Object { $_.UserPrincipalName -eq $upn })
        $validationStamp = @($accountValidation | Where-Object { $null -ne $_.TimeStamp } | ForEach-Object { $_.TimeStamp } | Sort-Object)

        $assumedTimestamp = $false
        if ($validationStamp.Count -gt 0) {
            $validationTime = $validationStamp[0]
            $validationEnd = $validationStamp[-1]
        }
        else {
            # An account supplied by the analyst with no derivable validation event. The start
            # of the search window is the only defensible anchor, and the output says so.
            $validationTime = $searchStart
            $validationEnd = $searchStart
            $assumedTimestamp = $true
        }

        $attackerIp = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        $attackerPrefix = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        $attackerAgent = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($record in $accountValidation) {
            if (-not [string]::IsNullOrWhiteSpace([string] $record.IpAddress)) { [void] $attackerIp.Add([string] $record.IpAddress) }
            if (-not [string]::IsNullOrWhiteSpace([string] $record.IpPrefix)) { [void] $attackerPrefix.Add([string] $record.IpPrefix) }
            if (-not [string]::IsNullOrWhiteSpace([string] $record.UserAgent)) { [void] $attackerAgent.Add([string] $record.UserAgent) }
        }
        foreach ($value in $attackerIpSeed) {
            [void] $attackerIp.Add($value)
            $seedPrefix = Get-CredEchoIpPrefix -IpAddress $value
            if ($seedPrefix) { [void] $attackerPrefix.Add($seedPrefix) }
        }
        foreach ($value in $attackerAgentSeed) { [void] $attackerAgent.Add($value) }

        $accountSuccess = @($successRecord | Where-Object { $_.UserPrincipalName -eq $upn -and $null -ne $_.TimeStamp })
        $baselineStart = $validationTime.AddDays(-$BaselineDays)
        $baseline = @($accountSuccess | Where-Object { $_.TimeStamp -ge $baselineStart -and $_.TimeStamp -lt $validationTime })
        $postValidation = @($accountSuccess | Where-Object { $_.TimeStamp -ge $validationTime })

        $baselineIp = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        $baselinePrefix = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        $baselineAgent = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($record in $baseline) {
            if (-not [string]::IsNullOrWhiteSpace([string] $record.IpAddress)) { [void] $baselineIp.Add([string] $record.IpAddress) }
            if (-not [string]::IsNullOrWhiteSpace([string] $record.IpPrefix)) { [void] $baselinePrefix.Add([string] $record.IpPrefix) }
            if (-not [string]::IsNullOrWhiteSpace([string] $record.UserAgent)) { [void] $baselineAgent.Add([string] $record.UserAgent) }
        }
        $baselineAssessed = $baseline.Count -gt 0

        $accountSignal = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        $accountFlagged = New-Object 'System.Collections.Generic.List[psobject]'
        $confirmedCount = 0
        $probableCount = 0
        $possibleCount = 0

        foreach ($success in $postValidation) {
            $match = $null
            if ($enrichment.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace([string] $success.IpAddress)) {
                $match = $enrichment | Where-Object {
                    $_.UserPrincipalName -eq $upn -and
                    $_.IpAddress -eq $success.IpAddress -and
                    $null -ne $_.TimeStamp -and
                    [System.Math]::Abs(($_.TimeStamp - $success.TimeStamp).TotalMinutes) -le $SignInCorrelationMinutes
                } | Select-Object -First 1
            }

            # Each signal is recorded as Name:Tier, and the sign-in takes the highest tier it earned.
            $signal = New-Object 'System.Collections.Generic.List[string]'
            $tier = $null

            # Confirmed tier.
            $exactSourceMatch = (-not [string]::IsNullOrWhiteSpace([string] $success.IpAddress)) -and $attackerIp.Contains([string] $success.IpAddress)
            if ($exactSourceMatch) { $signal.Add('SourceAddressSeenInValidationActivity:Confirmed') }
            if ((-not [string]::IsNullOrWhiteSpace([string] $success.UserAgent)) -and $attackerAgent.Contains([string] $success.UserAgent)) {
                $signal.Add('UserAgentSeenInValidationActivity:Confirmed')
            }
            if (-not [string]::IsNullOrWhiteSpace([string] $success.UserAgent)) {
                foreach ($pattern in $script:CredEchoNonBrowserAgent) {
                    if (([string] $success.UserAgent).IndexOf($pattern, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                        $signal.Add('NonBrowserClientString:Confirmed')
                        break
                    }
                }
            }
            if ($null -ne $match -and $match.AuthenticationProtocol -eq 'ropc') {
                $signal.Add('ResourceOwnerPasswordCredentialsGrantSucceeded:Confirmed')
            }

            # Probable tier. A prefix match only counts when the exact address did not already
            # match, otherwise every confirmed hit would also raise a redundant probable signal.
            if ((-not $exactSourceMatch) -and (-not [string]::IsNullOrWhiteSpace([string] $success.IpPrefix)) -and $attackerPrefix.Contains([string] $success.IpPrefix)) {
                $signal.Add('NetworkPrefixSeenInValidationActivity:Probable')
            }

            $multifactorSatisfied = $null
            if ($null -ne $match) { $multifactorSatisfied = ($match.AuthenticationRequirement -eq 'multiFactorAuthentication') }

            $firstSeenPrefix = $baselineAssessed -and (-not [string]::IsNullOrWhiteSpace([string] $success.IpPrefix)) -and (-not $baselinePrefix.Contains([string] $success.IpPrefix))
            if ($firstSeenPrefix -and $false -eq $multifactorSatisfied) {
                $signal.Add('FirstSeenNetworkPrefixWithoutMultifactor:Probable')
            }
            if ($null -ne $match -and $match.ConditionalAccessStatus -in @('notApplied', 'failure')) {
                $signal.Add("ConditionalAccessStatus_$($match.ConditionalAccessStatus):Probable")
            }
            if ($null -ne $match -and (-not [string]::IsNullOrWhiteSpace([string] $match.ClientAppUsed)) -and $match.ClientAppUsed -notin $script:CredEchoModernClientApp) {
                $signal.Add('LegacyClientApplication:Probable')
            }
            if ($null -ne $match -and $match.RiskLevelDuringSignIn -in @('low', 'medium', 'high')) {
                $signal.Add("IdentityProtectionRisk_$($match.RiskLevelDuringSignIn):Probable")
            }

            # Possible tier.
            $firstSeenAddress = $baselineAssessed -and (-not [string]::IsNullOrWhiteSpace([string] $success.IpAddress)) -and (-not $baselineIp.Contains([string] $success.IpAddress))
            if ($firstSeenAddress -and $true -eq $multifactorSatisfied) {
                $signal.Add('FirstSeenSourceAddressWithMultifactor:Possible')
            }
            elseif ($firstSeenAddress -and $null -eq $multifactorSatisfied) {
                # No enrichment for this sign-in, so multifactor state is unknown rather than absent.
                $signal.Add('FirstSeenSourceAddressMultifactorUnknown:Possible')
            }
            if (-not $baselineAssessed) {
                $signal.Add('NoveltyCouldNotBeAssessed:Possible')
            }

            if ($signal.Count -eq 0) { continue }

            foreach ($entry in $signal) {
                $entryTier = $entry.Split(':')[-1]
                if ($null -eq $tier -or $tierRank[$entryTier] -gt $tierRank[$tier]) { $tier = $entryTier }
                [void] $accountSignal.Add($entry)
            }

            switch ($tier) {
                'Confirmed' { $confirmedCount++ }
                'Probable' { $probableCount++ }
                'Possible' { $possibleCount++ }
            }

            $row = [pscustomobject]@{
                UserPrincipalName         = $upn
                TimeStamp                 = $success.TimeStamp
                Tier                      = $tier
                Signal                    = $signal.ToArray()
                IpAddress                 = $success.IpAddress
                IpPrefix                  = $success.IpPrefix
                UserAgent                 = $success.UserAgent
                ApplicationId             = $success.ApplicationId
                RecordId                  = $success.RecordId
                ClientAppUsed             = $(if ($null -ne $match) { $match.ClientAppUsed } else { $null })
                ConditionalAccessStatus   = $(if ($null -ne $match) { $match.ConditionalAccessStatus } else { $null })
                AuthenticationRequirement = $(if ($null -ne $match) { $match.AuthenticationRequirement } else { $null })
                AuthenticationProtocol    = $(if ($null -ne $match) { $match.AuthenticationProtocol } else { $null })
                RiskLevelDuringSignIn     = $(if ($null -ne $match) { $match.RiskLevelDuringSignIn } else { $null })
                AutonomousSystemNumber    = $(if ($null -ne $match) { $match.AutonomousSystemNumber } else { $null })
                Enriched                  = ($null -ne $match)
            }
            $accountFlagged.Add($row)
            $flaggedSignIn.Add($row)
        }

        $accountFollowOn = @($followOnAction | Where-Object { $_.UserPrincipalName -eq $upn })

        $verdict = 'NoIndicators'
        if ($confirmedCount -gt 0) { $verdict = 'Confirmed' }
        elseif ($accountFollowOn.Count -gt 0 -and $accountFlagged.Count -gt 0) {
            # A persistence action combined with any flagged sign-in is a confirmed account.
            $verdict = 'Confirmed'
            [void] $accountSignal.Add('FollowOnActionWithFlaggedSignIn:Confirmed')
        }
        elseif ($probableCount -gt 0) { $verdict = 'Probable' }
        elseif ($possibleCount -gt 0) { $verdict = 'Possible' }

        if (-not $baselineAssessed) {
            # Never let an unassessable account read as a clean result.
            [void] $accountSignal.Add('NoveltyCouldNotBeAssessed:Possible')
        }

        $accountVerdict.Add([pscustomobject]@{
                UserPrincipalName          = $upn
                Verdict                    = $verdict
                ConfirmedSignalCount       = $confirmedCount
                ProbableSignalCount        = $probableCount
                PossibleSignalCount        = $possibleCount
                DistinctSignal             = @($accountSignal | Sort-Object)
                FirstValidation            = $(if ($assumedTimestamp) { $null } else { $validationTime })
                LastValidation             = $(if ($assumedTimestamp) { $null } else { $validationEnd })
                ValidationErrorCode        = @($accountValidation | ForEach-Object { $_.ErrorCode } | Sort-Object -Unique)
                ValidationSourceAddress    = @($attackerIp | Sort-Object)
                ValidationTimestampAssumed = $assumedTimestamp
                PostValidationSignInCount  = $postValidation.Count
                FlaggedSignInCount         = $accountFlagged.Count
                FollowOnActionCount        = $accountFollowOn.Count
                BaselineAssessed           = $baselineAssessed
                BaselineSignInCount        = $baseline.Count
                NoveltyAssessment          = $(if ($baselineAssessed) { 'Assessed' } else { 'Novelty could not be assessed. This account has no successful sign-in in its baseline period, so there is no known-good source address, network prefix, or user agent to compare against.' })
            })
    }

    $verdictTally = @{ 'Confirmed' = 0; 'Probable' = 0; 'Possible' = 0; 'NoIndicators' = 0 }
    foreach ($row in $accountVerdict) { $verdictTally[[string] $row.Verdict]++ }

    $summary = [pscustomobject]@{
        GeneratedUtc                     = [datetime]::UtcNow
        ModuleVersion                    = (Get-Module -Name 'CredEcho').Version.ToString()
        TenantId                         = (Get-MgContext).TenantId
        SearchStartUtc                   = $searchStart
        SearchEndUtc                     = $searchEnd
        BaselineDays                     = $BaselineDays
        ChunkDays                        = $ChunkDays
        FailedLogonRecordCount           = $failedRecord.Count
        SuccessfulLogonRecordCount       = $successRecord.Count
        PostPasswordRecordCount          = $candidate.Count
        ValidationEventCount             = $validation.ValidationEventCount
        ValidatedAccountCount            = $validation.ValidatedAccountCount
        AttackerApplicationIdCount       = $validation.AttackerApplicationIdCount
        FirstValidationUtc               = $validation.FirstValidation
        LastValidationUtc                = $validation.LastValidation
        UsernameOracleEventCount         = $validation.UsernameOracleEventCount
        UsernameOracleAccountCount       = $validation.UsernameOracleAccountCount
        UsernameOracleSourceCount        = $validation.UsernameOracleSourceCount
        ServicePrincipalCount            = $knownApplication.RegisteredCount
        SuppressedByRegistrationCount    = $validation.SuppressedByRegistrationCount
        SuppressedByCorroborationCount   = $validation.SuppressedByCorroborationCount
        SuppressedByAllowlistCount       = $validation.SuppressedByAllowlistCount
        SuppressedByRegistration         = @($validation.SuppressedByRegistration)
        SuppressedByCorroboration        = @($validation.SuppressedByCorroboration)
        SuppressedByAllowlist            = @($validation.SuppressedByAllowlist)
        CorroborationAccountThreshold    = $CorroborationAccountThreshold
        CorroborationScope               = $(if ($TenantWideCorroboration) { 'Tenant' } else { 'TriageTargetAccountsOnly' })
        SignInEnrichmentRequested        = [bool] $IncludeSignInEnrichment
        SignInEnrichmentAvailable        = $canEnrich
        SignInEnrichmentRecordCount      = $enrichment.Count
        ExchangeFollowOnAvailable        = $canReadExchange
        TriagedAccountCount              = $accountVerdict.Count
        FlaggedSignInCount               = $flaggedSignIn.Count
        FollowOnActionCount              = $followOnAction.Count
        VerdictConfirmed                 = $verdictTally['Confirmed']
        VerdictProbable                  = $verdictTally['Probable']
        VerdictPossible                  = $verdictTally['Possible']
        VerdictNoIndicators              = $verdictTally['NoIndicators']
        AnalystSuppliedAccountCount      = $suppliedAccount.Count
        AnalystSuppliedIpAddressCount    = $attackerIpSeed.Count
        AnalystSuppliedUserAgentCount    = $attackerAgentSeed.Count
    }

    $export = Export-CredEchoResult -OutputDirectory $OutputDirectory `
        -AccountVerdict $accountVerdict.ToArray() -ValidationEvent @($validation.ValidationEvent) `
        -FlaggedSignIn $flaggedSignIn.ToArray() -FollowOnAction $followOnAction `
        -Summary $summary -Delimiter $Delimiter

    $result = [pscustomobject]@{
        Summary         = $summary
        AccountVerdict  = $accountVerdict.ToArray()
        ValidationEvent = @($validation.ValidationEvent)
        FlaggedSignIn   = $flaggedSignIn.ToArray()
        FollowOnAction  = $followOnAction
    }

    $file = New-Object 'System.Collections.Generic.List[string]'
    foreach ($item in @($export.File)) { $file.Add([string] $item) }

    if ($IncludeHtmlReport) {
        $reportPath = New-CredEchoHtmlReport -TriageResult $result `
            -Path (Join-Path -Path $export.OutputDirectory -ChildPath 'TriageReport.html')
        $file.Add($reportPath)
        Write-Verbose "Wrote the self-contained HTML report to $($reportPath)."
    }

    Write-Verbose "Wrote $($file.Count) artifacts to $($export.OutputDirectory)."

    [pscustomobject]@{
        Summary         = $summary
        AccountVerdict  = $result.AccountVerdict
        ValidationEvent = $result.ValidationEvent
        FlaggedSignIn   = $result.FlaggedSignIn
        FollowOnAction  = $result.FollowOnAction
        OutputDirectory = $export.OutputDirectory
        File            = $file.ToArray()
    }
}
