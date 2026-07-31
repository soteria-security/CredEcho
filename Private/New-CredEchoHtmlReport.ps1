function Protect-CredEchoHtmlText {
    <#
    .SYNOPSIS
    HTML-encodes a value that originated in tenant data.

    .DESCRIPTION
    User agent strings are attacker controlled and arrive carrying angle brackets and quotes.
    Application identifiers, logon errors, and signal lists all pass through the same path.
    Everything is encoded on the way into the payload rather than trusted on the way out, so the
    renderer can write markup with innerHTML and still have attacker text land as literal text.

    WebUtility.HtmlEncode covers the ampersand, both angle brackets, the double quote, and the
    single quote, which is the full set that matters for both element content and quoted
    attribute values.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Position = 0)]
        [AllowNull()]
        [AllowEmptyString()]
        $Value
    )

    if ($null -eq $Value) { return '' }
    [System.Net.WebUtility]::HtmlEncode([string] $Value)
}

function ConvertTo-CredEchoDateTime {
    <#
    .SYNOPSIS
    Coerces a timestamp to a UTC DateTime, or $null when there is nothing to coerce.

    .DESCRIPTION
    Timestamps reach the renderer as DateTime objects on the direct path and as strings on the
    path that re-renders a saved TriageResults.json, so both have to work.
    #>
    [CmdletBinding()]
    [OutputType([datetime])]
    param (
        [Parameter(Position = 0)]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string] $Value)) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }

    $parsed = [datetime]::MinValue
    if ([datetime]::TryParse([string] $Value, [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal,
            [ref] $parsed)) {
        return $parsed
    }
    return $null
}

function New-CredEchoHtmlReport {
    <#
    .SYNOPSIS
    Renders a triage result as a single self-contained HTML file.

    .DESCRIPTION
    The output opens from a file URI with networking disabled. There is no external stylesheet,
    no web font, no content delivery network script, no image file, and no runtime dependency on
    anything outside this module. Every asset is inlined, and the only absolute address anywhere
    in the file is the footer link to the Soteria site.

    The scaffold is held in a single-quoted here-string so that no dollar sign in the stylesheet
    or the script is interpolated, and the data is substituted against a distinctive placeholder
    token rather than through string interpolation. The file is written with a UTF-8 encoder
    constructed with no byte order mark, because a byte order mark shows up as a stray character
    in some browsers.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'This is a private helper. The public entry points own the ShouldProcess gate, and New-CredEchoReport declares SupportsShouldProcess so that WhatIf and Confirm reach this write through the caller.')]
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [psobject] $TriageResult,

        [Parameter(Mandatory)]
        [string] $Path
    )

    $summary = $TriageResult.Summary
    if ($null -eq $summary) { throw 'The triage result carries no Summary object, so there is nothing to render.' }

    $ladder = @('Confirmed', 'Probable', 'Possible', 'NoIndicators')

    $validationByAccount = @{}
    foreach ($record in @($TriageResult.ValidationEvent)) {
        $key = [string] $record.UserPrincipalName
        if (-not $validationByAccount.ContainsKey($key)) { $validationByAccount[$key] = New-Object 'System.Collections.Generic.List[psobject]' }
        $validationByAccount[$key].Add($record)
    }

    $flaggedByAccount = @{}
    foreach ($record in @($TriageResult.FlaggedSignIn)) {
        $key = [string] $record.UserPrincipalName
        if (-not $flaggedByAccount.ContainsKey($key)) { $flaggedByAccount[$key] = New-Object 'System.Collections.Generic.List[psobject]' }
        $flaggedByAccount[$key].Add($record)
    }

    $followOnByAccount = @{}
    foreach ($record in @($TriageResult.FollowOnAction)) {
        $key = [string] $record.UserPrincipalName
        if (-not $followOnByAccount.ContainsKey($key)) { $followOnByAccount[$key] = New-Object 'System.Collections.Generic.List[psobject]' }
        $followOnByAccount[$key].Add($record)
    }

    $verdictRank = @{ 'Confirmed' = 0; 'Probable' = 1; 'Possible' = 2; 'NoIndicators' = 3 }
    $ordered = @($TriageResult.AccountVerdict | Sort-Object -Property @{ Expression = { $verdictRank[[string] $_.Verdict] } }, @{ Expression = { [string] $_.UserPrincipalName } })

    $accounts = New-Object 'System.Collections.Generic.List[psobject]'

    foreach ($account in $ordered) {
        $upn = [string] $account.UserPrincipalName
        $accountValidation = @($validationByAccount[$upn])
        $accountFlagged = @($flaggedByAccount[$upn] | Where-Object { $null -ne $_ })
        $accountFollowOn = @($followOnByAccount[$upn] | Where-Object { $null -ne $_ })

        $anchor = ConvertTo-CredEchoDateTime $account.FirstValidation
        if ($null -eq $anchor) { $anchor = ConvertTo-CredEchoDateTime $summary.SearchStartUtc }

        $searchTerm = New-Object 'System.Collections.Generic.List[string]'
        $searchTerm.Add($upn)

        $signInRow = New-Object 'System.Collections.Generic.List[psobject]'
        foreach ($signIn in ($accountFlagged | Sort-Object -Property @{ Expression = { ConvertTo-CredEchoDateTime $_.TimeStamp } })) {
            $stamp = ConvertTo-CredEchoDateTime $signIn.TimeStamp
            $elapsed = ''
            if ($null -ne $stamp -and $null -ne $anchor) { $elapsed = [string] [math]::Round(($stamp - $anchor).TotalHours, 1) }

            $searchTerm.Add([string] $signIn.IpAddress)
            $searchTerm.Add([string] $signIn.UserAgent)

            $signInRow.Add([pscustomobject]@{
                    TimeStamp     = Protect-CredEchoHtmlText $(if ($null -ne $stamp) { $stamp.ToString('yyyy-MM-dd HH:mm:ss') } else { '' })
                    HoursAfter    = Protect-CredEchoHtmlText $elapsed
                    IpAddress     = Protect-CredEchoHtmlText $signIn.IpAddress
                    IpPrefix      = Protect-CredEchoHtmlText $signIn.IpPrefix
                    UserAgent     = Protect-CredEchoHtmlText $signIn.UserAgent
                    ApplicationId = Protect-CredEchoHtmlText $signIn.ApplicationId
                    Tier          = Protect-CredEchoHtmlText $signIn.Tier
                    Signal        = @(@($signIn.Signal) | Where-Object { -not [string]::IsNullOrWhiteSpace([string] $_) } | ForEach-Object { Protect-CredEchoHtmlText $_ })
                    Enriched      = [bool] $signIn.Enriched
                })
        }

        $followOnRow = New-Object 'System.Collections.Generic.List[psobject]'
        foreach ($action in ($accountFollowOn | Sort-Object -Property @{ Expression = { ConvertTo-CredEchoDateTime $_.TimeStamp } })) {
            $stamp = ConvertTo-CredEchoDateTime $action.TimeStamp
            $searchTerm.Add([string] $action.IpAddress)
            $followOnRow.Add([pscustomobject]@{
                    TimeStamp = Protect-CredEchoHtmlText $(if ($null -ne $stamp) { $stamp.ToString('yyyy-MM-dd HH:mm:ss') } else { '' })
                    Operation = Protect-CredEchoHtmlText $action.Operation
                    Category  = Protect-CredEchoHtmlText $action.Category
                    IpAddress = Protect-CredEchoHtmlText $action.IpAddress
                })
        }

        # One chronological sequence per account, built here so the page needs no date parsing
        # and no charting library.
        $timelineEvent = New-Object 'System.Collections.Generic.List[psobject]'
        foreach ($record in $accountValidation) {
            if ($null -eq $record) { continue }
            $searchTerm.Add([string] $record.IpAddress)
            $searchTerm.Add([string] $record.UserAgent)
            $stamp = ConvertTo-CredEchoDateTime $record.TimeStamp
            $timelineEvent.Add([pscustomobject]@{
                    Sort   = $stamp
                    Kind   = 'validation'
                    Label  = "Credential validated, error $(Protect-CredEchoHtmlText $record.ErrorCode) $(Protect-CredEchoHtmlText $record.ErrorName)"
                    Detail = "$(Protect-CredEchoHtmlText $record.IpAddress) $(Protect-CredEchoHtmlText $record.UserAgent)"
                    Stamp  = $(if ($null -ne $stamp) { $stamp.ToString('yyyy-MM-dd HH:mm:ss') } else { '' })
                    Tier   = ''
                })
        }
        foreach ($signIn in $accountFlagged) {
            $stamp = ConvertTo-CredEchoDateTime $signIn.TimeStamp
            $timelineEvent.Add([pscustomobject]@{
                    Sort   = $stamp
                    Kind   = 'signin'
                    Label  = "Scored sign-in, $(Protect-CredEchoHtmlText $signIn.Tier) tier"
                    Detail = "$(Protect-CredEchoHtmlText $signIn.IpAddress) $(Protect-CredEchoHtmlText $signIn.UserAgent)"
                    Stamp  = $(if ($null -ne $stamp) { $stamp.ToString('yyyy-MM-dd HH:mm:ss') } else { '' })
                    Tier   = Protect-CredEchoHtmlText $signIn.Tier
                })
        }
        foreach ($action in $accountFollowOn) {
            $stamp = ConvertTo-CredEchoDateTime $action.TimeStamp
            $timelineEvent.Add([pscustomobject]@{
                    Sort   = $stamp
                    Kind   = 'followon'
                    Label  = "Follow-on action, $(Protect-CredEchoHtmlText $action.Operation)"
                    Detail = "$(Protect-CredEchoHtmlText $action.Category) $(Protect-CredEchoHtmlText $action.IpAddress)"
                    Stamp  = $(if ($null -ne $stamp) { $stamp.ToString('yyyy-MM-dd HH:mm:ss') } else { '' })
                    Tier   = ''
                })
        }

        $timeline = @($timelineEvent | Sort-Object -Property Sort | ForEach-Object {
                [pscustomobject]@{
                    Kind   = $_.Kind
                    Stamp  = Protect-CredEchoHtmlText $_.Stamp
                    Label  = $_.Label
                    Detail = $_.Detail
                    Tier   = $_.Tier
                }
            })

        $blob = (@($searchTerm | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join ' ').ToLowerInvariant()

        $accounts.Add([pscustomobject]@{
                UserPrincipalName    = Protect-CredEchoHtmlText $upn
                Verdict              = Protect-CredEchoHtmlText $account.Verdict
                FirstValidation      = Protect-CredEchoHtmlText $(if ($null -ne (ConvertTo-CredEchoDateTime $account.FirstValidation)) { (ConvertTo-CredEchoDateTime $account.FirstValidation).ToString('yyyy-MM-dd HH:mm:ss') } else { 'assumed, not derivable' })
                TimestampAssumed     = [bool] $account.ValidationTimestampAssumed
                BaselineSignInCount  = [int] $account.BaselineSignInCount
                BaselineAssessed     = [bool] $account.BaselineAssessed
                SubsequentSignInCount = [int] $account.PostValidationSignInCount
                FlaggedSignInCount   = [int] $account.FlaggedSignInCount
                FollowOnActionCount  = [int] $account.FollowOnActionCount
                NoveltyAssessment    = Protect-CredEchoHtmlText $account.NoveltyAssessment
                ValidationErrorCode  = @(@($account.ValidationErrorCode) | Where-Object { -not [string]::IsNullOrWhiteSpace([string] $_) } | ForEach-Object { Protect-CredEchoHtmlText $_ })
                DistinctSignal       = @(@($account.DistinctSignal) | Where-Object { -not [string]::IsNullOrWhiteSpace([string] $_) } | ForEach-Object { Protect-CredEchoHtmlText $_ })
                SignIn               = $signInRow.ToArray()
                FollowOn             = $followOnRow.ToArray()
                Timeline             = $timeline
                SearchBlob           = Protect-CredEchoHtmlText $blob
            })
    }

    $verdictCount = [ordered]@{}
    foreach ($tier in $ladder) {
        $verdictCount[$tier] = @($ordered | Where-Object { [string] $_.Verdict -eq $tier }).Count
    }

    $validationEvents = @($TriageResult.ValidationEvent)

    <#
    Each distinct list is built inline and wrapped in @() at the point of assignment.

    This is deliberate rather than clumsy. Invoking a scriptblock or a function that returns a
    one-element collection hands back a bare scalar, because PowerShell unwraps single-element
    output on the way out. ConvertTo-Json then writes a JSON string where the page expects a JSON
    array, and the renderer fails on the first call to map. Wrapping a pipeline in @() is the one
    construction that survives both the one-element case and the empty case, since a strongly
    typed empty array serialises as null rather than as an empty array.
    #>
    $indicatorSource = @($validationEvents | ForEach-Object { [string] $_.IpAddress } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique |
        ForEach-Object { Protect-CredEchoHtmlText $_ })

    $indicatorPrefix = @($validationEvents | ForEach-Object { [string] $_.IpPrefix } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique |
        ForEach-Object { Protect-CredEchoHtmlText $_ })

    $indicatorAgent = @($validationEvents | ForEach-Object { [string] $_.UserAgent } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique |
        ForEach-Object { Protect-CredEchoHtmlText $_ })

    $indicatorApplication = @($validationEvents | ForEach-Object { [string] $_.ApplicationId } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique |
        ForEach-Object { Protect-CredEchoHtmlText $_ })

    $payload = [pscustomobject]@{
        Meta       = [pscustomobject]@{
            TenantId          = Protect-CredEchoHtmlText $summary.TenantId
            GeneratedUtc      = Protect-CredEchoHtmlText $(if ($null -ne (ConvertTo-CredEchoDateTime $summary.GeneratedUtc)) { (ConvertTo-CredEchoDateTime $summary.GeneratedUtc).ToString('yyyy-MM-dd HH:mm:ss') } else { '' })
            ModuleVersion     = Protect-CredEchoHtmlText $summary.ModuleVersion
            SearchStartUtc    = Protect-CredEchoHtmlText $(if ($null -ne (ConvertTo-CredEchoDateTime $summary.SearchStartUtc)) { (ConvertTo-CredEchoDateTime $summary.SearchStartUtc).ToString('yyyy-MM-dd HH:mm:ss') } else { '' })
            SearchEndUtc      = Protect-CredEchoHtmlText $(if ($null -ne (ConvertTo-CredEchoDateTime $summary.SearchEndUtc)) { (ConvertTo-CredEchoDateTime $summary.SearchEndUtc).ToString('yyyy-MM-dd HH:mm:ss') } else { '' })
            BaselineDays      = [int] $summary.BaselineDays
            EnrichmentActive  = [bool] $summary.SignInEnrichmentAvailable
            CorroborationScope = Protect-CredEchoHtmlText $summary.CorroborationScope
            CorroborationThreshold = [int] $summary.CorroborationAccountThreshold
        }
        Verdict    = [pscustomobject]@{
            Confirmed    = [int] $verdictCount['Confirmed']
            Probable     = [int] $verdictCount['Probable']
            Possible     = [int] $verdictCount['Possible']
            NoIndicators = [int] $verdictCount['NoIndicators']
        }
        Context    = [pscustomobject]@{
            ValidatedAccountCount      = [int] $summary.ValidatedAccountCount
            ProbedNotValidatedCount    = [int] $summary.UsernameOracleAccountCount
            UnregisteredApplicationCount = [int] $summary.AttackerApplicationIdCount
            AttackerSourceCount        = @(@($validationEvents | ForEach-Object { [string] $_.IpAddress } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)).Count
            ValidationEventCount       = [int] $summary.ValidationEventCount
            UsernameOracleEventCount   = [int] $summary.UsernameOracleEventCount
            FlaggedSignInCount         = [int] $summary.FlaggedSignInCount
            FollowOnActionCount        = [int] $summary.FollowOnActionCount
            ExchangeFollowOnAvailable  = [bool] $summary.ExchangeFollowOnAvailable
        }
        Indicator  = [pscustomobject]@{
            SourceAddress            = $indicatorSource
            NetworkPrefix            = $indicatorPrefix
            UserAgent                = $indicatorAgent
            ApplicationId            = $indicatorApplication
            SuppressedByRegistration = @(@($summary.SuppressedByRegistration) | Where-Object { -not [string]::IsNullOrWhiteSpace([string] $_) } | ForEach-Object { Protect-CredEchoHtmlText $_ })
            SuppressedByCorroboration = @(@($summary.SuppressedByCorroboration) | Where-Object { -not [string]::IsNullOrWhiteSpace([string] $_) } | ForEach-Object { Protect-CredEchoHtmlText $_ })
            SuppressedByAllowlist    = @(@($summary.SuppressedByAllowlist) | Where-Object { -not [string]::IsNullOrWhiteSpace([string] $_) } | ForEach-Object { Protect-CredEchoHtmlText $_ })
            SuppressedByRegistrationCount = [int] $summary.SuppressedByRegistrationCount
            SuppressedByCorroborationCount = [int] $summary.SuppressedByCorroborationCount
            SuppressedByAllowlistCount = [int] $summary.SuppressedByAllowlistCount
        }
        Account    = $accounts.ToArray()
    }

    $json = $payload | ConvertTo-Json -Depth 10 -Compress

    # A closing script tag inside the payload would end the script block early. The values are
    # already HTML-encoded, so this cannot fire on tenant data, and it stays as a hard stop.
    $json = [regex]::Replace($json, '</script', '<\/script', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

    $scaffold = Get-CredEchoReportScaffold
    $html = $scaffold.Replace('__CREDECHO_REPORT_DATA__', $json)

    $directory = Split-Path -Path $Path -Parent
    if (-not [string]::IsNullOrWhiteSpace($directory) -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -Path $directory -ItemType Directory -Force | Out-Null
    }

    # Out-File -Encoding utf8 emits a byte order mark on PowerShell 5.1, which some browsers
    # render as a stray character before the doctype.
    [System.IO.File]::WriteAllText($Path, $html, [System.Text.UTF8Encoding]::new($false))

    (Resolve-Path -LiteralPath $Path).Path
}

function Get-CredEchoReportScaffold {
    <#
    .SYNOPSIS
    Returns the static markup, stylesheet, and script, with a placeholder where the data goes.

    .DESCRIPTION
    Held in a single-quoted here-string deliberately. A double-quoted here-string would
    interpolate every dollar sign in the stylesheet and the script and corrupt the output without
    raising an error.

    Every design value is baked in here rather than read from a template on disk, so a generated
    report has no dependency on any path outside this module and no dependency on the network.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param ()

    return @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CredEcho Post-Validation Account Triage</title>
<style>
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  font-size: 14px; line-height: 1.55; background: #f4f6fa; color: #1f2430;
}
html.dark body { background: #12141f; color: #e4e7f0; }
h1, h2, h3 { margin: 0 0 0.5rem; line-height: 1.25; }
h1 { font-size: 1.5rem; }
h2 { font-size: 1.125rem; }
h3 { font-size: 0.9375rem; }
p { margin: 0 0 0.75rem; }
.mono { font-family: monospace; font-size: 0.8125rem; word-break: break-all; }
.muted { color: #5b6478; }
html.dark .muted { color: #9aa3ba; }

/* ---------- sidebar ---------- */
.sidebar {
  position: fixed; top: 0; left: 0; width: 240px; height: 100vh; overflow-y: auto;
  background: #0a2540; color: #cdd3f0; padding: 1.5rem 0 2rem;
}
html.dark .sidebar { background: #061a30; }
.brand-wordmark { font-size: 1.5rem; font-weight: 700; letter-spacing: -0.02em; color: #fff; padding: 0 1.25rem; }
.brand-subline { font-size: 0.75rem; color: #7a93bd; padding: 0 1.25rem; }
html.dark .brand-subline { color: #506988; }
.brand-tagline {
  font-size: 0.625rem; text-transform: uppercase; letter-spacing: 0.14em; color: #7a93bd;
  padding: 0.85rem 1.25rem 0; line-height: 1.7;
}
html.dark .brand-tagline { color: #506988; }
.nav-section {
  font-size: 0.6875rem; text-transform: uppercase; letter-spacing: 0.1em; color: #7a93bd;
  padding: 1.4rem 1.25rem 0.4rem; font-weight: 600;
}
html.dark .nav-section { color: #506988; }
.sidebar a {
  display: block; padding: 0.4rem 1.25rem; color: #cdd3f0; text-decoration: none;
  font-size: 0.8125rem; border-left: 3px solid transparent;
}
.sidebar a:hover, .sidebar a:focus { background: #123a66; border-left-color: #4a7fc8; outline: none; }
html.dark .sidebar a:hover, html.dark .sidebar a:focus { background: #0f2e52; }
.nav-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 0.5rem; }
.nav-count { float: right; color: #7a93bd; font-variant-numeric: tabular-nums; }
html.dark .nav-count { color: #506988; }

/* ---------- layout ---------- */
main { margin-left: 240px; max-width: 1400px; padding: 2rem; }
section { margin-bottom: 1.5rem; }

.card {
  background: #fff; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.08);
  padding: 1rem 1.25rem;
}
html.dark .card { background: #1a1d2e; box-shadow: 0 1px 3px rgba(0,0,0,0.4); }

.page-header {
  background: #fff; border-left: 4px solid #1e5bb8; border-radius: 8px; padding: 1.25rem 1.5rem;
  box-shadow: 0 1px 3px rgba(0,0,0,0.08); margin-bottom: 1.5rem;
  display: flex; flex-wrap: wrap; gap: 1rem; align-items: flex-start; justify-content: space-between;
}
html.dark .page-header { background: #1a1d2e; border-left-color: #4a7fc8; box-shadow: 0 1px 3px rgba(0,0,0,0.4); }
.page-header .meta { font-size: 0.8125rem; color: #5b6478; }
html.dark .page-header .meta { color: #9aa3ba; }

.export-bar { display: flex; gap: 0.5rem; align-items: center; }
button {
  font-family: inherit; font-size: 0.8125rem; border-radius: 6px; cursor: pointer;
  border: 1px solid #c9d2e3; background: #fff; color: #1f2430; padding: 0.4rem 0.85rem;
}
button:hover { border-color: #1e5bb8; color: #1e5bb8; }
html.dark button { background: #232742; border-color: #343a5c; color: #e4e7f0; }
html.dark button:hover { border-color: #60a5fa; color: #60a5fa; }

/* ---------- print-only brand header ---------- */
.print-brand { display: none; }

/* ---------- verdict ladder ---------- */
.strip { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; }
.strip.context { grid-template-columns: repeat(4, 1fr); }
.verdict-card { border-top: 4px solid #c9d2e3; text-align: left; }
.verdict-card .count { font-size: 2rem; font-weight: 700; line-height: 1.1; font-variant-numeric: tabular-nums; }
.verdict-card .label { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.08em; font-weight: 600; color: #5b6478; }
html.dark .verdict-card .label { color: #9aa3ba; }
.verdict-card .note { font-size: 0.75rem; color: #5b6478; margin-top: 0.35rem; }
html.dark .verdict-card .note { color: #9aa3ba; }
.v-confirmed { border-top-color: #dc2626; }
.v-probable { border-top-color: #ea580c; }
.v-possible { border-top-color: #7c3aed; }
.v-noindicators { border-top-color: #16a34a; }
.v-confirmed .count { color: #dc2626; }
.v-probable .count { color: #ea580c; }
.v-possible .count { color: #7c3aed; }
.v-noindicators .count { color: #16a34a; }

.ctx-card .count { font-size: 1.25rem; font-weight: 700; font-variant-numeric: tabular-nums; }
.ctx-card .label { font-size: 0.6875rem; text-transform: uppercase; letter-spacing: 0.06em; color: #5b6478; font-weight: 600; }
html.dark .ctx-card .label { color: #9aa3ba; }

.pill {
  display: inline-block; border-radius: 9999px; padding: 0.15rem 0.65rem; font-size: 0.6875rem;
  font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; color: #fff; white-space: nowrap;
}
.p-confirmed { background: #dc2626; }
.p-probable { background: #ea580c; }
.p-possible { background: #7c3aed; }
.p-noindicators { background: #16a34a; }

/* ---------- scope panel ---------- */
.scope-panel { border-left: 4px solid #7c3aed; }
.scope-panel ul { margin: 0; padding-left: 1.25rem; }
.scope-panel li { margin-bottom: 0.4rem; }

/* ---------- indicators ---------- */
.indicator-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1rem; }
.indicator-block h3 { margin-bottom: 0.35rem; }
.indicator-list { margin: 0; padding: 0; list-style: none; }
.indicator-list li {
  font-family: monospace; font-size: 0.8125rem; padding: 0.2rem 0.45rem; margin-bottom: 0.2rem;
  background: #f4f6fa; border-radius: 6px; word-break: break-all;
}
html.dark .indicator-list li { background: #232742; }
.suppression { margin-top: 1rem; border-top: 1px solid #e3e8f2; padding-top: 0.75rem; }
html.dark .suppression { border-top-color: #2a2f45; }

/* ---------- filters ---------- */
.filter-bar { display: flex; flex-wrap: wrap; gap: 0.75rem; align-items: center; margin-bottom: 1rem; }
.chip {
  display: inline-flex; align-items: center; gap: 0.4rem; border-radius: 9999px;
  border: 1px solid #c9d2e3; padding: 0.25rem 0.75rem; font-size: 0.75rem; cursor: pointer;
  user-select: none; font-weight: 600;
}
html.dark .chip { border-color: #343a5c; }
.chip input { margin: 0; cursor: pointer; }
.chip .swatch { width: 10px; height: 10px; border-radius: 50%; }
input[type="search"] {
  font-family: inherit; font-size: 0.8125rem; padding: 0.4rem 0.65rem; border-radius: 6px;
  border: 1px solid #c9d2e3; background: #fff; color: #1f2430; min-width: 22rem; flex: 1 1 18rem;
}
html.dark input[type="search"] { background: #232742; border-color: #343a5c; color: #e4e7f0; }
#showing-count { font-size: 0.8125rem; color: #5b6478; font-variant-numeric: tabular-nums; }
html.dark #showing-count { color: #9aa3ba; }

/* ---------- accounts ---------- */
.account { margin-bottom: 0.85rem; padding: 0; overflow: hidden; }
.account-head {
  display: flex; flex-wrap: wrap; gap: 0.75rem; align-items: center; padding: 0.85rem 1.25rem;
  cursor: pointer;
}
.account-head:hover { background: #f4f6fa; }
html.dark .account-head:hover { background: #232742; }
.account-head .upn { font-weight: 600; font-family: monospace; font-size: 0.875rem; }
.account-head .spacer { flex: 1 1 auto; }
.account-metric { font-size: 0.75rem; color: #5b6478; white-space: nowrap; }
html.dark .account-metric { color: #9aa3ba; }
.account-metric strong { font-variant-numeric: tabular-nums; color: #1f2430; }
html.dark .account-metric strong { color: #e4e7f0; }
.chev { display: inline-block; width: 1rem; color: #7a93bd; }
.account-body { display: none; padding: 0 1.25rem 1.25rem; border-top: 1px solid #e3e8f2; }
html.dark .account-body { border-top-color: #2a2f45; }
.account.open .account-body { display: block; }
.subhead {
  font-size: 0.6875rem; text-transform: uppercase; letter-spacing: 0.08em; font-weight: 700;
  color: #5b6478; margin: 1rem 0 0.5rem;
}
html.dark .subhead { color: #9aa3ba; }

table { width: 100%; border-collapse: collapse; font-size: 0.8125rem; }
th, td { text-align: left; padding: 0.4rem 0.5rem; border-bottom: 1px solid #e3e8f2; vertical-align: top; }
html.dark th, html.dark td { border-bottom-color: #2a2f45; }
th { font-size: 0.6875rem; text-transform: uppercase; letter-spacing: 0.05em; color: #5b6478; font-weight: 600; }
html.dark th { color: #9aa3ba; }
td.num { font-variant-numeric: tabular-nums; white-space: nowrap; }
.signal-tag {
  display: inline-block; font-size: 0.6875rem; background: #f4f6fa; border-radius: 6px;
  padding: 0.1rem 0.4rem; margin: 0 0.2rem 0.2rem 0; font-family: monospace;
}
html.dark .signal-tag { background: #232742; }

/* ---------- timeline, CSS only ---------- */
.timeline { list-style: none; margin: 0.5rem 0 0; padding: 0; border-left: 2px solid #dfe4ee; }
html.dark .timeline { border-left-color: #2a2f45; }
.timeline li { position: relative; padding: 0.3rem 0 0.55rem 1.35rem; }
.timeline li::before {
  content: ''; position: absolute; left: -7px; top: 0.6rem; width: 10px; height: 10px;
  border-radius: 50%; background: #7a93bd; border: 2px solid #fff;
}
html.dark .timeline li::before { border-color: #1a1d2e; }
.timeline li.k-validation::before { background: #1e5bb8; }
.timeline li.k-signin::before { background: #7a93bd; }
.timeline li.k-signin.t-confirmed::before { background: #dc2626; }
.timeline li.k-signin.t-probable::before { background: #ea580c; }
.timeline li.k-signin.t-possible::before { background: #7c3aed; }
.timeline li.k-followon::before { background: #7c3aed; }
.timeline .tl-when { font-family: monospace; font-size: 0.75rem; color: #5b6478; }
html.dark .timeline .tl-when { color: #9aa3ba; }
.timeline .tl-what { font-size: 0.8125rem; font-weight: 600; }
.timeline .tl-detail { font-family: monospace; font-size: 0.75rem; color: #5b6478; word-break: break-all; }
html.dark .timeline .tl-detail { color: #9aa3ba; }

.notice { font-size: 0.8125rem; padding: 0.5rem 0.75rem; border-radius: 6px; background: #f4f6fa; border-left: 3px solid #7c3aed; }
html.dark .notice { background: #232742; }

/* ---------- footer ---------- */
.brand-footer {
  background: #fff; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.08);
  padding: 1.25rem 1.5rem; margin-top: 2rem; text-align: center;
}
html.dark .brand-footer { background: #1a1d2e; box-shadow: 0 1px 3px rgba(0,0,0,0.4); }
.brand-footer .brand-wordmark { color: #0a2540; padding: 0; }
html.dark .brand-footer .brand-wordmark { color: #60a5fa; }
.brand-footer .tagline { font-size: 0.8125rem; color: #5b6478; margin: 0.15rem 0 0.35rem; }
html.dark .brand-footer .tagline { color: #9aa3ba; }
.brand-footer a { color: #1e5bb8; text-decoration: none; font-size: 0.8125rem; font-weight: 600; }
.brand-footer a:hover { text-decoration: underline; }
html.dark .brand-footer a { color: #60a5fa; }
.brand-footer .stamp { font-size: 0.75rem; color: #5b6478; margin-top: 0.5rem; }
html.dark .brand-footer .stamp { color: #9aa3ba; }

@media (max-width: 1100px) {
  .strip, .strip.context { grid-template-columns: repeat(2, 1fr); }
  .indicator-grid { grid-template-columns: 1fr; }
}
@media (max-width: 800px) {
  .sidebar { display: none; }
  main { margin-left: 0; padding: 1rem; }
}

/* ---------- print ---------- */
@media print {
  .sidebar { display: none !important; }
  main { margin-left: 0 !important; max-width: none !important; padding: 0 !important; }
  .print-brand { display: block !important; border-bottom: 3px solid #1e5bb8; padding-bottom: 0.75rem; margin-bottom: 1.25rem; }
  .print-brand .brand-wordmark { color: #0a2540 !important; padding: 0; font-size: 1.75rem; }
  .print-brand .tagline { font-size: 0.8125rem; color: #33415c; }
  .export-bar, #theme-toggle, .filter-bar, .account-toggle, .chev { display: none !important; }
  .account-body { display: block !important; }
  .account-head { cursor: default; }
  .account, .card, .page-header, .brand-footer { break-inside: avoid; page-break-inside: avoid; box-shadow: none !important; border: 1px solid #d5dbe8 !important; }
  section { break-inside: avoid; page-break-inside: avoid; }
  html.dark body, html.dark .card, html.dark .page-header, html.dark .account,
  html.dark .brand-footer, html.dark table, html.dark th, html.dark td, html.dark .notice,
  html.dark .indicator-list li, html.dark .signal-tag, html.dark .account-body {
    background: #fff !important; color: #111 !important;
  }
  html.dark .muted, html.dark .account-metric, html.dark th, html.dark .tl-when,
  html.dark .tl-detail, html.dark .verdict-card .label, html.dark .ctx-card .label,
  html.dark .subhead, html.dark .brand-footer .tagline, html.dark .brand-footer .stamp {
    color: #40495c !important;
  }
  html.dark .brand-footer .brand-wordmark { color: #0a2540 !important; }
  html.dark .timeline { border-left-color: #c9d2e3 !important; }
  html.dark .timeline li::before { border-color: #fff !important; }
  a { text-decoration: none; color: #1e5bb8 !important; }
}
</style>
</head>
<body>

<nav class="sidebar">
  <div class="brand-wordmark">CredEcho</div>
  <div class="brand-subline">by Soteria</div>
  <div class="brand-tagline">POST-VALIDATION<br>ACCOUNT TRIAGE</div>

  <div class="nav-section">Report</div>
  <a href="#verdicts">Verdict summary</a>
  <a href="#context">Engagement context</a>
  <a href="#scope">Scope and limitations</a>
  <a href="#indicators">Attacker indicators</a>
  <a href="#accounts">Account triage</a>

  <div class="nav-section">Verdicts</div>
  <div id="nav-verdicts"></div>
</nav>

<main>
  <div class="print-brand">
    <div class="brand-wordmark">CredEcho</div>
    <div class="tagline">Cybersecurity Expertise to Protect Your Digital Journey</div>
  </div>

  <header class="page-header">
    <div>
      <h1>Post-Validation Account Triage</h1>
      <div class="meta" id="header-meta"></div>
    </div>
    <div class="export-bar">
      <button type="button" id="print-button">Print or save as PDF</button>
      <button type="button" id="theme-toggle" aria-label="Switch theme"></button>
    </div>
  </header>

  <section id="verdicts">
    <h2>Verdict summary</h2>
    <div class="strip" id="verdict-strip"></div>
  </section>

  <section id="context">
    <h2>Engagement context</h2>
    <div class="strip context" id="context-strip"></div>
  </section>

  <section id="scope">
    <h2>Scope and limitations</h2>
    <div class="card scope-panel">
      <p>This report identifies accounts in the organization's tenant whose passwords were
      confirmed valid by an adversary, and scores which of those accounts were subsequently
      accessed by someone other than the account owner. The following constraints govern how the
      findings may be read.</p>
      <ul>
        <li><strong>The output is investigative leads rather than proof.</strong> A verdict states
        how strongly the retained evidence supports unauthorized access. It is not a
        determination of compromise, and it does not establish what an actor did once inside.
        Every account listed warrants analyst review before any conclusion is drawn.</li>
        <li><strong>A clean result is bounded by audit retention.</strong> Directory audit
        retention limits how far back this analysis can see. Activity that fell outside the
        retained window is absent from the source data, so the absence of a finding for an
        account is not evidence that nothing happened to it.</li>
        <li><strong>The detected account set is a floor, not a total.</strong> Authentication
        attempts against usernames that do not exist in the directory are never logged, so the
        adversary's target list is larger than anything observable here. The count of accounts
        confirmed is a lower bound on the scale of the campaign.</li>
        <li><strong>Network prefix matching is a coarse proxy.</strong> The audit source carries
        no autonomous system number and no geolocation, so shared infrastructure is approximated
        by an IPv4 or IPv6 network prefix. A large hosting provider or a carrier grade address
        translation range will place unrelated traffic in the same prefix, which is why prefix
        matches are scored one tier below exact source address matches.</li>
        <li><strong>Accounts with no baseline activity are unassessable, not clean.</strong> Where
        an account produced no successful sign-in during its baseline period, there is no known
        good source address, network prefix, or user agent to compare against. Those accounts
        carry an explicit signal saying novelty could not be assessed, and they require manual
        review rather than dismissal.</li>
        <li><strong>Signal availability varies.</strong> Multifactor authentication state,
        Conditional Access outcome, client application, and risk level are not present in the
        audit source and are available only where sign-in log enrichment was active and within
        its own shorter retention window. Forwarding these records to an external log management
        system or security information and event management platform extends the window available
        to future analysis.</li>
      </ul>
    </div>
  </section>

  <section id="indicators">
    <h2>Attacker indicators</h2>
    <div class="card">
      <div class="indicator-grid" id="indicator-grid"></div>
      <div class="suppression" id="suppression-block"></div>
    </div>
  </section>

  <section id="accounts">
    <h2>Account triage</h2>
    <div class="card filter-bar">
      <div class="chips" id="verdict-chips"></div>
      <input type="search" id="search-box" placeholder="Search user principal name, source address, or user agent">
      <span id="showing-count"></span>
      <button type="button" id="clear-filters">Clear filters</button>
      <button type="button" id="expand-all">Expand all</button>
      <button type="button" id="collapse-all">Collapse all</button>
    </div>
    <div id="account-list"></div>
  </section>

  <footer class="brand-footer">
    <div class="brand-wordmark">CredEcho</div>
    <div class="tagline">Cybersecurity Expertise to Protect Your Digital Journey</div>
    <a href="https://soteria.io" rel="noreferrer">soteria.io</a>
    <div class="stamp" id="footer-stamp"></div>
  </footer>
</main>

<script id="report-data">var REPORT_DATA = __CREDECHO_REPORT_DATA__;</script>
<script>
(function () {
  'use strict';

  var D = REPORT_DATA;
  var LADDER = ['Confirmed', 'Probable', 'Possible', 'NoIndicators'];
  var LABEL = {
    Confirmed: 'Confirmed',
    Probable: 'Probable',
    Possible: 'Possible',
    NoIndicators: 'No Indicators'
  };
  var NOTE = {
    Confirmed: 'Direct indicator match, or a persistence action alongside a flagged sign-in.',
    Probable: 'Anomalous against baseline, short of a direct indicator match.',
    Possible: 'Unresolved rather than lesser. Requires analyst triage.',
    NoIndicators: 'No anomalous post-validation access found within the retained window.'
  };
  var COLOR = {
    Confirmed: '#dc2626',
    Probable: '#ea580c',
    Possible: '#7c3aed',
    NoIndicators: '#16a34a'
  };

  function cls(v) { return String(v || '').toLowerCase(); }
  function el(id) { return document.getElementById(id); }

  /* Every collection that crossed the JSON boundary is normalised before it is walked. The
     generator unwraps a one-element collection into a bare scalar, and a bare string answers
     truthily and reports a length while having no map method, so an unguarded walk would fail on
     exactly the reports that carry a single indicator. */
  function list(value) {
    if (value === null || value === undefined) { return []; }
    return Array.isArray(value) ? value : [value];
  }

  /* ---------- theme ---------- */
  var root = document.documentElement;
  var saved = null;
  try { saved = window.localStorage.getItem('credecho-theme'); } catch (e) { saved = null; }
  if (saved === 'dark') {
    root.classList.add('dark');
  } else if (saved !== 'light' && window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
    root.classList.add('dark');
  }

  function syncToggle() {
    var dark = root.classList.contains('dark');
    var b = el('theme-toggle');
    /* Sun and moon written as escapes so the generator source stays pure ASCII. A byte order
       mark free source file is read as ANSI by Windows PowerShell, which would corrupt a
       literal glyph on the way into the output. */
    b.textContent = dark ? '\u2600 Light' : '\u263E Dark';
    b.setAttribute('aria-label', dark ? 'Switch to light theme' : 'Switch to dark theme');
  }

  el('theme-toggle').addEventListener('click', function () {
    root.classList.toggle('dark');
    try {
      window.localStorage.setItem('credecho-theme', root.classList.contains('dark') ? 'dark' : 'light');
    } catch (e) { /* storage unavailable from a file URI in some browsers */ }
    syncToggle();
  });
  syncToggle();

  el('print-button').addEventListener('click', function () { window.print(); });

  /* ---------- header and footer ---------- */
  el('header-meta').innerHTML =
    'Tenant identifier <span class="mono">' + D.Meta.TenantId + '</span>' +
    ' &middot; generated ' + D.Meta.GeneratedUtc + ' UTC' +
    ' &middot; search window ' + D.Meta.SearchStartUtc + ' to ' + D.Meta.SearchEndUtc + ' UTC' +
    ' &middot; module version ' + D.Meta.ModuleVersion;
  el('footer-stamp').textContent = 'Report generated ' + D.Meta.GeneratedUtc + ' UTC';

  /* ---------- verdict strip and sidebar verdict list ---------- */
  var strip = '';
  var nav = '';
  LADDER.forEach(function (tier) {
    var n = D.Verdict[tier] || 0;
    strip += '<div class="card verdict-card v-' + cls(tier) + '">' +
      '<div class="count">' + n + '</div>' +
      '<div class="label">' + LABEL[tier] + '</div>' +
      '<div class="note">' + NOTE[tier] + '</div>' +
      '</div>';
    nav += '<a href="#accounts" data-verdict-filter="' + tier + '">' +
      '<span class="nav-dot" style="background:' + COLOR[tier] + '"></span>' + LABEL[tier] +
      '<span class="nav-count">' + n + '</span></a>';
  });
  el('verdict-strip').innerHTML = strip;
  el('nav-verdicts').innerHTML = nav;

  /* ---------- engagement context ---------- */
  var C = D.Context;
  var ctx = [
    { label: 'Accounts with confirmed credentials', value: C.ValidatedAccountCount },
    { label: 'Accounts probed but not validated', value: C.ProbedNotValidatedCount },
    { label: 'Unregistered application identifiers', value: C.UnregisteredApplicationCount },
    { label: 'Distinct attacker source addresses', value: C.AttackerSourceCount },
    { label: 'Validation events', value: C.ValidationEventCount },
    { label: 'Flagged sign-ins', value: C.FlaggedSignInCount },
    { label: 'Follow-on actions', value: C.FollowOnActionCount },
    { label: 'Baseline length', value: D.Meta.BaselineDays + ' days' },
    { label: 'Search window start', value: D.Meta.SearchStartUtc + ' UTC' },
    { label: 'Search window end', value: D.Meta.SearchEndUtc + ' UTC' },
    { label: 'Sign-in log enrichment', value: D.Meta.EnrichmentActive ? 'Active' : 'Not active' },
    { label: 'Corroboration scope', value: D.Meta.CorroborationScope }
  ];
  el('context-strip').innerHTML = ctx.map(function (c) {
    return '<div class="card ctx-card"><div class="count">' + c.value + '</div>' +
      '<div class="label">' + c.label + '</div></div>';
  }).join('');

  /* ---------- attacker indicators ---------- */
  var I = D.Indicator;
  function block(title, items, emptyText) {
    var rows = list(items);
    var body = rows.length
      ? '<ul class="indicator-list">' + rows.map(function (i) { return '<li>' + i + '</li>'; }).join('') + '</ul>'
      : '<p class="muted">' + emptyText + '</p>';
    return '<div class="indicator-block"><h3>' + title + ' <span class="muted">(' +
      rows.length + ')</span></h3>' + body + '</div>';
  }
  el('indicator-grid').innerHTML =
    block('Source addresses', I.SourceAddress, 'No source address was recorded on the validation events.') +
    block('Network prefixes', I.NetworkPrefix, 'No network prefix could be derived.') +
    block('User agents', I.UserAgent, 'No user agent was recorded on the validation events.') +
    block('Unregistered application identifiers', I.ApplicationId, 'No application identifier was recorded, which is what a malformed client identifier produces.');

  function suppressionRow(title, count, items, explanation) {
    var rows = list(items);
    var listed = rows.length ? ' <span class="mono">' + rows.join(', ') + '</span>' : '';
    return '<li><strong>' + title + ':</strong> ' + count + '.' + ' ' + explanation + listed + '</li>';
  }
  el('suppression-block').innerHTML =
    '<h3>Suppressed application identifiers</h3>' +
    '<p class="muted">Suppression is reported rather than applied silently, so a reader can see which identifiers were cleared and by which control.</p>' +
    '<ul>' +
    suppressionRow('Service principal present in the tenant', I.SuppressedByRegistrationCount, I.SuppressedByRegistration,
      'These identifiers resolve to an application registered in the directory, so they are not adversary supplied.') +
    suppressionRow('Tenant-wide corroboration', I.SuppressedByCorroborationCount, I.SuppressedByCorroboration,
      'Observed in successful sign-ins across at least ' + D.Meta.CorroborationThreshold +
      ' distinct accounts during the baseline period, which an adversary identifier cannot achieve.') +
    suppressionRow('Explicit analyst allowlist', I.SuppressedByAllowlistCount, I.SuppressedByAllowlist,
      'Excluded by the analyst running the collection.') +
    '</ul>';

  /* ---------- account cards ---------- */
  function signalTags(tags) {
    var rows = list(tags);
    if (!rows.length) { return '<span class="muted">none</span>'; }
    return rows.map(function (s) { return '<span class="signal-tag">' + s + '</span>'; }).join('');
  }

  function signInTable(source) {
    var rows = list(source);
    if (!rows.length) {
      return '<p class="muted">No post-validation sign-in earned a signal for this account.</p>';
    }
    var h = '<table><thead><tr>' +
      '<th>Timestamp (UTC)</th><th>Hours after validation</th><th>Source address</th>' +
      '<th>User agent</th><th>Application identifier</th><th>Tier</th><th>Signals</th>' +
      '</tr></thead><tbody>';
    rows.forEach(function (r) {
      h += '<tr>' +
        '<td class="num mono">' + r.TimeStamp + '</td>' +
        '<td class="num">' + r.HoursAfter + '</td>' +
        '<td class="mono">' + r.IpAddress + '<br><span class="muted">' + r.IpPrefix + '</span></td>' +
        '<td class="mono">' + r.UserAgent + '</td>' +
        '<td class="mono">' + r.ApplicationId + '</td>' +
        '<td><span class="pill p-' + cls(r.Tier) + '">' + r.Tier + '</span></td>' +
        '<td>' + signalTags(r.Signal) + '</td>' +
        '</tr>';
    });
    return h + '</tbody></table>';
  }

  function followOnTable(source) {
    var rows = list(source);
    if (!rows.length) {
      return '<p class="muted">No follow-on persistence action was recorded for this account.</p>';
    }
    var h = '<table><thead><tr><th>Timestamp (UTC)</th><th>Operation</th><th>Category</th>' +
      '<th>Source address</th></tr></thead><tbody>';
    rows.forEach(function (r) {
      h += '<tr><td class="num mono">' + r.TimeStamp + '</td><td>' + r.Operation + '</td>' +
        '<td>' + r.Category + '</td><td class="mono">' + r.IpAddress + '</td></tr>';
    });
    return h + '</tbody></table>';
  }

  function timelineList(source) {
    var rows = list(source);
    if (!rows.length) { return '<p class="muted">No dated event is available for this account.</p>'; }
    return '<ul class="timeline">' + rows.map(function (r) {
      return '<li class="k-' + r.Kind + (r.Tier ? ' t-' + cls(r.Tier) : '') + '">' +
        '<div class="tl-when">' + r.Stamp + ' UTC</div>' +
        '<div class="tl-what">' + r.Label + '</div>' +
        '<div class="tl-detail">' + r.Detail + '</div>' +
        '</li>';
    }).join('') + '</ul>';
  }

  function accountCard(a) {
    var baselineNote = a.BaselineAssessed
      ? ''
      : '<div class="notice">' + a.NoveltyAssessment + '</div>';
    var assumedNote = a.TimestampAssumed
      ? '<div class="notice">The validation timestamp was not derivable for this account, so the start of the search window was used as the anchor. Elapsed times are measured from that assumed anchor.</div>'
      : '';

    return '<article class="card account" data-verdict="' + a.Verdict + '" data-search="' + a.SearchBlob + '">' +
      '<div class="account-head">' +
        '<span class="chev account-toggle">&#9656;</span>' +
        '<span class="upn">' + a.UserPrincipalName + '</span>' +
        '<span class="pill p-' + cls(a.Verdict) + '">' + LABEL[a.Verdict] + '</span>' +
        '<span class="spacer"></span>' +
        '<span class="account-metric">Validated <strong>' + a.FirstValidation + '</strong></span>' +
        '<span class="account-metric">Baseline <strong>' + a.BaselineSignInCount + '</strong></span>' +
        '<span class="account-metric">Subsequent <strong>' + a.SubsequentSignInCount + '</strong></span>' +
        '<span class="account-metric">Flagged <strong>' + a.FlaggedSignInCount + '</strong></span>' +
        '<span class="account-metric">Follow-on <strong>' + a.FollowOnActionCount + '</strong></span>' +
      '</div>' +
      '<div class="account-body">' +
        assumedNote + baselineNote +
        '<div class="subhead">Timeline</div>' + timelineList(a.Timeline) +
        '<div class="subhead">Scored sign-ins</div>' + signInTable(a.SignIn) +
        '<div class="subhead">Follow-on actions</div>' + followOnTable(a.FollowOn) +
        '<div class="subhead">Distinct signals for this account</div>' + signalTags(a.DistinctSignal) +
      '</div>' +
      '</article>';
  }

  var accounts = list(D.Account);
  el('account-list').innerHTML = accounts.length
    ? accounts.map(accountCard).join('')
    : '<div class="card"><p class="muted">No account reached triage. Either no validation event was detected in the search window, or every post-password error resolved to a registered application.</p></div>';

  /* ---------- expand and collapse ---------- */
  document.querySelectorAll('.account-head').forEach(function (head) {
    head.addEventListener('click', function () {
      var card = head.parentNode;
      card.classList.toggle('open');
      var chev = head.querySelector('.chev');
      if (chev) { chev.innerHTML = card.classList.contains('open') ? '&#9662;' : '&#9656;'; }
    });
  });

  function setAll(open) {
    document.querySelectorAll('.account').forEach(function (card) {
      if (open) { card.classList.add('open'); } else { card.classList.remove('open'); }
      var chev = card.querySelector('.chev');
      if (chev) { chev.innerHTML = open ? '&#9662;' : '&#9656;'; }
    });
  }
  el('expand-all').addEventListener('click', function () { setAll(true); });
  el('collapse-all').addEventListener('click', function () { setAll(false); });

  /* ---------- filters ---------- */
  el('verdict-chips').innerHTML = LADDER.map(function (tier) {
    return '<label class="chip"><input type="checkbox" class="verdict-filter" value="' + tier +
      '" checked><span class="swatch" style="background:' + COLOR[tier] + '"></span>' +
      LABEL[tier] + '</label>';
  }).join('');

  function applyFilters() {
    var checked = {};
    document.querySelectorAll('.verdict-filter').forEach(function (box) {
      if (box.checked) { checked[box.value] = true; }
    });
    var term = el('search-box').value.trim().toLowerCase();
    var shown = 0;
    var cards = document.querySelectorAll('.account');
    cards.forEach(function (card) {
      var verdictOk = checked[card.getAttribute('data-verdict')] === true;
      var textOk = term === '' || (card.getAttribute('data-search') || '').indexOf(term) !== -1;
      var visible = verdictOk && textOk;
      card.style.display = visible ? '' : 'none';
      if (visible) { shown++; }
    });
    el('showing-count').textContent = 'Showing ' + shown + ' of ' + cards.length + ' accounts';
  }

  document.querySelectorAll('.verdict-filter').forEach(function (box) {
    box.addEventListener('change', applyFilters);
  });
  el('search-box').addEventListener('input', applyFilters);

  el('clear-filters').addEventListener('click', function () {
    document.querySelectorAll('.verdict-filter').forEach(function (box) { box.checked = true; });
    el('search-box').value = '';
    applyFilters();
  });

  document.querySelectorAll('[data-verdict-filter]').forEach(function (link) {
    link.addEventListener('click', function () {
      var wanted = link.getAttribute('data-verdict-filter');
      document.querySelectorAll('.verdict-filter').forEach(function (box) {
        box.checked = (box.value === wanted);
      });
      el('search-box').value = '';
      applyFilters();
    });
  });

  applyFilters();
})();
</script>
</body>
</html>
'@
}
