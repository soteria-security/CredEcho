function Get-CredEchoValidationEvent {
    <#
    .SYNOPSIS
    Separates confirmed credential validations from mere probing, and applies the false
    positive controls to the application registration test.

    .DESCRIPTION
    A post-password error code means the submitted password validated before the security
    token service failed the request for another reason. Those records, once the application
    identifier is shown not to belong to the tenant, are the validation events.

    Username oracle events are counted and returned as campaign context because they establish
    the scale of the probing, and they are deliberately not turned into triage targets. An
    account that produced only 50126 was probed and not validated, and including it buries the
    real leads.

    An absent or empty ApplicationId is treated as not corresponding to a service principal.
    A client identifier that is not a well formed GUID is not recorded in the application
    identifier field at all, so discarding those records would drop exactly the subset of the
    technique that leaves the emptiest trail.

    Suppression is counted per control and returned rather than applied silently.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [psobject[]] $LogonRecord,

        [Parameter(Mandatory)]
        [psobject] $KnownApplication
    )

    $newSet = { New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase) }

    $validationEvent = New-Object 'System.Collections.Generic.List[psobject]'
    $suppressedByAllowlist = & $newSet
    $suppressedByRegistration = & $newSet
    $suppressedByCorroboration = & $newSet
    $attackerApplication = & $newSet
    $validatedAccount = & $newSet

    foreach ($record in @($LogonRecord | Where-Object { $_.ErrorClass -eq 'PostPassword' })) {
        $appId = [string] $record.ApplicationId

        if (-not [string]::IsNullOrWhiteSpace($appId)) {
            if ($KnownApplication.Allowed.Contains($appId)) {
                [void] $suppressedByAllowlist.Add($appId)
                continue
            }
            if ($KnownApplication.Registered.Contains($appId)) {
                [void] $suppressedByRegistration.Add($appId)
                continue
            }
            if ($KnownApplication.Corroborated.Contains($appId)) {
                [void] $suppressedByCorroboration.Add($appId)
                continue
            }
            [void] $attackerApplication.Add($appId)
        }

        $validationEvent.Add($record)
        if (-not [string]::IsNullOrWhiteSpace([string] $record.UserPrincipalName)) {
            [void] $validatedAccount.Add([string] $record.UserPrincipalName)
        }
    }

    $oracleRecord = @($LogonRecord | Where-Object { $_.ErrorClass -eq 'UsernameOracle' })
    $oracleAccount = & $newSet
    $oracleSource = & $newSet
    foreach ($record in $oracleRecord) {
        if (-not [string]::IsNullOrWhiteSpace([string] $record.UserPrincipalName)) {
            [void] $oracleAccount.Add([string] $record.UserPrincipalName)
        }
        if (-not [string]::IsNullOrWhiteSpace([string] $record.IpAddress)) {
            [void] $oracleSource.Add([string] $record.IpAddress)
        }
    }

    $timestamp = @($validationEvent | Where-Object { $null -ne $_.TimeStamp } | ForEach-Object { $_.TimeStamp } | Sort-Object)

    [pscustomobject]@{
        ValidationEvent                = $validationEvent.ToArray()
        ValidationEventCount           = $validationEvent.Count
        ValidatedAccount               = @($validatedAccount)
        ValidatedAccountCount          = $validatedAccount.Count
        AttackerApplicationId          = @($attackerApplication)
        AttackerApplicationIdCount     = $attackerApplication.Count
        FirstValidation                = $(if ($timestamp.Count -gt 0) { $timestamp[0] } else { $null })
        LastValidation                 = $(if ($timestamp.Count -gt 0) { $timestamp[-1] } else { $null })
        UsernameOracleEventCount       = $oracleRecord.Count
        UsernameOracleAccountCount     = $oracleAccount.Count
        UsernameOracleSourceCount      = $oracleSource.Count
        SuppressedByAllowlist          = @($suppressedByAllowlist)
        SuppressedByAllowlistCount     = $suppressedByAllowlist.Count
        SuppressedByRegistration       = @($suppressedByRegistration)
        SuppressedByRegistrationCount  = $suppressedByRegistration.Count
        SuppressedByCorroboration      = @($suppressedByCorroboration)
        SuppressedByCorroborationCount = $suppressedByCorroboration.Count
    }
}
