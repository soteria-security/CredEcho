function Get-CredEchoKnownApplication {
    <#
    .SYNOPSIS
    Builds the set of application identifiers that must not be treated as attacker supplied.

    .DESCRIPTION
    The unified audit log carries no application display name, so the registration test runs
    against ApplicationId alone. Three sets are returned, and they are kept separate so the
    caller can report how many identifiers each control suppressed rather than hiding the
    suppression:

      Registered    An application identifier belonging to a service principal object in the
                    tenant.
      Corroborated  An identifier observed in successful sign-ins across at least
                    CorroborationAccountThreshold distinct accounts during the baseline
                    period. Some legitimate Microsoft first party applications have no
                    service principal provisioned in a given tenant, and this control catches
                    them. An attacker identifier cannot reach the threshold, because it never
                    produces a successful sign-in.
      Allowed       Supplied by the analyst to suppress a known internal client without
                    editing code.

    Corroborated and Allowed exclude anything already Registered so the three counts do not
    double count the same identifier.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter()]
        [AllowEmptyCollection()]
        [psobject[]] $BaselineSuccess = @(),

        [int] $CorroborationAccountThreshold = 3,

        [string[]] $AllowedApplicationId = @()
    )

    $registered = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

    $uri = 'https://graph.microsoft.com/v1.0/servicePrincipals?$select=appId&$top=999'
    while ($uri) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $uri
        foreach ($servicePrincipal in @($page['value'])) {
            $appId = [string] $servicePrincipal['appId']
            if (-not [string]::IsNullOrWhiteSpace($appId)) { [void] $registered.Add($appId.Trim()) }
        }
        $uri = [string] $page['@odata.nextLink']
    }

    Write-Verbose "Enumerated $($registered.Count) service principal application identifiers."

    $accountsByApplication = @{}
    foreach ($record in $BaselineSuccess) {
        $appId = [string] $record.ApplicationId
        $upn = [string] $record.UserPrincipalName
        if ([string]::IsNullOrWhiteSpace($appId) -or [string]::IsNullOrWhiteSpace($upn)) { continue }

        if (-not $accountsByApplication.ContainsKey($appId)) {
            $accountsByApplication[$appId] = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        }
        [void] $accountsByApplication[$appId].Add($upn)
    }

    $corroborated = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($appId in $accountsByApplication.Keys) {
        if ($accountsByApplication[$appId].Count -ge $CorroborationAccountThreshold -and -not $registered.Contains($appId)) {
            [void] $corroborated.Add($appId)
        }
    }

    $allowed = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($appId in $AllowedApplicationId) {
        if ([string]::IsNullOrWhiteSpace($appId)) { continue }
        $trimmed = $appId.Trim()
        if (-not $registered.Contains($trimmed)) { [void] $allowed.Add($trimmed) }
    }

    [pscustomobject]@{
        Registered                    = $registered
        Corroborated                  = $corroborated
        Allowed                       = $allowed
        RegisteredCount               = $registered.Count
        CorroboratedCount             = $corroborated.Count
        AllowedCount                  = $allowed.Count
        CorroborationAccountThreshold = $CorroborationAccountThreshold
    }
}
