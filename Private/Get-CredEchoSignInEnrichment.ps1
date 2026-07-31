function Get-CredEchoSignInEnrichment {
    <#
    .SYNOPSIS
    Pulls Entra sign-in log entries so successes can be enriched with the fields the unified
    audit log does not carry.

    .DESCRIPTION
    None of authenticationRequirement, conditionalAccessStatus, authenticationProtocol,
    clientAppUsed, riskLevelDuringSignIn, or autonomousSystemNumber exists in the unified audit
    log. The beta endpoint is used because autonomousSystemNumber, authenticationProtocol, and
    authenticationRequirement are documented on the beta signIn resource and not on the v1.0
    resource.

    This is enrichment and never the primary source. Sign-in logs retain only 30 days on Entra
    ID P1 and P2, so anything older than that window cannot be enriched at all, and the absence
    of an enrichment match says nothing about the sign-in.

    One query is issued per account when an account list is supplied, because the account set
    is the triage target list and is small. Filtering server side on userPrincipalName is
    cheaper than pulling every sign-in in the tenant for the window.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory)]
        [datetime] $StartTime,

        [Parameter(Mandatory)]
        [datetime] $EndTime,

        [string[]] $UserPrincipalName = @()
    )

    $select = 'id,createdDateTime,userPrincipalName,ipAddress,appId,appDisplayName,clientAppUsed,conditionalAccessStatus,riskLevelDuringSignIn,authenticationRequirement,authenticationProtocol,autonomousSystemNumber,isInteractive,status,resourceDisplayName'

    $windowFilter = "createdDateTime ge $($StartTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) and createdDateTime le $($EndTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"

    $accountFilter = @($UserPrincipalName | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
    if ($accountFilter.Count -eq 0) { $accountFilter = @($null) }

    foreach ($account in $accountFilter) {
        $filter = $windowFilter
        if ($null -ne $account) {
            $filter = "$($windowFilter) and userPrincipalName eq '$($account.Replace("'", "''"))'"
        }

        $uri = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=$([uri]::EscapeDataString($filter))&`$select=$($select)&`$top=1000"

        while ($uri) {
            $page = $null
            try {
                $page = Invoke-MgGraphRequest -Method GET -Uri $uri
            }
            catch {
                Write-Warning "Sign-in log enrichment failed for $(if ($account) { $account } else { 'the tenant window' }): $($_.Exception.Message). Continuing without enrichment for this query."
                break
            }

            foreach ($signIn in @($page['value'])) {
                $status = $signIn['status']
                $signInErrorCode = $null
                if ($null -ne $status) { $signInErrorCode = $status['errorCode'] }

                $ipAddress = [string] $signIn['ipAddress']

                [pscustomobject]@{
                    SignInId                  = [string] $signIn['id']
                    TimeStamp                 = $(if ($null -ne $signIn['createdDateTime']) { ([datetime] $signIn['createdDateTime']).ToUniversalTime() } else { $null })
                    UserPrincipalName         = $(if ([string]::IsNullOrWhiteSpace([string] $signIn['userPrincipalName'])) { $null } else { ([string] $signIn['userPrincipalName']).ToLowerInvariant() })
                    IpAddress                 = $ipAddress
                    IpPrefix                  = Get-CredEchoIpPrefix -IpAddress $ipAddress
                    ApplicationId             = [string] $signIn['appId']
                    ApplicationDisplayName    = [string] $signIn['appDisplayName']
                    ResourceDisplayName       = [string] $signIn['resourceDisplayName']
                    ClientAppUsed             = [string] $signIn['clientAppUsed']
                    ConditionalAccessStatus   = [string] $signIn['conditionalAccessStatus']
                    RiskLevelDuringSignIn     = [string] $signIn['riskLevelDuringSignIn']
                    AuthenticationRequirement = [string] $signIn['authenticationRequirement']
                    AuthenticationProtocol    = [string] $signIn['authenticationProtocol']
                    AutonomousSystemNumber    = $signIn['autonomousSystemNumber']
                    IsInteractive             = $signIn['isInteractive']
                    SignInErrorCode           = $signInErrorCode
                    IsSuccess                 = ($null -ne $signInErrorCode -and 0 -eq [int] $signInErrorCode)
                }
            }

            $uri = [string] $page['@odata.nextLink']
        }
    }
}
