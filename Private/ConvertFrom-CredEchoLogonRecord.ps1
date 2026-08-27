function ConvertFrom-CredEchoLogonRecord {
    <#
    .SYNOPSIS
    Flattens a raw auditLogRecord into the fields CredEcho scores, and classifies its error
    code.

    .DESCRIPTION
    The accessor pattern below was confirmed by probing the deserializer that
    Invoke-MgGraphRequest uses rather than by reading the schema alone. Findings:

      Invoke-MgGraphRequest defaults to HashTable output, and the SDK builds every node,
      including the nested auditData object, as a System.Collections.Hashtable keyed with
      System.OrdinalIgnoreCaseComparer. auditData arrives as a nested hashtable and not as a
      JSON string, because the metadata declares defaultAuditData as an open type. Key casing
      survives verbatim, so PascalCase names stay PascalCase, and because the comparer ignores
      case, both index and dot access succeed at any casing. PascalCase is written here to
      match the documented schema, and it would still resolve if the service changed casing.

    Two fields are read under two names each, because the field that appears in real records
    is not the field the schema documents:

      ErrorNumber is present in live STS logon records and is undocumented. ErrorCode is what
      the Office 365 Management Activity API schema documents for the Azure Active Directory
      Secure Token Service Logon schema. Both are read, undocumented name first.

      ActorIpAddress is present in live records and is undocumented. ClientIP is documented,
      and the Common schema warns that for Microsoft Entra ID related events the IP address is
      not logged and the value of the ClientIP property is null. The envelope clientIp is the
      last fallback.

    ResultStatus is deliberately ignored. The schema states that for Entra STS logon events a
    ResultStatus of Succeeded means only that the HTTP operation succeeded, and directs the
    reader to the logon error instead. Operation plus error code is the reliable pair.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '',
        Justification = 'The rule matches the parameter names UsernameOracleError and PostPasswordError on the substrings Username and Password. Both carry error code lookup tables. Neither accepts a credential, and this module never handles one.')]
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [System.Collections.IDictionary] $Record,

        [hashtable] $UsernameOracleError = $script:CredEchoUsernameOracleError,

        [hashtable] $PostPasswordError = $script:CredEchoPostPasswordError,

        [hashtable] $ErrorConfidence = $script:CredEchoErrorConfidence
    )

    process {
        $auditData = $Record['auditData']
        if ($null -eq $auditData) { return }

        $extended = @{}
        foreach ($pair in @($auditData['ExtendedProperties'])) {
            if ($null -ne $pair) { $extended[[string] $pair['Name']] = [string] $pair['Value'] }
        }

        $errorCode = [string] $auditData['ErrorNumber']
        if ([string]::IsNullOrWhiteSpace($errorCode)) { $errorCode = [string] $auditData['ErrorCode'] }
        $errorCode = $errorCode.Trim()

        $ipAddress = @(
            [string] $auditData['ActorIpAddress']
            [string] $auditData['ClientIP']
            [string] $Record['clientIp']
        ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1

        $userPrincipalName = @(
            [string] $Record['userPrincipalName']
            [string] $auditData['UserId']
            [string] $Record['userId']
        ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and $_ -ne 'Unknown' } | Select-Object -First 1

        $operation = [string] $Record['operation']
        if ([string]::IsNullOrWhiteSpace($operation)) { $operation = [string] $auditData['Operation'] }

        $isSuccess = $operation -eq 'UserLoggedIn'

        $errorClass = 'Other'
        if ($PostPasswordError.ContainsKey($errorCode)) { $errorClass = 'PostPassword' }
        elseif ($UsernameOracleError.ContainsKey($errorCode)) { $errorClass = 'UsernameOracle' }
        elseif ($isSuccess -or $errorCode -eq '0') { $errorClass = 'Success' }

        $errorName = $PostPasswordError[$errorCode]
        if ($null -eq $errorName) { $errorName = $UsernameOracleError[$errorCode] }

        # A post-password code with no entry in the rating table is reported as Unrated rather
        # than as an empty value. Every code CredEcho ships is rated, so this only fires for a
        # code an analyst added through AdditionalPostPasswordErrorCode without supplying a
        # rating for it. An empty value in that position reads as a rating that failed to
        # render; Unrated says the classification is the analyst's and CredEcho does not vouch
        # for it. Codes outside the post-password class stay blank, because the rating describes
        # how far a post-password classification can be defended and means nothing elsewhere.
        $confidence = $ErrorConfidence[$errorCode]
        if ($null -eq $confidence -and $errorClass -eq 'PostPassword') { $confidence = 'Unrated' }

        $timestamp = $null
        if ($null -ne $Record['createdDateTime']) {
            $timestamp = ([datetime] $Record['createdDateTime']).ToUniversalTime()
        }
        elseif ($null -ne $auditData['CreationTime']) {
            $timestamp = ([datetime] $auditData['CreationTime']).ToUniversalTime()
        }

        $userAgent = $extended['UserAgent']
        if ([string]::IsNullOrWhiteSpace($userAgent)) { $userAgent = [string] $auditData['Client'] }

        $account = $null
        if (-not [string]::IsNullOrWhiteSpace($userPrincipalName)) { $account = $userPrincipalName.ToLowerInvariant() }

        [pscustomobject]@{
            RecordId           = [string] $Record['id']
            TimeStamp          = $timestamp
            Operation          = $operation
            RecordType         = [string] $Record['auditLogRecordType']
            UserPrincipalName  = $account
            ApplicationId      = [string] $auditData['ApplicationId']
            ErrorCode          = $errorCode
            ErrorClass         = $errorClass
            ErrorName          = $errorName
            ErrorConfidence    = $confidence
            LogonError         = [string] $auditData['LogonError']
            IpAddress          = $ipAddress
            IpPrefix           = Get-CredEchoIpPrefix -IpAddress $ipAddress
            UserAgent          = $userAgent
            RequestType        = $extended['RequestType']
            ResultStatusDetail = $extended['ResultStatusDetail']
            IsSuccess          = $isSuccess
        }
    }
}
