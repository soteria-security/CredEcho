function Get-CredEchoAuditRecord {
    <#
    .SYNOPSIS
    Runs a unified audit log query through the Microsoft Graph AuditLogQuery API and emits
    every record it returns.

    .DESCRIPTION
    The unified audit log is the evidence source rather than the Entra sign-in logs, because
    Entra sign-in logs retain only 30 days on Entra ID P1 and P2, which is useless for a
    campaign that ran for months. Microsoft Entra audit records are retained 180 days under
    Purview Audit Standard, and one year by default for users licensed for E5 or the Purview
    Suite. Search-UnifiedAuditLog is not used either: its HighCompleteness switch exists
    precisely because the default query "might have missing search results", the Microsoft
    best practices guidance for the cmdlet states that "the returned data might contain
    duplicate records", and switching SessionCommand values on one SessionId silently caps
    output at 10,000 results.

    The API is asynchronous. A query is submitted, polled until it reaches a terminal state,
    and then read page by page following @odata.nextLink.

    Every query is sliced into ChunkDays windows. A single audit log query over a long range
    returns unreliable volumes, and the Purview audit search documentation caps a search at a
    180 day range. Records are deduplicated by identifier across chunks, because a record
    landing exactly on a chunk boundary would otherwise be counted twice.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param (
        [Parameter(Mandatory)]
        [datetime] $StartTime,

        [Parameter(Mandatory)]
        [datetime] $EndTime,

        [string[]] $RecordTypeFilter = @(),

        [string[]] $OperationFilter = @(),

        [string[]] $UserPrincipalNameFilter = @(),

        [string[]] $IpAddressFilter = @(),

        [int] $ChunkDays = 30,

        [int] $PollSeconds = 20,

        [int] $QueryTimeoutMinutes = 120,

        [string] $Label = 'CredEcho'
    )

    $graphRoot = 'https://graph.microsoft.com/v1.0/security/auditLog/queries'
    $seenRecordId = New-Object 'System.Collections.Generic.HashSet[string]'

    $windowStart = $StartTime.ToUniversalTime()
    $windowEnd = $EndTime.ToUniversalTime()
    $chunkIndex = 0
    $chunkTotal = [System.Math]::Max(1, [System.Math]::Ceiling(($windowEnd - $windowStart).TotalDays / $ChunkDays))

    $cursor = $windowStart
    while ($cursor -lt $windowEnd) {
        $chunkIndex++
        $chunkEnd = $cursor.AddDays($ChunkDays)
        if ($chunkEnd -gt $windowEnd) { $chunkEnd = $windowEnd }

        $body = @{
            displayName         = "$($Label) $($cursor.ToString('yyyyMMddHHmmss'))"
            filterStartDateTime = $cursor.ToString('yyyy-MM-ddTHH:mm:ssZ')
            filterEndDateTime   = $chunkEnd.ToString('yyyy-MM-ddTHH:mm:ssZ')
        }

        # recordTypeFilters is documented as taking camelCase enum member names, while the
        # live v1.0 metadata declares them PascalCase. The values are passed through exactly
        # as supplied so the caller can switch casing without a code change if the service
        # rejects one form. serviceFilter is deliberately never sent: the reference documents
        # it as a singular string and the live metadata declares serviceFilters as a string
        # collection, and record type plus operation filters make it unnecessary.
        if ($RecordTypeFilter.Count -gt 0) { $body['recordTypeFilters'] = @($RecordTypeFilter) }
        if ($OperationFilter.Count -gt 0) { $body['operationFilters'] = @($OperationFilter) }
        if ($UserPrincipalNameFilter.Count -gt 0) { $body['userPrincipalNameFilters'] = @($UserPrincipalNameFilter) }
        if ($IpAddressFilter.Count -gt 0) { $body['ipAddressFilters'] = @($IpAddressFilter) }

        Write-Verbose "Submitting audit log query $($chunkIndex) of $($chunkTotal): $($body['filterStartDateTime']) to $($body['filterEndDateTime'])."
        Write-Progress -Activity 'CredEcho audit log query' -Status "Chunk $($chunkIndex) of $($chunkTotal), submitting" -PercentComplete (($chunkIndex - 1) / $chunkTotal * 100)

        $query = Invoke-MgGraphRequest -Method POST -Uri $graphRoot -Body ($body | ConvertTo-Json -Depth 5) -ContentType 'application/json'
        $queryId = [string] $query['id']

        $deadline = [datetime]::UtcNow.AddMinutes($QueryTimeoutMinutes)
        $status = [string] $query['status']
        while ($status -in @('notStarted', 'running') -and [datetime]::UtcNow -lt $deadline) {
            Start-Sleep -Seconds $PollSeconds
            $state = Invoke-MgGraphRequest -Method GET -Uri "$($graphRoot)/$($queryId)"
            $status = [string] $state['status']
            Write-Progress -Activity 'CredEcho audit log query' -Status "Chunk $($chunkIndex) of $($chunkTotal), status $($status)" -PercentComplete (($chunkIndex - 1) / $chunkTotal * 100)
        }

        if ($status -ne 'succeeded') {
            Write-Warning "Audit log query $($queryId) covering $($body['filterStartDateTime']) to $($body['filterEndDateTime']) ended in status '$($status)'. Results for this window are absent, so treat the output as partial."
            $cursor = $chunkEnd
            continue
        }

        $chunkCount = 0
        $uri = "$($graphRoot)/$($queryId)/records"
        while ($uri) {
            $page = Invoke-MgGraphRequest -Method GET -Uri $uri
            foreach ($record in @($page['value'])) {
                if ($seenRecordId.Add([string] $record['id'])) {
                    $chunkCount++
                    $record
                }
            }
            $uri = [string] $page['@odata.nextLink']
        }

        Write-Verbose "Chunk $($chunkIndex) returned $($chunkCount) new records."
        $cursor = $chunkEnd
    }

    Write-Progress -Activity 'CredEcho audit log query' -Completed
}
