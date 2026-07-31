<#
.SYNOPSIS
Pulls one unified audit log record and dumps auditData so the accessor pattern can be
confirmed against a real tenant.

.DESCRIPTION
The auditData payload is raw workload JSON with PascalCase property names. The documented
schema is one thing, and how that casing survives deserialization through
Invoke-MgGraphRequest is another. This probe answers the second question against a live
tenant before anyone trusts the flattening layer that sits on top of it.

It reports the .NET type of every node, the exact key casing as returned, whether lookups
are case sensitive, and the shape of ExtendedProperties.

Read only. Requires an existing Graph context holding AuditLogsQuery-Entra.Read.All or
AuditLogsQuery.Read.All.

.EXAMPLE
Connect-MgGraph -Scopes 'AuditLogsQuery-Entra.Read.All'
.\Tools\Probe-AuditDataCasing.ps1

.EXAMPLE
.\Tools\Probe-AuditDataCasing.ps1 -DaysBack 30 -Operation 'UserLoginFailed'
#>
[CmdletBinding()]
param (
    [int] $DaysBack = 7,

    [string] $Operation = 'UserLoginFailed',

    [string] $RecordType = 'azureActiveDirectoryStsLogon',

    [int] $TimeoutSeconds = 900
)

$ErrorActionPreference = 'Stop'
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

if ($null -eq (Get-MgContext)) {
    throw 'Connect-MgGraph first, with AuditLogsQuery-Entra.Read.All or AuditLogsQuery.Read.All.'
}

$end = [System.DateTime]::UtcNow
$start = $end.AddDays(-$DaysBack)

$body = @{
    displayName           = "CredEcho auditData casing probe"
    filterStartDateTime   = $start.ToString('yyyy-MM-ddTHH:mm:ssZ')
    filterEndDateTime     = $end.ToString('yyyy-MM-ddTHH:mm:ssZ')
    recordTypeFilters     = @($RecordType)
    operationFilters      = @($Operation)
}

"Submitting query for $($Operation) / $($RecordType) over the last $($DaysBack) days."
$query = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/security/auditLog/queries' -Body ($body | ConvertTo-Json -Depth 5) -ContentType 'application/json'

$queryId = $query['id']
"Query id: $($queryId)"

$deadline = [System.DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
do {
    Start-Sleep -Seconds 15
    $state = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/security/auditLog/queries/$($queryId)"
    $status = $state['status']
    "  status: $($status)"
} while ($status -in @('notStarted', 'running') -and [System.DateTime]::UtcNow -lt $deadline)

if ($status -ne 'succeeded') {
    throw "Query ended in status '$($status)'. Nothing to probe."
}

$page = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/security/auditLog/queries/$($queryId)/records?`$top=1"
$records = @($page['value'])

if ($records.Count -eq 0) {
    throw "The query succeeded but returned no records. Widen -DaysBack or pick a different -Operation."
}

$record = $records[0]

"`n=== 1. envelope and record types ==="
"envelope : $($page.GetType().FullName)"
"record   : $($record.GetType().FullName)"
"record keys as returned: $((@($record.Keys) | Sort-Object) -join ', ')"

"`n=== 2. auditData node ==="
$auditData = $record['auditData']
"auditData type      : $(if ($null -eq $auditData) { '<null>' } else { $auditData.GetType().FullName })"
"auditData is string : $($auditData -is [string])"

if ($auditData -is [string]) {
    Write-Warning 'auditData came back as a string. The flattening layer must ConvertFrom-Json it first.'
    $auditData = $auditData | ConvertFrom-Json
    "after ConvertFrom-Json: $($auditData.GetType().FullName)"
}

"`n=== 3. auditData key casing exactly as returned ==="
if ($auditData -is [System.Collections.IDictionary]) {
    (@($auditData.Keys) | Sort-Object) -join ', '
}
else {
    (@($auditData.PSObject.Properties.Name) | Sort-Object) -join ', '
}

"`n=== 4. is lookup case sensitive ==="
if ($auditData -is [System.Collections.Hashtable]) {
    $field = [System.Collections.Hashtable].GetField('_keycomparer', 'Instance,NonPublic')
    if ($null -eq $field) { $field = [System.Collections.Hashtable].GetField('_comparer', 'Instance,NonPublic') }
    if ($null -ne $field) {
        $comparer = $field.GetValue($auditData)
        "key comparer: $(if ($null -eq $comparer) { '<null>, meaning case SENSITIVE' } else { $comparer.GetType().FullName })"
    }
}
foreach ($variant in 'ApplicationId', 'applicationId', 'APPLICATIONID') {
    "  [$($variant)] index='$($auditData[$variant])' dot='$($auditData.$variant)'"
}

"`n=== 5. the fields CredEcho reads ==="
foreach ($name in 'ApplicationId', 'ErrorNumber', 'ActorIpAddress', 'ClientIP', 'LogonError', 'ResultStatus', 'RecordType', 'UserId') {
    $value = $auditData[$name]
    "  {0,-16} = {1,-46} type: {2}" -f $name, "'$($value)'", $(if ($null -eq $value) { 'null' } else { $value.GetType().Name })
}

"`n=== 6. ExtendedProperties shape ==="
$extended = $auditData['ExtendedProperties']
"ExtendedProperties type: $(if ($null -eq $extended) { '<null>' } else { $extended.GetType().FullName })"
if ($null -ne $extended) {
    "element type: $(@($extended)[0].GetType().FullName)"
    foreach ($property in @($extended)) {
        "  Name='$($property['Name'])' Value='$($property['Value'])'"
    }
}

"`n=== 7. full auditData as JSON ==="
$auditData | ConvertTo-Json -Depth 10
