function Export-CredEchoResult {
    <#
    .SYNOPSIS
    Writes the CredEcho artifacts to a directory.

    .DESCRIPTION
    Four comma separated files and one JSON summary. Every file is written even when it has no
    rows, because an empty artifact and a missing artifact mean different things to whoever
    reads the output later: the first says the phase ran and found nothing, and the second says
    the phase did not run.

    Array valued properties are joined with a pipe for the delimited files, since the field
    delimiter itself is configurable and a signal list must survive whatever delimiter is
    chosen. The JSON summary keeps the arrays intact.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory)]
        [string] $OutputDirectory,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [psobject[]] $AccountVerdict,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [psobject[]] $ValidationEvent,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [psobject[]] $FlaggedSignIn,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [psobject[]] $FollowOnAction,

        [Parameter(Mandatory)]
        [psobject] $Summary,

        [string] $Delimiter = ';'
    )

    if (-not (Test-Path -LiteralPath $OutputDirectory)) {
        New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
    }

    $verdictRank = @{ 'Confirmed' = 0; 'Probable' = 1; 'Possible' = 2; 'NoIndicators' = 3 }
    $sortedVerdict = @($AccountVerdict | Sort-Object -Property @{ Expression = { $verdictRank[[string] $_.Verdict] } }, @{ Expression = { $_.UserPrincipalName } })

    $artifact = @(
        [pscustomobject]@{
            FileName = 'AccountVerdicts.csv'
            Row      = $sortedVerdict
            Column   = @('UserPrincipalName', 'Verdict', 'ConfirmedSignalCount', 'ProbableSignalCount', 'PossibleSignalCount', 'DistinctSignal', 'FirstValidation', 'LastValidation', 'ValidationErrorCode', 'ValidationSourceAddress', 'ValidationTimestampAssumed', 'PostValidationSignInCount', 'FlaggedSignInCount', 'FollowOnActionCount', 'BaselineAssessed', 'BaselineSignInCount', 'NoveltyAssessment')
        }
        [pscustomobject]@{
            FileName = 'ValidationEvents.csv'
            Row      = @($ValidationEvent)
            Column   = @('RecordId', 'TimeStamp', 'Operation', 'RecordType', 'UserPrincipalName', 'ApplicationId', 'ErrorCode', 'ErrorClass', 'ErrorName', 'ErrorConfidence', 'LogonError', 'IpAddress', 'IpPrefix', 'UserAgent', 'RequestType', 'ResultStatusDetail', 'IsSuccess')
        }
        [pscustomobject]@{
            FileName = 'FlaggedSignIns.csv'
            Row      = @($FlaggedSignIn)
            Column   = @('UserPrincipalName', 'TimeStamp', 'Tier', 'Signal', 'IpAddress', 'IpPrefix', 'UserAgent', 'ApplicationId', 'RecordId', 'ClientAppUsed', 'ConditionalAccessStatus', 'AuthenticationRequirement', 'AuthenticationProtocol', 'RiskLevelDuringSignIn', 'AutonomousSystemNumber', 'Enriched')
        }
        [pscustomobject]@{
            FileName = 'FollowOnActions.csv'
            Row      = @($FollowOnAction)
            Column   = @('UserPrincipalName', 'TimeStamp', 'Operation', 'Category', 'RecordType', 'IpAddress', 'TargetObject', 'RecordId', 'IsTargetAccount')
        }
    )

    $written = New-Object 'System.Collections.Generic.List[string]'

    foreach ($item in $artifact) {
        $path = Join-Path -Path $OutputDirectory -ChildPath $item.FileName

        if ($item.Row.Count -eq 0) {
            Set-Content -LiteralPath $path -Value (($item.Column | ForEach-Object { """$($_)""" }) -join $Delimiter) -Encoding UTF8
        }
        else {
            $flattened = foreach ($row in $item.Row) {
                $ordered = [ordered]@{}
                foreach ($property in $row.PSObject.Properties) {
                    $value = $property.Value
                    if ($value -is [System.Collections.IEnumerable] -and $value -isnot [string]) {
                        $value = (@($value) | ForEach-Object { [string] $_ }) -join ' | '
                    }
                    $ordered[$property.Name] = $value
                }
                [pscustomobject] $ordered
            }
            $flattened | Export-Csv -LiteralPath $path -NoTypeInformation -Delimiter $Delimiter -Encoding UTF8
        }

        $written.Add($path)
        Write-Verbose "Wrote $($item.Row.Count) rows to $($path)."
    }

    $jsonPath = Join-Path -Path $OutputDirectory -ChildPath 'TriageResults.json'
    $payload = [pscustomobject]@{
        Summary         = $Summary
        AccountVerdict  = $sortedVerdict
        ValidationEvent = @($ValidationEvent)
        FlaggedSignIn   = @($FlaggedSignIn)
        FollowOnAction  = @($FollowOnAction)
    }
    $payload | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
    $written.Add($jsonPath)

    [pscustomobject]@{
        OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
        File            = $written.ToArray()
    }
}
