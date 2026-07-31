function New-CredEchoReport {
    <#
    .SYNOPSIS
    Renders the branded HTML report from a saved TriageResults.json file.

    .DESCRIPTION
    Re-renders a report from collection output that already exists on disk, so an analyst can
    change the presentation, share a fresh copy, or produce a report on a workstation that has no
    connection to the tenant, without running the collection again. No Microsoft Graph context is
    required and no query is issued.

    The generated file is self-contained. It opens from a file URI with networking disabled, and
    it carries no external stylesheet, no web font, no content delivery network script, and no
    image file.

    CredEcho is read only throughout. This command reads one file and writes one file.

    .PARAMETER InputPath
    Path to a TriageResults.json file produced by Invoke-CredEchoTriage.

    .PARAMETER OutputPath
    Path of the HTML file to write. Defaults to TriageReport.html in the same directory as
    InputPath.

    .PARAMETER PassThru
    Emits the resolved path of the generated file.

    .EXAMPLE
    New-CredEchoReport -InputPath 'C:\Cases\1042\TriageResults.json'

    Writes C:\Cases\1042\TriageReport.html next to the source data. This is the normal re-render
    path after a collection has already run.

    .EXAMPLE
    New-CredEchoReport -InputPath 'C:\Cases\1042\TriageResults.json' -OutputPath 'C:\Cases\1042\Deliverables\AccountTriage.html' -PassThru

    Writes the report to a separate deliverables directory, creating it when it does not exist,
    and returns the resolved path.

    .EXAMPLE
    Get-ChildItem 'C:\Cases' -Filter 'TriageResults.json' -Recurse | ForEach-Object { New-CredEchoReport -InputPath $_.FullName }

    Re-renders every saved result under a case directory, which is useful after a change to the
    report itself.

    .NOTES
    No Microsoft Graph scopes are required, because this command does not contact the tenant.

    The report presents four verdict tiers in a fixed ladder: Confirmed, Probable, Possible, and
    NoIndicators. Possible is an unresolved verdict requiring analyst triage rather than a lesser
    severity claim.

    Requires PowerShell 5.1 or later.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param (
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('FullName')]
        [string] $InputPath,

        [Parameter(Position = 1)]
        [string] $OutputPath,

        [switch] $PassThru
    )

    process {
        if (-not (Test-Path -LiteralPath $InputPath -PathType Leaf)) {
            throw "No file was found at $($InputPath). Supply the path to a TriageResults.json file written by Invoke-CredEchoTriage."
        }

        $resolved = (Resolve-Path -LiteralPath $InputPath).Path
        $triageResult = Get-Content -LiteralPath $resolved -Raw | ConvertFrom-Json

        if ($null -eq $triageResult.Summary) {
            throw "$($resolved) does not carry a Summary object, so it is not a TriageResults.json file produced by Invoke-CredEchoTriage."
        }

        $target = $OutputPath
        if ([string]::IsNullOrWhiteSpace($target)) {
            $target = Join-Path -Path (Split-Path -Path $resolved -Parent) -ChildPath 'TriageReport.html'
        }

        if (-not $PSCmdlet.ShouldProcess($target, 'Write the CredEcho HTML report')) { return }

        $written = New-CredEchoHtmlReport -TriageResult $triageResult -Path $target
        Write-Verbose "Rendered $(@($triageResult.AccountVerdict).Count) accounts to $($written)."

        if ($PassThru) { $written }
    }
}
