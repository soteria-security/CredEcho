function Test-CredEchoGraphContext {
    <#
    .SYNOPSIS
    Confirms the caller already holds a Microsoft Graph context carrying a usable scope.

    .DESCRIPTION
    CredEcho never authenticates on the caller's behalf, so this checks the context that
    Connect-MgGraph already established and reports the specific scope that is missing.

    AnyOfScope is satisfied when the context holds at least one of the supplied scopes,
    which is how the audit query permissions work: the Entra scoped variant and the broad
    variant are alternatives rather than a set.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory)]
        [string[]] $AnyOfScope,

        [Parameter(Mandatory)]
        [string] $Capability,

        # Warn and return $false instead of throwing, for the optional phases.
        [switch] $Optional
    )

    $context = Get-MgContext

    if ($null -eq $context) {
        throw 'No Microsoft Graph context was found. Run Connect-MgGraph with the scopes listed in the NOTES section of Get-Help Invoke-CredEchoTriage, then run this command again. CredEcho does not connect on your behalf.'
    }

    $held = @($context.Scopes)

    if (@($AnyOfScope | Where-Object { $held -contains $_ }).Count -gt 0) { return $true }

    $reported = if ($held.Count -gt 0) { $held -join ', ' } else { '(the context reports no scopes)' }
    $message = "The current Microsoft Graph context cannot satisfy $($Capability). Reconnect with at least one of these scopes: $($AnyOfScope -join ', '). Scopes currently held: $($reported). For an app-only context, confirm the corresponding application permission is both granted and consented."

    if ($Optional) {
        Write-Warning $message
        return $false
    }

    throw $message
}
