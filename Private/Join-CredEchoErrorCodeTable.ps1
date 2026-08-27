function Join-CredEchoErrorCodeTable {
    <#
    .SYNOPSIS
    Merges an addition into an error code table and returns the result.

    .DESCRIPTION
    Every error code table Invoke-CredEchoTriage exposes follows the same two-parameter shape.
    The base parameter replaces the built-in table outright, and the Additional parameter merges
    into whichever table is in force, so the two compose: a caller can hand over an entirely
    different table, extend the built-in one, or both.

    The addition is applied second and so wins on a shared key, which lets a caller correct one
    entry without restating the rest of the table.

    Keys are cast to string because an analyst writing a table inline will reach for a bare
    number, and the error code read off an audit record is always a string. Without the cast an
    entry keyed 50072 would never match the record that carries '50072'.

    Either side may be null, which is what an explicitly passed $null binds to on a hashtable
    parameter. A null side contributes nothing rather than throwing, so a caller building a table
    conditionally does not have to guard the call.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param (
        [AllowNull()]
        [System.Collections.IDictionary] $Base,

        [AllowNull()]
        [System.Collections.IDictionary] $Addition
    )

    $merged = @{}
    foreach ($table in @($Base, $Addition)) {
        if ($null -eq $table) { continue }
        foreach ($pair in $table.GetEnumerator()) { $merged[[string] $pair.Key] = $pair.Value }
    }
    $merged
}
