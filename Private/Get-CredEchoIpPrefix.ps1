function Get-CredEchoIpPrefix {
    <#
    .SYNOPSIS
    Reduces an address to a coarse network prefix.

    .DESCRIPTION
    Returns an IPv4 /24 or an IPv6 /48 for the supplied address, or $null when the
    input cannot be parsed.

    This is a coarse proxy and nothing better. The unified audit log carries no
    autonomous system number and no geolocation, so there is no way to ask whether
    two addresses belong to the same hosting provider. A shared /24 or /48 means the
    two addresses sit in the same allocation, which is suggestive and not conclusive:
    a large cloud provider or a carrier grade NAT range will place unrelated traffic
    in the same prefix. Every prefix match is therefore scored one tier below an
    exact address match.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Position = 0)]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $IpAddress
    )

    if ([string]::IsNullOrWhiteSpace($IpAddress)) { return $null }

    $candidate = $IpAddress.Trim()

    # ClientIp and ActorIpAddress arrive in three shapes across workloads: a bare
    # address, an address with a source port, and a bracketed IPv6 address with a port.
    if ($candidate.StartsWith('[')) {
        $close = $candidate.IndexOf(']')
        if ($close -gt 1) { $candidate = $candidate.Substring(1, $close - 1) }
    }
    elseif (([regex]::Matches($candidate, ':')).Count -eq 1) {
        # A single colon is always IPv4 with a port. Every IPv6 form carries at least two.
        $candidate = $candidate.Split(':')[0]
    }

    $parsed = [System.Net.IPAddress]::None
    if (-not [System.Net.IPAddress]::TryParse($candidate, [ref] $parsed)) { return $null }

    if ($parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        $octet = $parsed.GetAddressBytes()
        return '{0}.{1}.{2}.0/24' -f $octet[0], $octet[1], $octet[2]
    }

    if ($parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
        # Treat an IPv4 mapped address as the IPv4 address it represents, otherwise every
        # one of them collapses into the same ::ffff:0:0/48 prefix.
        if ($parsed.IsIPv4MappedToIPv6) {
            $octet = $parsed.MapToIPv4().GetAddressBytes()
            return '{0}.{1}.{2}.0/24' -f $octet[0], $octet[1], $octet[2]
        }

        $masked = New-Object 'byte[]' 16
        [System.Array]::Copy($parsed.GetAddressBytes(), $masked, 6)
        return "$(([System.Net.IPAddress] $masked).IPAddressToString)/48"
    }

    return $null
}
