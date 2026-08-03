#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $manifest = Join-Path -Path (Split-Path -Parent $PSScriptRoot) -ChildPath 'CredEcho.psd1'
    Import-Module -Name $manifest -Force -ErrorAction Stop

    $script:CredEchoTestApp = @{
        Registered   = 'aaaa1111-1111-1111-1111-111111111111'
        Corroborated = 'bbbb2222-2222-2222-2222-222222222222'
        Allowed      = 'cccc3333-3333-3333-3333-333333333333'
        Attacker     = 'ffff9999-9999-9999-9999-999999999999'
    }

    # Records are built as case-insensitive hashtables with a nested auditData hashtable, which
    # is exactly what Invoke-MgGraphRequest produces. Confirmed by probing the deserializer the
    # SDK uses rather than assumed from the schema.
    function Get-CredEchoTestRecord {
        param (
            [string] $Id,
            [string] $Time,
            [string] $Operation,
            [string] $Upn,
            [string] $AppId,
            [string] $ErrorNumber,
            [string] $Ip,
            [string] $UserAgent = 'Mozilla/5.0 (Windows NT 10.0)'
        )

        $auditData = @{
            ApplicationId      = $AppId
            ErrorNumber        = $ErrorNumber
            ActorIpAddress     = $Ip
            UserId             = $Upn
            ResultStatus       = 'Succeeded'
            ExtendedProperties = @(
                @{ Name = 'UserAgent'; Value = $UserAgent }
                @{ Name = 'RequestType'; Value = 'OAuth2:Token' }
            )
        }

        @{
            id                 = $Id
            createdDateTime    = $Time
            auditLogRecordType = 'azureActiveDirectoryStsLogon'
            operation          = $Operation
            userPrincipalName  = $Upn
            clientIp           = $null
            auditData          = $auditData
        }
    }

    $a = $script:CredEchoTestApp

    # AttackerProbe/1.0 is a client string the legitimate owners never use, so the only accounts
    # that earn a user agent signal are the two meant to.
    $failedSpec = @(
        @{ Id = 'f1'; Time = '2026-06-10T02:00:00Z'; Upn = 'jdoe@contoso.com'; AppId = $a.Attacker; ErrorNumber = '700016'; Ip = '185.220.101.44'; UserAgent = 'python-requests/2.32.3' }
        @{ Id = 'f2'; Time = '2026-06-10T02:01:00Z'; Upn = 'probeonly@contoso.com'; AppId = $a.Attacker; ErrorNumber = '50126'; Ip = '185.220.101.44'; UserAgent = 'python-requests/2.32.3' }
        @{ Id = 'f3'; Time = '2026-06-10T02:02:00Z'; Upn = 'legitapp@contoso.com'; AppId = $a.Registered; ErrorNumber = '700016'; Ip = '203.0.113.9'; UserAgent = 'AttackerProbe/1.0' }
        @{ Id = 'f4'; Time = '2026-06-10T02:03:00Z'; Upn = 'corrob@contoso.com'; AppId = $a.Corroborated; ErrorNumber = '700016'; Ip = '203.0.113.10'; UserAgent = 'AttackerProbe/1.0' }
        @{ Id = 'f5'; Time = '2026-06-10T02:04:00Z'; Upn = 'allowed@contoso.com'; AppId = $a.Allowed; ErrorNumber = '700016'; Ip = '203.0.113.11'; UserAgent = 'AttackerProbe/1.0' }
        @{ Id = 'f6'; Time = '2026-06-10T02:05:00Z'; Upn = 'nobase@contoso.com'; AppId = $a.Attacker; ErrorNumber = '700016'; Ip = '203.0.113.5'; UserAgent = 'AttackerProbe/1.0' }
        @{ Id = 'f7'; Time = '2026-06-10T02:06:00Z'; Upn = 'prob@contoso.com'; AppId = $a.Attacker; ErrorNumber = '700016'; Ip = '198.51.100.10'; UserAgent = 'AttackerProbe/1.0' }
        @{ Id = 'f8'; Time = '2026-06-10T02:07:00Z'; Upn = 'poss@contoso.com'; AppId = $a.Attacker; ErrorNumber = '700016'; Ip = '192.0.2.50'; UserAgent = 'AttackerProbe/1.0' }
        @{ Id = 'f9'; Time = '2026-06-10T02:08:00Z'; Upn = 'clean@contoso.com'; AppId = $a.Attacker; ErrorNumber = '700016'; Ip = '192.0.2.60'; UserAgent = 'AttackerProbe/1.0' }
        @{ Id = 'f10'; Time = '2026-06-10T02:09:00Z'; Upn = 'noappid@contoso.com'; AppId = ''; ErrorNumber = '700016'; Ip = '192.0.2.70'; UserAgent = 'AttackerProbe/1.0' }
        @{ Id = 'f11'; Time = '2026-06-10T02:10:00Z'; Upn = 'poss2@contoso.com'; AppId = $a.Attacker; ErrorNumber = '700016'; Ip = '192.0.2.80'; UserAgent = 'AttackerProbe/1.0' }
    )

    $successSpec = @(
        @{ Id = 's1'; Time = '2026-05-01T09:00:00Z'; Upn = 'jdoe@contoso.com'; AppId = $a.Registered; ErrorNumber = '0'; Ip = '10.1.1.5' }
        @{ Id = 's2'; Time = '2026-05-02T09:00:00Z'; Upn = 'prob@contoso.com'; AppId = $a.Registered; ErrorNumber = '0'; Ip = '10.2.2.9' }
        @{ Id = 's3'; Time = '2026-05-03T09:00:00Z'; Upn = 'poss@contoso.com'; AppId = $a.Registered; ErrorNumber = '0'; Ip = '10.3.3.3' }
        @{ Id = 's4'; Time = '2026-05-04T09:00:00Z'; Upn = 'clean@contoso.com'; AppId = $a.Registered; ErrorNumber = '0'; Ip = '10.4.4.4' }
        @{ Id = 's5'; Time = '2026-05-05T09:00:00Z'; Upn = 'corrob@contoso.com'; AppId = $a.Corroborated; ErrorNumber = '0'; Ip = '10.5.5.5' }
        @{ Id = 's6'; Time = '2026-05-06T09:00:00Z'; Upn = 'legitapp@contoso.com'; AppId = $a.Corroborated; ErrorNumber = '0'; Ip = '10.6.6.6' }
        @{ Id = 's7'; Time = '2026-05-07T09:00:00Z'; Upn = 'allowed@contoso.com'; AppId = $a.Corroborated; ErrorNumber = '0'; Ip = '10.7.7.7' }
        @{ Id = 's8'; Time = '2026-05-08T09:00:00Z'; Upn = 'noappid@contoso.com'; AppId = $a.Registered; ErrorNumber = '0'; Ip = '10.8.8.8' }
        @{ Id = 's14'; Time = '2026-05-09T09:00:00Z'; Upn = 'poss2@contoso.com'; AppId = $a.Registered; ErrorNumber = '0'; Ip = '10.9.9.9' }
        @{ Id = 's9'; Time = '2026-06-15T09:00:00Z'; Upn = 'jdoe@contoso.com'; AppId = $a.Attacker; ErrorNumber = '0'; Ip = '185.220.101.44'; UserAgent = 'python-requests/2.32.3' }
        @{ Id = 's10'; Time = '2026-06-15T09:00:00Z'; Upn = 'prob@contoso.com'; AppId = $a.Registered; ErrorNumber = '0'; Ip = '198.51.100.77' }
        @{ Id = 's11'; Time = '2026-06-15T09:00:00Z'; Upn = 'poss@contoso.com'; AppId = $a.Registered; ErrorNumber = '0'; Ip = '172.16.9.9' }
        @{ Id = 's12'; Time = '2026-06-15T09:00:00Z'; Upn = 'clean@contoso.com'; AppId = $a.Registered; ErrorNumber = '0'; Ip = '10.4.4.4' }
        @{ Id = 's13'; Time = '2026-06-15T09:00:00Z'; Upn = 'nobase@contoso.com'; AppId = $a.Registered; ErrorNumber = '0'; Ip = '8.8.8.8' }
        @{ Id = 's15'; Time = '2026-06-15T09:00:00Z'; Upn = 'poss2@contoso.com'; AppId = $a.Registered; ErrorNumber = '0'; Ip = '172.17.9.9' }
    )

    $script:CredEchoTestFailed = @($failedSpec | ForEach-Object { $spec = $_; Get-CredEchoTestRecord @spec -Operation 'UserLoginFailed' })
    $script:CredEchoTestSuccess = @($successSpec | ForEach-Object { $spec = $_; Get-CredEchoTestRecord @spec -Operation 'UserLoggedIn' })

    $script:CredEchoTestFollowOn = @(
        @{
            id                 = 'fo1'
            createdDateTime    = '2026-06-16T10:00:00Z'
            auditLogRecordType = 'azureActiveDirectory'
            operation          = 'Add strong authentication method'
            userPrincipalName  = 'poss@contoso.com'
            objectId           = 'poss@contoso.com'
            clientIp           = '192.0.2.50'
            auditData          = @{ UserId = 'poss@contoso.com'; ActorIpAddress = '192.0.2.50' }
        }
    )

    $script:CredEchoTestQueryMap = @{}
    $script:CredEchoTestQuerySeq = 0
}

Describe 'Get-CredEchoIpPrefix' {

    Context 'IPv4' {
        It 'reduces <Address> to <Expected>' -ForEach @(
            @{ Address = '185.220.101.44'; Expected = '185.220.101.0/24' }
            @{ Address = '10.0.0.255'; Expected = '10.0.0.0/24' }
            @{ Address = '8.8.8.8'; Expected = '8.8.8.0/24' }
            @{ Address = '192.0.2.1'; Expected = '192.0.2.0/24' }
        ) {
            InModuleScope CredEcho -Parameters @{ Address = $Address; Expected = $Expected } {
                Get-CredEchoIpPrefix -IpAddress $Address | Should -Be $Expected
            }
        }

        It 'strips a source port from <Address>' -ForEach @(
            @{ Address = '8.8.8.8:443'; Expected = '8.8.8.0/24' }
            @{ Address = '203.0.113.77:52918'; Expected = '203.0.113.0/24' }
        ) {
            InModuleScope CredEcho -Parameters @{ Address = $Address; Expected = $Expected } {
                Get-CredEchoIpPrefix -IpAddress $Address | Should -Be $Expected
            }
        }
    }

    Context 'IPv6' {
        It 'reduces <Address> to <Expected>' -ForEach @(
            @{ Address = '2001:db8:1234:5678::1'; Expected = '2001:db8:1234::/48' }
            @{ Address = 'fe80::1'; Expected = 'fe80::/48' }
            @{ Address = '2606:4700:4700::1111'; Expected = '2606:4700:4700::/48' }
        ) {
            InModuleScope CredEcho -Parameters @{ Address = $Address; Expected = $Expected } {
                Get-CredEchoIpPrefix -IpAddress $Address | Should -Be $Expected
            }
        }

        It 'strips brackets and a port from a bracketed address' {
            InModuleScope CredEcho {
                Get-CredEchoIpPrefix -IpAddress '[2001:db8:1234:5678::9]:443' | Should -Be '2001:db8:1234::/48'
            }
        }

        It 'treats an IPv4 mapped address as IPv4 so mapped addresses do not collapse into one prefix' {
            InModuleScope CredEcho {
                Get-CredEchoIpPrefix -IpAddress '::ffff:192.168.1.10' | Should -Be '192.168.1.0/24'
                Get-CredEchoIpPrefix -IpAddress '::ffff:10.20.30.40' | Should -Be '10.20.30.0/24'
            }
        }

        It 'distinguishes two addresses that differ inside the first 48 bits' {
            InModuleScope CredEcho {
                $left = Get-CredEchoIpPrefix -IpAddress '2001:db8:1111::1'
                $right = Get-CredEchoIpPrefix -IpAddress '2001:db8:2222::1'
                $left | Should -Not -Be $right
            }
        }

        It 'treats two addresses that differ only beyond the first 48 bits as one prefix' {
            InModuleScope CredEcho {
                $left = Get-CredEchoIpPrefix -IpAddress '2001:db8:1111:aaaa::1'
                $right = Get-CredEchoIpPrefix -IpAddress '2001:db8:1111:bbbb::2'
                $left | Should -Be $right
            }
        }
    }

    Context 'Unusable input' {
        It 'returns null for <Label>' -ForEach @(
            @{ Label = 'empty string'; Address = '' }
            @{ Label = 'whitespace'; Address = '   ' }
            @{ Label = 'null'; Address = $null }
            @{ Label = 'a hostname'; Address = 'not-an-ip' }
            @{ Label = 'too many octets'; Address = '1.2.3.4.5' }
        ) {
            InModuleScope CredEcho -Parameters @{ Address = $Address } {
                Get-CredEchoIpPrefix -IpAddress $Address | Should -BeNullOrEmpty
            }
        }
    }
}

Describe 'ConvertFrom-CredEchoLogonRecord error code classification' {

    It 'classifies post-password code <Code> as PostPassword' -ForEach @(
        @{ Code = '700016' }
        @{ Code = '50076' }
        @{ Code = '50079' }
        @{ Code = '50158' }
        @{ Code = '53003' }
        @{ Code = '50055' }
    ) {
        InModuleScope CredEcho -Parameters @{ Code = $Code } {
            $record = @{
                id                = 'x'
                createdDateTime   = '2026-06-10T02:00:00Z'
                operation         = 'UserLoginFailed'
                userPrincipalName = 'u@contoso.com'
                auditData         = @{ ApplicationId = 'app'; ErrorNumber = $Code; ActorIpAddress = '1.2.3.4' }
            }
            (ConvertFrom-CredEchoLogonRecord -Record $record).ErrorClass | Should -Be 'PostPassword'
        }
    }

    It 'classifies username oracle code <Code> as UsernameOracle' -ForEach @(
        @{ Code = '50126' }
        @{ Code = '50034' }
        @{ Code = '50053' }
    ) {
        InModuleScope CredEcho -Parameters @{ Code = $Code } {
            $record = @{
                id                = 'x'
                createdDateTime   = '2026-06-10T02:00:00Z'
                operation         = 'UserLoginFailed'
                userPrincipalName = 'u@contoso.com'
                auditData         = @{ ApplicationId = 'app'; ErrorNumber = $Code; ActorIpAddress = '1.2.3.4' }
            }
            (ConvertFrom-CredEchoLogonRecord -Record $record).ErrorClass | Should -Be 'UsernameOracle'
        }
    }

    It 'records the confidence of each classification so weak leads stay visible' {
        InModuleScope CredEcho {
            $build = {
                param ($Code)
                @{
                    id                = 'x'
                    createdDateTime   = '2026-06-10T02:00:00Z'
                    operation         = 'UserLoginFailed'
                    userPrincipalName = 'u@contoso.com'
                    auditData         = @{ ApplicationId = 'app'; ErrorNumber = $Code; ActorIpAddress = '1.2.3.4' }
                }
            }
            (ConvertFrom-CredEchoLogonRecord -Record (& $build '53003')).ErrorConfidence | Should -Be 'Documented'
            (ConvertFrom-CredEchoLogonRecord -Record (& $build '700016')).ErrorConfidence | Should -Be 'Observed'
            (ConvertFrom-CredEchoLogonRecord -Record (& $build '50055')).ErrorConfidence | Should -Be 'Ambiguous'
        }
    }

    It 'reads the undocumented ErrorNumber field in preference to the documented ErrorCode field' {
        InModuleScope CredEcho {
            $record = @{
                id                = 'x'
                createdDateTime   = '2026-06-10T02:00:00Z'
                operation         = 'UserLoginFailed'
                userPrincipalName = 'u@contoso.com'
                auditData         = @{ ApplicationId = 'app'; ErrorNumber = '700016'; ErrorCode = '50126' }
            }
            (ConvertFrom-CredEchoLogonRecord -Record $record).ErrorCode | Should -Be '700016'
        }
    }

    It 'falls back to the documented ErrorCode field when ErrorNumber is absent' {
        InModuleScope CredEcho {
            $record = @{
                id                = 'x'
                createdDateTime   = '2026-06-10T02:00:00Z'
                operation         = 'UserLoginFailed'
                userPrincipalName = 'u@contoso.com'
                auditData         = @{ ApplicationId = 'app'; ErrorCode = '700016' }
            }
            $flat = ConvertFrom-CredEchoLogonRecord -Record $record
            $flat.ErrorCode | Should -Be '700016'
            $flat.ErrorClass | Should -Be 'PostPassword'
        }
    }

    It 'classifies a UserLoggedIn record as Success without trusting ResultStatus' {
        InModuleScope CredEcho {
            $record = @{
                id                = 'x'
                createdDateTime   = '2026-06-10T02:00:00Z'
                operation         = 'UserLoggedIn'
                userPrincipalName = 'u@contoso.com'
                auditData         = @{ ApplicationId = 'app'; ErrorNumber = 0; ResultStatus = 'Failed' }
            }
            $flat = ConvertFrom-CredEchoLogonRecord -Record $record
            $flat.ErrorClass | Should -Be 'Success'
            $flat.IsSuccess | Should -BeTrue
        }
    }

    It 'classifies an unrecognised failure code as Other so it never becomes a triage target' {
        InModuleScope CredEcho {
            $record = @{
                id                = 'x'
                createdDateTime   = '2026-06-10T02:00:00Z'
                operation         = 'UserLoginFailed'
                userPrincipalName = 'u@contoso.com'
                auditData         = @{ ApplicationId = 'app'; ErrorNumber = '90099' }
            }
            (ConvertFrom-CredEchoLogonRecord -Record $record).ErrorClass | Should -Be 'Other'
        }
    }

    It 'prefers ActorIpAddress, then ClientIP, then the envelope clientIp' {
        InModuleScope CredEcho {
            $all = @{ id = 'x'; createdDateTime = '2026-06-10T02:00:00Z'; operation = 'UserLoginFailed'; clientIp = '3.3.3.3'
                auditData = @{ ErrorNumber = '700016'; ActorIpAddress = '1.1.1.1'; ClientIP = '2.2.2.2' }
            }
            $noActor = @{ id = 'x'; createdDateTime = '2026-06-10T02:00:00Z'; operation = 'UserLoginFailed'; clientIp = '3.3.3.3'
                auditData = @{ ErrorNumber = '700016'; ClientIP = '2.2.2.2' }
            }
            $envelopeOnly = @{ id = 'x'; createdDateTime = '2026-06-10T02:00:00Z'; operation = 'UserLoginFailed'; clientIp = '3.3.3.3'
                auditData = @{ ErrorNumber = '700016' }
            }
            (ConvertFrom-CredEchoLogonRecord -Record $all).IpAddress | Should -Be '1.1.1.1'
            (ConvertFrom-CredEchoLogonRecord -Record $noActor).IpAddress | Should -Be '2.2.2.2'
            (ConvertFrom-CredEchoLogonRecord -Record $envelopeOnly).IpAddress | Should -Be '3.3.3.3'
        }
    }

    It 'honours an overridden post-password table' {
        InModuleScope CredEcho {
            $record = @{
                id                = 'x'
                createdDateTime   = '2026-06-10T02:00:00Z'
                operation         = 'UserLoginFailed'
                userPrincipalName = 'u@contoso.com'
                auditData         = @{ ApplicationId = 'app'; ErrorNumber = '50072' }
            }
            (ConvertFrom-CredEchoLogonRecord -Record $record).ErrorClass | Should -Be 'Other'
            $extended = @{ '50072' = 'UserStrongAuthEnrollmentRequiredInterrupt' }
            (ConvertFrom-CredEchoLogonRecord -Record $record -PostPasswordError $extended).ErrorClass | Should -Be 'PostPassword'
        }
    }
}

Describe 'Get-CredEchoKnownApplication' {


    It 'enumerates service principal application identifiers' {
        InModuleScope CredEcho {
            Mock Invoke-MgGraphRequest { @{ value = @( @{ appId = 'aaaa1111-1111-1111-1111-111111111111' } ) } }
            $known = Get-CredEchoKnownApplication
            $known.RegisteredCount | Should -Be 1
            $known.Registered.Contains('aaaa1111-1111-1111-1111-111111111111') | Should -BeTrue
        }
    }

    It 'matches a service principal identifier without regard to case' {
        InModuleScope CredEcho {
            Mock Invoke-MgGraphRequest { @{ value = @( @{ appId = 'aaaa1111-1111-1111-1111-111111111111' } ) } }
            (Get-CredEchoKnownApplication).Registered.Contains('AAAA1111-1111-1111-1111-111111111111') | Should -BeTrue
        }
    }

    Context 'Tenant-wide corroboration control' {

        It 'corroborates an identifier reaching the distinct account threshold' {
            InModuleScope CredEcho {
                Mock Invoke-MgGraphRequest { @{ value = @( @{ appId = 'aaaa1111-1111-1111-1111-111111111111' } ) } }
                $success = @(
                    [pscustomobject]@{ ApplicationId = 'unregistered-app'; UserPrincipalName = 'a@contoso.com' }
                    [pscustomobject]@{ ApplicationId = 'unregistered-app'; UserPrincipalName = 'b@contoso.com' }
                    [pscustomobject]@{ ApplicationId = 'unregistered-app'; UserPrincipalName = 'c@contoso.com' }
                )
                $known = Get-CredEchoKnownApplication -BaselineSuccess $success -CorroborationAccountThreshold 3
                $known.CorroboratedCount | Should -Be 1
                $known.Corroborated.Contains('unregistered-app') | Should -BeTrue
            }
        }

        It 'does not corroborate an identifier below the threshold' {
            InModuleScope CredEcho {
                Mock Invoke-MgGraphRequest { @{ value = @( @{ appId = 'aaaa1111-1111-1111-1111-111111111111' } ) } }
                $success = @(
                    [pscustomobject]@{ ApplicationId = 'unregistered-app'; UserPrincipalName = 'a@contoso.com' }
                    [pscustomobject]@{ ApplicationId = 'unregistered-app'; UserPrincipalName = 'b@contoso.com' }
                )
                $known = Get-CredEchoKnownApplication -BaselineSuccess $success -CorroborationAccountThreshold 3
                $known.CorroboratedCount | Should -Be 0
            }
        }

        It 'counts distinct accounts and not repeated sign-ins by one account' {
            InModuleScope CredEcho {
                Mock Invoke-MgGraphRequest { @{ value = @( @{ appId = 'aaaa1111-1111-1111-1111-111111111111' } ) } }
                $success = @(1..10 | ForEach-Object {
                        [pscustomobject]@{ ApplicationId = 'unregistered-app'; UserPrincipalName = 'a@contoso.com' }
                    })
                (Get-CredEchoKnownApplication -BaselineSuccess $success -CorroborationAccountThreshold 3).CorroboratedCount | Should -Be 0
            }
        }

        It 'honours a raised threshold as a named parameter' {
            InModuleScope CredEcho {
                Mock Invoke-MgGraphRequest { @{ value = @( @{ appId = 'aaaa1111-1111-1111-1111-111111111111' } ) } }
                $success = @('a', 'b', 'c' | ForEach-Object {
                        [pscustomobject]@{ ApplicationId = 'unregistered-app'; UserPrincipalName = "$($_)@contoso.com" }
                    })
                (Get-CredEchoKnownApplication -BaselineSuccess $success -CorroborationAccountThreshold 5).CorroboratedCount | Should -Be 0
                (Get-CredEchoKnownApplication -BaselineSuccess $success -CorroborationAccountThreshold 3).CorroboratedCount | Should -Be 1
            }
        }

        It 'does not count an already registered identifier as corroborated' {
            InModuleScope CredEcho {
                Mock Invoke-MgGraphRequest { @{ value = @( @{ appId = 'aaaa1111-1111-1111-1111-111111111111' } ) } }
                $success = @('a', 'b', 'c' | ForEach-Object {
                        [pscustomobject]@{ ApplicationId = 'aaaa1111-1111-1111-1111-111111111111'; UserPrincipalName = "$($_)@contoso.com" }
                    })
                (Get-CredEchoKnownApplication -BaselineSuccess $success -CorroborationAccountThreshold 3).CorroboratedCount | Should -Be 0
            }
        }
    }

    Context 'Explicit allowlist control' {

        It 'accepts identifiers to exclude without a code change' {
            InModuleScope CredEcho {
                Mock Invoke-MgGraphRequest { @{ value = @( @{ appId = 'aaaa1111-1111-1111-1111-111111111111' } ) } }
                $known = Get-CredEchoKnownApplication -AllowedApplicationId 'internal-client-1', 'internal-client-2'
                $known.AllowedCount | Should -Be 2
                $known.Allowed.Contains('internal-client-1') | Should -BeTrue
            }
        }

        It 'trims whitespace and ignores empty entries' {
            InModuleScope CredEcho {
                Mock Invoke-MgGraphRequest { @{ value = @( @{ appId = 'aaaa1111-1111-1111-1111-111111111111' } ) } }
                $known = Get-CredEchoKnownApplication -AllowedApplicationId '  internal-client-1  ', '', '   '
                $known.AllowedCount | Should -Be 1
                $known.Allowed.Contains('internal-client-1') | Should -BeTrue
            }
        }

        It 'does not double count an allowlisted identifier that is already registered' {
            InModuleScope CredEcho {
                Mock Invoke-MgGraphRequest { @{ value = @( @{ appId = 'aaaa1111-1111-1111-1111-111111111111' } ) } }
                (Get-CredEchoKnownApplication -AllowedApplicationId 'aaaa1111-1111-1111-1111-111111111111').AllowedCount | Should -Be 0
            }
        }
    }

    It 'follows the nextLink when service principals span pages' {
        InModuleScope CredEcho {
            $script:page = 0
            Mock Invoke-MgGraphRequest {
                $script:page++
                if ($script:page -eq 1) {
                    return @{ value = @( @{ appId = 'page1-app' } ); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/servicePrincipals?next' }
                }
                return @{ value = @( @{ appId = 'page2-app' } ) }
            }
            $known = Get-CredEchoKnownApplication
            $known.RegisteredCount | Should -Be 2
            $known.Registered.Contains('page2-app') | Should -BeTrue
        }
    }
}

Describe 'Get-CredEchoValidationEvent' {

    It 'keeps a post-password record whose application is unregistered' {
        InModuleScope CredEcho {
            $known = [pscustomobject]@{
                Registered   = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                Corroborated = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                Allowed      = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            }
            $record = [pscustomobject]@{ UserPrincipalName = 'u@contoso.com'; ApplicationId = 'attacker-app'; ErrorCode = '700016'; ErrorClass = 'PostPassword'; TimeStamp = [datetime]'2026-06-10T02:00:00Z'; IpAddress = '1.2.3.4'; IpPrefix = '1.2.3.0/24'; UserAgent = 'ua' }
            $result = Get-CredEchoValidationEvent -LogonRecord @($record) -KnownApplication $known
            $result.ValidationEventCount | Should -Be 1
            $result.ValidatedAccount | Should -Contain 'u@contoso.com'
        }
    }

    It 'counts username oracle events as campaign context and never triages the accounts they name' {
        InModuleScope CredEcho {
            $known = [pscustomobject]@{
                Registered   = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                Corroborated = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                Allowed      = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            }
            $records = @(
                [pscustomobject]@{ UserPrincipalName = 'probed@contoso.com'; ApplicationId = 'attacker-app'; ErrorCode = '50126'; ErrorClass = 'UsernameOracle'; TimeStamp = [datetime]'2026-06-10T02:00:00Z'; IpAddress = '9.9.9.9'; IpPrefix = 'p'; UserAgent = 'ua' }
                [pscustomobject]@{ UserPrincipalName = 'probed2@contoso.com'; ApplicationId = 'attacker-app'; ErrorCode = '50034'; ErrorClass = 'UsernameOracle'; TimeStamp = [datetime]'2026-06-10T02:00:00Z'; IpAddress = '9.9.9.9'; IpPrefix = 'p'; UserAgent = 'ua' }
            )
            $result = Get-CredEchoValidationEvent -LogonRecord $records -KnownApplication $known
            $result.ValidationEventCount | Should -Be 0
            $result.UsernameOracleEventCount | Should -Be 2
            $result.UsernameOracleAccountCount | Should -Be 2
            $result.UsernameOracleSourceCount | Should -Be 1
            $result.ValidatedAccount | Should -Not -Contain 'probed@contoso.com'
        }
    }

    It 'retains a post-password record whose application identifier is empty, since a malformed client identifier is never recorded' {
        InModuleScope CredEcho {
            $known = [pscustomobject]@{
                Registered   = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                Corroborated = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                Allowed      = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            }
            $record = [pscustomobject]@{ UserPrincipalName = 'u@contoso.com'; ApplicationId = ''; ErrorCode = '700016'; ErrorClass = 'PostPassword'; TimeStamp = [datetime]'2026-06-10T02:00:00Z'; IpAddress = '1.2.3.4'; IpPrefix = 'p'; UserAgent = 'ua' }
            $result = Get-CredEchoValidationEvent -LogonRecord @($record) -KnownApplication $known
            $result.ValidationEventCount | Should -Be 1
            $result.AttackerApplicationIdCount | Should -Be 0
        }
    }

    It 'reports suppression separately for each control rather than silently' {
        InModuleScope CredEcho {
            $registered = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            [void] $registered.Add('registered-app')
            $corroborated = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            [void] $corroborated.Add('corroborated-app')
            $allowed = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            [void] $allowed.Add('allowed-app')
            $known = [pscustomobject]@{ Registered = $registered; Corroborated = $corroborated; Allowed = $allowed }

            $records = @('registered-app', 'corroborated-app', 'allowed-app', 'attacker-app' | ForEach-Object {
                    [pscustomobject]@{ UserPrincipalName = "u-$($_)@contoso.com"; ApplicationId = $_; ErrorCode = '700016'; ErrorClass = 'PostPassword'; TimeStamp = [datetime]'2026-06-10T02:00:00Z'; IpAddress = '1.2.3.4'; IpPrefix = 'p'; UserAgent = 'ua' }
                })

            $result = Get-CredEchoValidationEvent -LogonRecord $records -KnownApplication $known
            $result.ValidationEventCount | Should -Be 1
            $result.SuppressedByRegistrationCount | Should -Be 1
            $result.SuppressedByCorroborationCount | Should -Be 1
            $result.SuppressedByAllowlistCount | Should -Be 1
            $result.SuppressedByRegistration | Should -Contain 'registered-app'
            $result.SuppressedByCorroboration | Should -Contain 'corroborated-app'
            $result.SuppressedByAllowlist | Should -Contain 'allowed-app'
        }
    }

    It 'returns an empty result set without throwing when nothing was found' {
        InModuleScope CredEcho {
            $known = [pscustomobject]@{
                Registered   = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                Corroborated = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                Allowed      = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            }
            $result = Get-CredEchoValidationEvent -LogonRecord @() -KnownApplication $known
            $result.ValidationEventCount | Should -Be 0
            $result.FirstValidation | Should -BeNullOrEmpty
        }
    }
}

Describe 'Invoke-CredEchoTriage end to end' {

    BeforeAll {
        Mock -ModuleName CredEcho Get-MgContext {
            [pscustomobject]@{
                TenantId = '00000000-1111-2222-3333-444444444444'
                Account  = 'analyst@contoso.com'
                AuthType = 'Delegated'
                Scopes   = @('AuditLogsQuery-Entra.Read.All', 'AuditLogsQuery-Exchange.Read.All', 'Application.Read.All')
            }
        }

        Mock -ModuleName CredEcho Start-Sleep { }

        Mock -ModuleName CredEcho Invoke-MgGraphRequest {
            if ($Uri -like '*servicePrincipals*') {
                return @{ value = @( @{ appId = $script:CredEchoTestApp.Registered } ) }
            }

            if ($Method -eq 'POST') {
                $script:CredEchoTestQuerySeq++
                $id = "q$($script:CredEchoTestQuerySeq)"
                $script:CredEchoTestQueryMap[$id] = ($Body | ConvertFrom-Json)
                return @{ id = $id; status = 'succeeded' }
            }

            if ($Uri -match 'queries/(q\d+)/records') {
                $spec = $script:CredEchoTestQueryMap[$Matches[1]]
                # An absent filter deserialises to $null, and @($null) has a count of one, so
                # empty entries have to be stripped or an absent filter matches nothing.
                $operations = @($spec.operationFilters | Where-Object { -not [string]::IsNullOrWhiteSpace([string] $_) })
                $upnFilter = @($spec.userPrincipalNameFilters | Where-Object { -not [string]::IsNullOrWhiteSpace([string] $_) })

                $rows = @()
                if ($operations -contains 'UserLoginFailed') { $rows = $script:CredEchoTestFailed }
                elseif ($operations -contains 'UserLoggedIn') { $rows = $script:CredEchoTestSuccess }
                else { $rows = $script:CredEchoTestFollowOn }

                if ($upnFilter.Count -gt 0) {
                    $rows = @($rows | Where-Object { $upnFilter -contains [string] $_['userPrincipalName'] })
                }

                # Only return records inside the requested slice, so chunking is exercised for real.
                $from = [datetime] $spec.filterStartDateTime
                $to = [datetime] $spec.filterEndDateTime
                $rows = @($rows | Where-Object {
                        $stamp = ([datetime] $_['createdDateTime']).ToUniversalTime()
                        $stamp -ge $from.ToUniversalTime() -and $stamp -le $to.ToUniversalTime()
                    })

                return @{ value = $rows }
            }

            if ($Uri -match 'queries/(q\d+)$') {
                return @{ id = $Matches[1]; status = 'succeeded' }
            }

            throw "Unexpected Graph call in test: $($Method) $($Uri)"
        }

        $script:CredEchoTestQueryMap = @{}
        $script:CredEchoTestQuerySeq = 0

        $script:result = Invoke-CredEchoTriage -OutputDirectory (Join-Path $TestDrive 'out') `
            -SearchStartTime ([datetime]::SpecifyKind([datetime]'2026-06-01T00:00:00', 'Utc')) `
            -SearchEndTime ([datetime]::SpecifyKind([datetime]'2026-06-30T00:00:00', 'Utc')) `
            -AllowedApplicationId $script:CredEchoTestApp.Allowed `
            -BaselineDays 90

        $script:verdict = @{}
        foreach ($row in $script:result.AccountVerdict) { $script:verdict[$row.UserPrincipalName] = $row }
    }

    Context 'Phase one detection' {

        It 'derives its own target list from the audit log' {
            $script:result.Summary.ValidationEventCount | Should -Be 7
            $script:result.Summary.ValidatedAccountCount | Should -Be 7
        }

        It 'never triages an account that only produced a username oracle error' {
            $script:verdict.Keys | Should -Not -Contain 'probeonly@contoso.com'
            $script:result.ValidationEvent.UserPrincipalName | Should -Not -Contain 'probeonly@contoso.com'
        }

        It 'reports username oracle activity as campaign context' {
            $script:result.Summary.UsernameOracleEventCount | Should -Be 1
            $script:result.Summary.UsernameOracleAccountCount | Should -Be 1
        }

        It 'suppresses an application with a service principal and reports the count' {
            $script:result.Summary.SuppressedByRegistrationCount | Should -Be 1
            $script:result.Summary.SuppressedByRegistration | Should -Contain $script:CredEchoTestApp.Registered
            $script:verdict.Keys | Should -Not -Contain 'legitapp@contoso.com'
        }

        It 'suppresses an application corroborated across enough distinct accounts and reports the count' {
            $script:result.Summary.SuppressedByCorroborationCount | Should -Be 1
            $script:result.Summary.SuppressedByCorroboration | Should -Contain $script:CredEchoTestApp.Corroborated
            $script:verdict.Keys | Should -Not -Contain 'corrob@contoso.com'
        }

        It 'suppresses an allowlisted application and reports the count' {
            $script:result.Summary.SuppressedByAllowlistCount | Should -Be 1
            $script:result.Summary.SuppressedByAllowlist | Should -Contain $script:CredEchoTestApp.Allowed
            $script:verdict.Keys | Should -Not -Contain 'allowed@contoso.com'
        }

        It 'retains a record whose application identifier was never populated' {
            $script:verdict.Keys | Should -Contain 'noappid@contoso.com'
        }
    }

    Context 'Tier escalation' {

        It 'rates an exact attacker source address match as Confirmed' {
            $script:verdict['jdoe@contoso.com'].Verdict | Should -Be 'Confirmed'
            $script:verdict['jdoe@contoso.com'].ConfirmedSignalCount | Should -Be 1
            $script:verdict['jdoe@contoso.com'].DistinctSignal | Should -Contain 'SourceAddressSeenInValidationActivity:Confirmed'
        }

        It 'flags a non-browser client string as Confirmed' {
            $script:verdict['jdoe@contoso.com'].DistinctSignal | Should -Contain 'NonBrowserClientString:Confirmed'
            $script:verdict['jdoe@contoso.com'].DistinctSignal | Should -Contain 'UserAgentSeenInValidationActivity:Confirmed'
        }

        It 'rates a network prefix match below an exact address match, at Probable' {
            $script:verdict['prob@contoso.com'].Verdict | Should -Be 'Probable'
            $script:verdict['prob@contoso.com'].DistinctSignal | Should -Contain 'NetworkPrefixSeenInValidationActivity:Probable'
            $script:verdict['prob@contoso.com'].ConfirmedSignalCount | Should -Be 0
        }

        It 'does not raise a redundant prefix signal when the exact address already matched' {
            $script:verdict['jdoe@contoso.com'].DistinctSignal | Should -Not -Contain 'NetworkPrefixSeenInValidationActivity:Probable'
        }

        It 'rates a first-seen source address with no enrichment as Possible' {
            $script:verdict['poss2@contoso.com'].Verdict | Should -Be 'Possible'
            $script:verdict['poss2@contoso.com'].DistinctSignal | Should -Contain 'FirstSeenSourceAddressMultifactorUnknown:Possible'
        }

        It 'escalates to Confirmed when a follow-on persistence action accompanies any flagged sign-in' {
            $script:verdict['poss@contoso.com'].Verdict | Should -Be 'Confirmed'
            $script:verdict['poss@contoso.com'].ConfirmedSignalCount | Should -Be 0
            $script:verdict['poss@contoso.com'].FollowOnActionCount | Should -Be 1
            $script:verdict['poss@contoso.com'].DistinctSignal | Should -Contain 'FollowOnActionWithFlaggedSignIn:Confirmed'
        }

        It 'returns NoIndicators when every post-validation sign-in matches the baseline' {
            $script:verdict['clean@contoso.com'].Verdict | Should -Be 'NoIndicators'
            $script:verdict['clean@contoso.com'].FlaggedSignInCount | Should -Be 0
            $script:verdict['clean@contoso.com'].BaselineAssessed | Should -BeTrue
        }

        It 'tallies verdicts in the summary' {
            $script:result.Summary.VerdictConfirmed | Should -Be 2
            $script:result.Summary.VerdictProbable | Should -Be 1
            $script:result.Summary.VerdictPossible | Should -Be 2
            $script:result.Summary.VerdictNoIndicators | Should -Be 2
        }
    }

    Context 'Empty baseline' {

        It 'signals that novelty could not be assessed instead of reporting a clean result' {
            $row = $script:verdict['nobase@contoso.com']
            $row.BaselineAssessed | Should -BeFalse
            $row.BaselineSignInCount | Should -Be 0
            $row.DistinctSignal | Should -Contain 'NoveltyCouldNotBeAssessed:Possible'
            $row.NoveltyAssessment | Should -Match 'could not be assessed'
            $row.Verdict | Should -Not -Be 'NoIndicators'
        }

        It 'does not claim novelty for an account it could not baseline' {
            $row = $script:verdict['nobase@contoso.com']
            $row.DistinctSignal | Should -Not -Contain 'FirstSeenSourceAddressMultifactorUnknown:Possible'
            $row.DistinctSignal | Should -Not -Contain 'FirstSeenNetworkPrefixWithoutMultifactor:Probable'
        }

        It 'still records the assessment for an account with a baseline' {
            $script:verdict['jdoe@contoso.com'].NoveltyAssessment | Should -Be 'Assessed'
            $script:verdict['jdoe@contoso.com'].BaselineSignInCount | Should -Be 1
        }
    }

    Context 'Phase three follow-on actions' {

        It 'collects persistence actions and categorises them' {
            $script:result.FollowOnAction.Count | Should -Be 1
            $script:result.FollowOnAction[0].Category | Should -Be 'AuthenticationMethodRegistration'
            $script:result.FollowOnAction[0].IsTargetAccount | Should -BeTrue
        }
    }

    Context 'Output artifacts' {

        It 'writes every artifact' -ForEach @(
            @{ FileName = 'AccountVerdicts.csv' }
            @{ FileName = 'ValidationEvents.csv' }
            @{ FileName = 'FlaggedSignIns.csv' }
            @{ FileName = 'FollowOnActions.csv' }
            @{ FileName = 'TriageResults.json' }
        ) {
            Join-Path (Join-Path $TestDrive 'out') $FileName | Should -Exist
        }

        It 'sorts AccountVerdicts.csv with Confirmed first' {
            $rows = Import-Csv -LiteralPath (Join-Path (Join-Path $TestDrive 'out') 'AccountVerdicts.csv') -Delimiter ';'
            $rows[0].Verdict | Should -Be 'Confirmed'
            $rows[1].Verdict | Should -Be 'Confirmed'
            $rows[-1].Verdict | Should -Be 'NoIndicators'
        }

        It 'uses a semicolon delimiter by default and keeps the signal list intact' {
            $raw = Get-Content -LiteralPath (Join-Path (Join-Path $TestDrive 'out') 'FlaggedSignIns.csv') -Raw
            $raw | Should -Match ';'
            $raw | Should -Match 'SourceAddressSeenInValidationActivity'
        }

        It 'produces a JSON summary that round-trips' {
            $json = Get-Content -LiteralPath (Join-Path (Join-Path $TestDrive 'out') 'TriageResults.json') -Raw | ConvertFrom-Json
            $json.Summary.ValidationEventCount | Should -Be 7
            $json.Summary.TenantId | Should -Be '00000000-1111-2222-3333-444444444444'
            $json.Summary.CorroborationScope | Should -Be 'TriageTargetAccountsOnly'
        }

        It 'writes no HTML report unless the switch is specified' {
            Join-Path (Join-Path $TestDrive 'out') 'TriageReport.html' | Should -Not -Exist
        }

        It 'writes the HTML report when IncludeHtmlReport is specified' {
            $target = Join-Path $TestDrive 'withreport'
            $run = Invoke-CredEchoTriage -OutputDirectory $target `
                -SearchStartTime ([datetime]::SpecifyKind([datetime]'2026-06-01T00:00:00', 'Utc')) `
                -SearchEndTime ([datetime]::SpecifyKind([datetime]'2026-06-30T00:00:00', 'Utc')) `
                -AllowedApplicationId $script:CredEchoTestApp.Allowed -BaselineDays 90 -IncludeHtmlReport

            $reportPath = Join-Path $target 'TriageReport.html'
            $reportPath | Should -Exist
            @($run.File).Count | Should -Be 6
            $html = Get-Content -LiteralPath $reportPath -Raw
            $html | Should -BeLike '*var REPORT_DATA = *'
            $html | Should -Not -BeLike '*__CREDECHO_REPORT_DATA__*'
        }
    }

    Context 'Read only' {

        It 'never calls Graph with a mutating method' {
            $mutating = @($script:CredEchoTestQueryMap.Values | Where-Object { $null -eq $_ })
            $mutating.Count | Should -Be 0
            # Every POST issued is an audit log query submission, which is how the read API works.
            foreach ($spec in $script:CredEchoTestQueryMap.Values) {
                $spec.displayName | Should -Match '^CredEcho'
            }
        }

        It 'exports only the triage cmdlet and the report cmdlet' {
            @(Get-Command -Module CredEcho).Name | Sort-Object |
                Should -Be @('Invoke-CredEchoTriage', 'New-CredEchoReport')
        }
    }
}

Describe 'Test-CredEchoGraphContext' {

    It 'throws a clear message when no context exists' {
        InModuleScope CredEcho {
            Mock Get-MgContext { $null }
            { Test-CredEchoGraphContext -AnyOfScope 'AuditLogsQuery.Read.All' -Capability 'testing' } |
                Should -Throw -ExpectedMessage '*Connect-MgGraph*'
        }
    }

    It 'names the missing scope when the context cannot satisfy the capability' {
        InModuleScope CredEcho {
            Mock Get-MgContext { [pscustomobject]@{ Scopes = @('User.Read') } }
            { Test-CredEchoGraphContext -AnyOfScope 'AuditLogsQuery-Entra.Read.All' -Capability 'reading audit records' } |
                Should -Throw -ExpectedMessage '*AuditLogsQuery-Entra.Read.All*'
        }
    }

    It 'accepts any one of several alternative scopes' {
        InModuleScope CredEcho {
            Mock Get-MgContext { [pscustomobject]@{ Scopes = @('AuditLogsQuery.Read.All') } }
            Test-CredEchoGraphContext -AnyOfScope 'AuditLogsQuery-Entra.Read.All', 'AuditLogsQuery.Read.All' -Capability 'reading audit records' |
                Should -BeTrue
        }
    }

    It 'warns instead of throwing for an optional capability' {
        InModuleScope CredEcho {
            Mock Get-MgContext { [pscustomobject]@{ Scopes = @('User.Read') } }
            Mock Write-Warning { }
            Test-CredEchoGraphContext -AnyOfScope 'AuditLog.Read.All' -Capability 'enrichment' -Optional | Should -BeFalse
            Should -Invoke Write-Warning -Times 1
        }
    }
}

Describe 'HTML report renderer' {

    BeforeAll {
        # Angle brackets, both quote characters, an event handler, and a literal closing script
        # tag. Every one of these has to reach the page as inert text.
        $script:HostileAgent = 'python-requests/2.32.3 <img src=x onerror="alert(''pwn'')"> </script><script>fetch(1)</script>'

        function Get-CredEchoRendererFixture {
            $attackerApp = 'ffff9999-9999-9999-9999-999999999999'

            # Every indicator list below holds exactly one element on purpose. A one-element
            # collection is the case that silently degrades to a scalar on serialisation.
            $validation = @(
                [pscustomobject]@{ RecordId = 'v1'; TimeStamp = '2026-06-10T02:00:00Z'; Operation = 'UserLoginFailed'
                    RecordType = 'azureActiveDirectoryStsLogon'; UserPrincipalName = 'confirmed@contoso.com'
                    ApplicationId = $attackerApp; ErrorCode = '700016'; ErrorClass = 'PostPassword'
                    ErrorName = 'UnauthorizedClient_DoesNotMatchRequest'; ErrorConfidence = 'Observed'
                    LogonError = 'InvalidResourceServicePrincipalNotFound'; IpAddress = '185.220.101.44'
                    IpPrefix = '185.220.101.0/24'; UserAgent = $script:HostileAgent
                    RequestType = 'OAuth2:Token'; ResultStatusDetail = ''; IsSuccess = $false }
            )

            $flagged = @(
                [pscustomobject]@{ UserPrincipalName = 'confirmed@contoso.com'; TimeStamp = '2026-06-15T09:00:00Z'
                    Tier = 'Confirmed'; Signal = @('SourceAddressSeenInValidationActivity:Confirmed')
                    IpAddress = '185.220.101.44'; IpPrefix = '185.220.101.0/24'; UserAgent = $script:HostileAgent
                    ApplicationId = $attackerApp; RecordId = 's1'; ClientAppUsed = 'Other clients'
                    ConditionalAccessStatus = 'notApplied'; AuthenticationRequirement = 'singleFactorAuthentication'
                    AuthenticationProtocol = 'ropc'; RiskLevelDuringSignIn = 'high'
                    AutonomousSystemNumber = 14061; Enriched = $true }
                [pscustomobject]@{ UserPrincipalName = 'nobaseline@contoso.com'; TimeStamp = '2026-06-15T11:45:00Z'
                    Tier = 'Possible'; Signal = @('NoveltyCouldNotBeAssessed:Possible')
                    IpAddress = '8.8.8.8'; IpPrefix = '8.8.8.0/24'; UserAgent = 'Mozilla/5.0 (Linux)'
                    ApplicationId = 'aaaa1111-1111-1111-1111-111111111111'; RecordId = 's2'; ClientAppUsed = ''
                    ConditionalAccessStatus = ''; AuthenticationRequirement = ''; AuthenticationProtocol = ''
                    RiskLevelDuringSignIn = ''; AutonomousSystemNumber = $null; Enriched = $false }
            )

            $followOn = @(
                [pscustomobject]@{ UserPrincipalName = 'confirmed@contoso.com'; TimeStamp = '2026-06-17T11:00:00Z'
                    Operation = 'New-InboxRule'; Category = 'InboxRule'; RecordType = 'exchangeAdmin'
                    # An inbox rule name is chosen by whoever created the rule, so the target
                    # object is attacker controlled on exactly the records that matter most.
                    IpAddress = '185.220.101.44'; TargetObject = 'Forward all <img src=x onerror="alert(1)">'
                    RecordId = 'f1'; IsTargetAccount = $true }
                # No target object. Not every audit record carries one, and the table has to say so
                # rather than render an empty cell that reads as though nothing was touched.
                [pscustomobject]@{ UserPrincipalName = 'confirmed@contoso.com'; TimeStamp = '2026-06-17T11:04:00Z'
                    Operation = 'Add strong authentication method'; Category = 'AuthenticationMethodRegistration'
                    RecordType = 'azureActiveDirectory'; IpAddress = '185.220.101.44'; TargetObject = ''
                    RecordId = 'f2'; IsTargetAccount = $true }
            )

            $verdicts = @(
                [pscustomobject]@{ UserPrincipalName = 'confirmed@contoso.com'; Verdict = 'Confirmed'
                    ConfirmedSignalCount = 1; ProbableSignalCount = 0; PossibleSignalCount = 0
                    DistinctSignal = @('SourceAddressSeenInValidationActivity:Confirmed')
                    FirstValidation = '2026-06-10T02:00:00Z'; LastValidation = '2026-06-10T02:00:00Z'
                    ValidationErrorCode = @('700016'); ValidationSourceAddress = @('185.220.101.44')
                    ValidationTimestampAssumed = $false; PostValidationSignInCount = 3; FlaggedSignInCount = 1
                    FollowOnActionCount = 2; BaselineAssessed = $true; BaselineSignInCount = 42
                    NoveltyAssessment = 'Assessed' }
                [pscustomobject]@{ UserPrincipalName = 'probable@contoso.com'; Verdict = 'Probable'
                    ConfirmedSignalCount = 0; ProbableSignalCount = 1; PossibleSignalCount = 0
                    DistinctSignal = @('NetworkPrefixSeenInValidationActivity:Probable')
                    FirstValidation = '2026-06-10T02:06:00Z'; LastValidation = '2026-06-10T02:06:00Z'
                    ValidationErrorCode = @('53003'); ValidationSourceAddress = @('198.51.100.10')
                    ValidationTimestampAssumed = $false; PostValidationSignInCount = 5; FlaggedSignInCount = 0
                    FollowOnActionCount = 0; BaselineAssessed = $true; BaselineSignInCount = 18
                    NoveltyAssessment = 'Assessed' }
                [pscustomobject]@{ UserPrincipalName = 'nobaseline@contoso.com'; Verdict = 'Possible'
                    ConfirmedSignalCount = 0; ProbableSignalCount = 0; PossibleSignalCount = 1
                    DistinctSignal = @('NoveltyCouldNotBeAssessed:Possible')
                    FirstValidation = $null; LastValidation = $null; ValidationErrorCode = @('50076')
                    ValidationSourceAddress = @('203.0.113.5'); ValidationTimestampAssumed = $true
                    PostValidationSignInCount = 1; FlaggedSignInCount = 1; FollowOnActionCount = 0
                    BaselineAssessed = $false; BaselineSignInCount = 0
                    NoveltyAssessment = 'Novelty could not be assessed. This account has no successful sign-in in its baseline period.' }
                [pscustomobject]@{ UserPrincipalName = 'clean@contoso.com'; Verdict = 'NoIndicators'
                    ConfirmedSignalCount = 0; ProbableSignalCount = 0; PossibleSignalCount = 0
                    DistinctSignal = @(); FirstValidation = '2026-06-10T02:08:00Z'; LastValidation = '2026-06-10T02:08:00Z'
                    ValidationErrorCode = @('700016'); ValidationSourceAddress = @('192.0.2.60')
                    ValidationTimestampAssumed = $false; PostValidationSignInCount = 9; FlaggedSignInCount = 0
                    FollowOnActionCount = 0; BaselineAssessed = $true; BaselineSignInCount = 63
                    NoveltyAssessment = 'Assessed' }
            )

            [pscustomobject]@{
                Summary         = [pscustomobject]@{
                    GeneratedUtc = '2026-07-31T18:00:00Z'; ModuleVersion = '1.0.0'
                    TenantId = '00000000-1111-2222-3333-444444444444'
                    SearchStartUtc = '2026-02-01T00:00:00Z'; SearchEndUtc = '2026-07-31T00:00:00Z'
                    BaselineDays = 90; ChunkDays = 30
                    ValidationEventCount = 1; ValidatedAccountCount = 4; AttackerApplicationIdCount = 1
                    UsernameOracleEventCount = 38994; UsernameOracleAccountCount = 1476; UsernameOracleSourceCount = 62
                    SuppressedByRegistrationCount = 1; SuppressedByCorroborationCount = 1; SuppressedByAllowlistCount = 1
                    SuppressedByRegistration = @('aaaa1111-1111-1111-1111-111111111111')
                    SuppressedByCorroboration = @('bbbb2222-2222-2222-2222-222222222222')
                    SuppressedByAllowlist = @('cccc3333-3333-3333-3333-333333333333')
                    CorroborationAccountThreshold = 3; CorroborationScope = 'Tenant'
                    SignInEnrichmentAvailable = $true; ExchangeFollowOnAvailable = $true
                    FlaggedSignInCount = 2; FollowOnActionCount = 2; TriagedAccountCount = 4
                }
                AccountVerdict  = $verdicts
                ValidationEvent = $validation
                FlaggedSignIn   = $flagged
                FollowOnAction  = $followOn
            }
        }

        $script:Fixture = Get-CredEchoRendererFixture
        $script:ReportPath = Join-Path $TestDrive 'TriageReport.html'
        InModuleScope CredEcho -Parameters @{ Fixture = $script:Fixture; Target = $script:ReportPath } {
            New-CredEchoHtmlReport -TriageResult $Fixture -Path $Target | Out-Null
        }
        $script:Html = Get-Content -LiteralPath $script:ReportPath -Raw
    }

    Context 'Placeholder substitution and payload validity' {

        It 'leaves no placeholder token in the output' {
            $script:Html | Should -Not -BeLike '*__CREDECHO_REPORT_DATA__*'
        }

        It 'injects a payload that parses as JSON' {
            $match = [regex]::Match($script:Html, 'var REPORT_DATA = (?<json>.+?);</script>')
            $match.Success | Should -BeTrue
            { $match.Groups['json'].Value | ConvertFrom-Json } | Should -Not -Throw
            $parsed = $match.Groups['json'].Value | ConvertFrom-Json
            @($parsed.Account).Count | Should -Be 4
            $parsed.Meta.TenantId | Should -Be '00000000-1111-2222-3333-444444444444'
        }

        It 'carries all four verdict tiers even where a count is zero' {
            $parsed = ([regex]::Match($script:Html, 'var REPORT_DATA = (?<json>.+?);</script>')).Groups['json'].Value | ConvertFrom-Json
            foreach ($tier in 'Confirmed', 'Probable', 'Possible', 'NoIndicators') {
                $parsed.Verdict.PSObject.Properties.Name | Should -Contain $tier
            }
            $parsed.Verdict.Confirmed | Should -Be 1
            $parsed.Verdict.NoIndicators | Should -Be 1
        }

        It 'serialises a one-element collection as a JSON array rather than a bare scalar' {
            # Regression guard. A scalar here reaches the page as a string, which answers
            # truthily and reports a length while having no map method, so the renderer fails on
            # exactly the reports that carry a single indicator.
            $parsed = ([regex]::Match($script:Html, 'var REPORT_DATA = (?<json>.+?);</script>')).Groups['json'].Value | ConvertFrom-Json
            foreach ($name in 'SourceAddress', 'NetworkPrefix', 'UserAgent', 'ApplicationId', 'ErrorCode',
                'SuppressedByRegistration', 'SuppressedByCorroboration', 'SuppressedByAllowlist') {
                $value = $parsed.Indicator.$name
                $value -is [array] | Should -BeTrue -Because "Indicator.$($name) must be an array, and it holds one element in this fixture"
                @($value).Count | Should -Be 1
            }
            $first = $parsed.Account[0]
            $first.SignIn -is [array] | Should -BeTrue
            $first.DistinctSignal -is [array] | Should -BeTrue
            $first.ValidationErrorCode -is [array] | Should -BeTrue
            $first.FollowOn -is [array] | Should -BeTrue
        }

        It 'has no engagement context field that the page never reads' {
            # Dead field guard. A value can be serialised into the payload and then never consumed,
            # which reads as reported when it is not. This caught UsernameOracleEventCount, where
            # the campaign probe volume was carried into the page and silently dropped.
            $parsed = ([regex]::Match($script:Html, 'var REPORT_DATA = (?<json>.+?);</script>')).Groups['json'].Value | ConvertFrom-Json
            $scriptText = ($script:Html -split '<script>')[-1]
            foreach ($name in $parsed.Context.PSObject.Properties.Name) {
                $scriptText | Should -BeLike "*C.$($name)*" -Because "Context.$($name) is serialised, so the page has to read it or it should not be sent"
            }
        }
    }

    Context 'Follow-on target objects' {

        It 'carries the target object into the payload, encoded' {
            $parsed = ([regex]::Match($script:Html, 'var REPORT_DATA = (?<json>.+?);</script>')).Groups['json'].Value | ConvertFrom-Json
            $confirmed = @($parsed.Account | Where-Object { $_.UserPrincipalName -eq 'confirmed@contoso.com' })[0]
            $target = @($confirmed.FollowOn)[0].TargetObject
            $target | Should -BeLike 'Forward all &lt;img src=x*'
            $target | Should -Not -BeLike '*<img*'
        }

        It 'renders a target object column in the follow-on table' {
            $script:Html | Should -BeLike '*<th>Target object</th>*'
            $script:Html | Should -BeLike '*r.TargetObject*'
        }

        It 'names the target object in the timeline detail' {
            $parsed = ([regex]::Match($script:Html, 'var REPORT_DATA = (?<json>.+?);</script>')).Groups['json'].Value | ConvertFrom-Json
            $confirmed = @($parsed.Account | Where-Object { $_.UserPrincipalName -eq 'confirmed@contoso.com' })[0]
            $followOnEvent = @($confirmed.Timeline | Where-Object { $_.Label -like 'Follow-on action*' })[0]
            $followOnEvent.Detail | Should -BeLike '*Forward all*'
            $followOnEvent.Detail | Should -Not -BeLike '*<img*'
        }

        It 'includes the target object in the search blob so filtering reaches it' {
            $parsed = ([regex]::Match($script:Html, 'var REPORT_DATA = (?<json>.+?);</script>')).Groups['json'].Value | ConvertFrom-Json
            $confirmed = @($parsed.Account | Where-Object { $_.UserPrincipalName -eq 'confirmed@contoso.com' })[0]
            $confirmed.SearchBlob | Should -BeLike '*forward all*'
        }

        It 'falls back to a stated absence rather than an empty cell' {
            $parsed = ([regex]::Match($script:Html, 'var REPORT_DATA = (?<json>.+?);</script>')).Groups['json'].Value | ConvertFrom-Json
            $confirmed = @($parsed.Account | Where-Object { $_.UserPrincipalName -eq 'confirmed@contoso.com' })[0]
            $rows = @($confirmed.FollowOn)
            $rows.Count | Should -Be 2
            $rows[1].TargetObject | Should -Be '' -Because 'the fixture carries a record with no target object'
            $script:Html | Should -BeLike '*not recorded*'
        }

        It 'omits the target object from the timeline detail where none was recorded' {
            $parsed = ([regex]::Match($script:Html, 'var REPORT_DATA = (?<json>.+?);</script>')).Groups['json'].Value | ConvertFrom-Json
            $confirmed = @($parsed.Account | Where-Object { $_.UserPrincipalName -eq 'confirmed@contoso.com' })[0]
            $bare = @($confirmed.Timeline | Where-Object { $_.Label -like '*Add strong authentication method*' })[0]
            $bare | Should -Not -BeNullOrEmpty
            $bare.Detail | Should -Not -BeLike '*,*' -Because 'no trailing separator should be left where there is no target'
        }
    }

    Context 'Error code confidence' {

        It 'reports each code with its name, basis, and event count' {
            $parsed = ([regex]::Match($script:Html, 'var REPORT_DATA = (?<json>.+?);</script>')).Groups['json'].Value | ConvertFrom-Json
            $codes = @($parsed.Indicator.ErrorCode)
            $codes.Count | Should -Be 1
            $codes[0].Code | Should -Be '700016'
            $codes[0].Name | Should -Be 'UnauthorizedClient_DoesNotMatchRequest'
            $codes[0].Confidence | Should -Be 'Observed'
            $codes[0].EventCount | Should -Be 1
        }

        It 'annotates the account error codes from the same source' {
            $parsed = ([regex]::Match($script:Html, 'var REPORT_DATA = (?<json>.+?);</script>')).Groups['json'].Value | ConvertFrom-Json
            $confirmed = @($parsed.Account | Where-Object { $_.UserPrincipalName -eq 'confirmed@contoso.com' })[0]
            @($confirmed.ValidationErrorCode)[0].Code | Should -Be '700016'
            @($confirmed.ValidationErrorCode)[0].Confidence | Should -Be 'Observed'
        }

        It 'degrades to a bare code where no validation event carries that code' {
            # The probable account cites 53003, which no retained validation event names, so there
            # is no basis to report. The code still has to appear rather than vanish.
            $parsed = ([regex]::Match($script:Html, 'var REPORT_DATA = (?<json>.+?);</script>')).Groups['json'].Value | ConvertFrom-Json
            $probable = @($parsed.Account | Where-Object { $_.UserPrincipalName -eq 'probable@contoso.com' })[0]
            $entry = @($probable.ValidationErrorCode)[0]
            $entry.Code | Should -Be '53003'
            $entry.Confidence | Should -Be ''
        }

        It 'explains the three bases in the report body' {
            foreach ($phrase in 'Documented means Microsoft states', 'Observed means the behavior is reported',
                'Ambiguous means Microsoft categorizes') {
                $script:Html | Should -BeLike "*$($phrase)*"
            }
        }

        It 'renders the codes and the account annotation' {
            $script:Html | Should -BeLike '*Post-password error codes*'
            $script:Html | Should -BeLike '*Validation error codes*'
            $script:Html | Should -BeLike '*errorCodeBlock(I.ErrorCode)*'
        }
    }

    Context 'Username enumeration volume' {

        It 'reports the enumeration event count as a context card' {
            $parsed = ([regex]::Match($script:Html, 'var REPORT_DATA = (?<json>.+?);</script>')).Groups['json'].Value | ConvertFrom-Json
            $parsed.Context.UsernameOracleEventCount | Should -Be 38994
            $script:Html | Should -BeLike "*Username enumeration events*"
            $script:Html | Should -BeLike '*C.UsernameOracleEventCount*'
        }
    }

    Context 'Conditional mailbox coverage caveat' {

        It 'holds the scope list open for a conditional limitation' {
            $script:Html | Should -BeLike '*id="scope-list"*'
            $script:Html | Should -BeLike '*Mailbox follow-on coverage is absent*'
        }

        It 'gates the caveat on the availability flag rather than always showing it' {
            $script:Html | Should -BeLike '*if (!C.ExchangeFollowOnAvailable)*'
            $parsed = ([regex]::Match($script:Html, 'var REPORT_DATA = (?<json>.+?);</script>')).Groups['json'].Value | ConvertFrom-Json
            $parsed.Context.ExchangeFollowOnAvailable | Should -BeTrue
        }
    }

    Context 'HTML encoding of attacker controlled values' {

        It 'encodes angle brackets and quotes' {
            InModuleScope CredEcho {
                $encoded = Protect-CredEchoHtmlText '<img src=x onerror="alert(''p'')">'
                $encoded | Should -Not -BeLike '*<img*'
                $encoded | Should -BeLike '*&lt;img*'
                $encoded | Should -BeLike '*&quot;*'
                $encoded | Should -BeLike '*&#39;*'
                $encoded | Should -BeLike '*&gt;*'
            }
        }

        It 'encodes the ampersand so an entity cannot be smuggled through' {
            InModuleScope CredEcho {
                Protect-CredEchoHtmlText '&lt;script&gt;' | Should -Be '&amp;lt;script&amp;gt;'
            }
        }

        It 'returns an empty string for a null value rather than throwing' {
            InModuleScope CredEcho {
                Protect-CredEchoHtmlText $null | Should -Be ''
            }
        }

        It 'writes no unescaped attacker markup anywhere in the file' {
            $script:Html | Should -Not -BeLike '*<img src=x*'
            $script:Html | Should -Not -BeLike '*<script>fetch*'

            # The encoded form is asserted against the decoded payload rather than the raw file
            # text, because the two engines spell the same value differently on disk. Windows
            # PowerShell serialises through JavaScriptSerializer, which escapes the ampersand of
            # every HTML entity as a six character unicode escape, so the entity never appears
            # literally in the file. PowerShell 7 writes the entity as is. Both deliver the
            # identical string to the browser, so the decoded payload is the one assertion that
            # holds on both.
            $payload = ([regex]::Match($script:Html, 'var REPORT_DATA = (?<json>.+?);</script>')).Groups['json'].Value | ConvertFrom-Json
            $indicatorAgent = @($payload.Indicator.UserAgent) -join ' '
            $indicatorAgent | Should -BeLike '*&lt;img src=x*'
            $indicatorAgent | Should -Not -BeLike '*<img*'

            $rowAgent = @($payload.Account | ForEach-Object { $_.SignIn } | ForEach-Object { $_.UserAgent }) -join ' '
            $rowAgent | Should -BeLike '*&lt;img src=x*'
            $rowAgent | Should -Not -BeLike '*<img*'
        }

        It 'leaves exactly the two real closing script tags, so the payload closer was neutralised' {
            # The fixture user agent contains a literal closing script tag. If it survived intact
            # the data block would end early and the renderer would never run.
            ([regex]::Matches($script:Html, '(?i)</script')).Count | Should -Be 2
        }
    }

    Context 'File encoding and self-containment' {

        It 'writes the file without a byte order mark' {
            $bytes = [System.IO.File]::ReadAllBytes($script:ReportPath)
            $bytes[0] | Should -Be 0x3C
            ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) | Should -BeFalse
        }

        It 'contains no external resource element' {
            $script:Html | Should -Not -Match '(?i)<link\b'
            $script:Html | Should -Not -Match '(?i)<img\b'
            $script:Html | Should -Not -Match '(?i)<script\b[^>]*\bsrc\s*='
            $script:Html | Should -Not -Match '(?i)<iframe\b'
            $script:Html | Should -Not -Match '(?i)@import'
            $script:Html | Should -Not -Match '(?i)url\('
        }

        It 'carries exactly one absolute address, the footer link' {
            $urls = @([regex]::Matches($script:Html, 'https?://[^\s"''<>)]*') | ForEach-Object { $_.Value } | Sort-Object -Unique)
            $urls.Count | Should -Be 1
            $urls[0] | Should -Be 'https://soteria.io'
        }

        It 'inlines a stylesheet and the scripts' {
            ([regex]::Matches($script:Html, '(?i)<style\b')).Count | Should -Be 1
            ([regex]::Matches($script:Html, '(?i)<script\b')).Count | Should -Be 2
        }
    }

    Context 'Branding and structure' {

        It 'renders the wordmark in the sidebar, the print header, and the footer' {
            ([regex]::Matches($script:Html, 'class="brand-wordmark">CredEcho<')).Count | Should -Be 3
        }

        It 'carries the sub-line, the nav sub-tagline, and the footer tagline' {
            $script:Html | Should -BeLike '*by Soteria*'
            $script:Html | Should -BeLike '*POST-VALIDATION<br>ACCOUNT TRIAGE*'
            $script:Html | Should -BeLike '*Cybersecurity Expertise to Protect Your Digital Journey*'
        }

        It 'persists the theme under the expected key and follows the system preference first' {
            $script:Html | Should -BeLike "*localStorage.getItem('credecho-theme')*"
            $script:Html | Should -BeLike "*localStorage.setItem('credecho-theme'*"
            $script:Html | Should -BeLike '*prefers-color-scheme: dark*'
        }

        It 'uses the specified verdict colors and no substitute' {
            foreach ($hex in '#dc2626', '#ea580c', '#7c3aed', '#16a34a') {
                $script:Html | Should -BeLike "*$($hex)*"
            }
        }

        It 'uses the brand palette' {
            foreach ($hex in '#0a2540', '#061a30', '#1e5bb8', '#4a7fc8', '#60a5fa', '#cdd3f0', '#7a93bd', '#506988', '#123a66', '#0f2e52', '#1a1d2e') {
                $script:Html | Should -BeLike "*$($hex)*"
            }
        }

        It 'includes the six required structural components' {
            $script:Html | Should -BeLike '*<nav class="sidebar">*'
            $script:Html | Should -BeLike '*class="print-brand"*'
            $script:Html | Should -BeLike '*class="page-header"*'
            $script:Html | Should -BeLike '*id="theme-toggle"*'
            $script:Html | Should -BeLike '*id="account-list"*'
            $script:Html | Should -BeLike '*class="brand-footer"*'
        }

        It 'states the scope limitations in the report itself' {
            $script:Html | Should -BeLike '*investigative leads rather than proof*'
            $script:Html | Should -BeLike '*bounded by audit retention*'
            $script:Html | Should -BeLike '*floor, not a total*'
            $script:Html | Should -BeLike '*coarse proxy*'
            $script:Html | Should -BeLike '*unassessable, not clean*'
        }

        It 'expands every account card and hides the controls in print' {
            $script:Html | Should -BeLike '*.account-body { display: block !important; }*'
            $script:Html | Should -BeLike '*.print-brand { display: block !important;*'
        }

        It 'uses third-person organizational language' {
            $script:Html | Should -Not -Match '(?i)\byour tenant\b'
            $script:Html | Should -BeLike "*the organization's tenant*"
        }
    }

    Context 'Unique source and client pairings' {

        BeforeAll {
            # A separate fixture, because the shared one carries one sign-in per account and the
            # behaviour under test only appears once a pairing repeats. Eight sign-ins across three
            # distinct address and client pairings, deliberately out of chronological order, with the
            # highest tier sitting on a middle row so a naive first-wins would pick the wrong one.
            $agentChrome = 'Mozilla/5.0 (Windows NT 10.0) Chrome/146.0.0.0'
            $agentBroker = 'Windows-AzureAD-Authentication-Provider/1.0'

            $manyFlagged = @(
                [pscustomobject]@{ UserPrincipalName = 'noisy@contoso.com'; TimeStamp = '2026-06-20T10:00:00Z'
                    Tier = 'Possible'; Signal = @('FirstSeenSourceAddressWithMultifactor:Possible')
                    IpAddress = '203.0.113.9'; IpPrefix = '203.0.113.0/24'; UserAgent = $agentBroker
                    ApplicationId = 'dddd4444-4444-4444-4444-444444444444'; RecordId = 'n1'; ClientAppUsed = 'Browser'
                    ConditionalAccessStatus = 'success'; AuthenticationRequirement = 'multiFactorAuthentication'
                    AuthenticationProtocol = ''; RiskLevelDuringSignIn = ''; AutonomousSystemNumber = $null; Enriched = $true }
                [pscustomobject]@{ UserPrincipalName = 'noisy@contoso.com'; TimeStamp = '2026-06-18T08:00:00Z'
                    Tier = 'Possible'; Signal = @('FirstSeenSourceAddressWithMultifactor:Possible')
                    IpAddress = '203.0.113.9'; IpPrefix = '203.0.113.0/24'; UserAgent = $agentBroker
                    ApplicationId = 'dddd4444-4444-4444-4444-444444444444'; RecordId = 'n2'; ClientAppUsed = 'Browser'
                    ConditionalAccessStatus = 'success'; AuthenticationRequirement = 'multiFactorAuthentication'
                    AuthenticationProtocol = ''; RiskLevelDuringSignIn = ''; AutonomousSystemNumber = $null; Enriched = $true }
                # Same address, different client. This must not collapse into the rows above.
                [pscustomobject]@{ UserPrincipalName = 'noisy@contoso.com'; TimeStamp = '2026-06-19T09:00:00Z'
                    Tier = 'Probable'; Signal = @('LegacyClientApplication:Probable')
                    IpAddress = '203.0.113.9'; IpPrefix = '203.0.113.0/24'; UserAgent = $agentChrome
                    ApplicationId = 'dddd4444-4444-4444-4444-444444444444'; RecordId = 'n3'; ClientAppUsed = 'Other clients'
                    ConditionalAccessStatus = 'notApplied'; AuthenticationRequirement = 'singleFactorAuthentication'
                    AuthenticationProtocol = ''; RiskLevelDuringSignIn = ''; AutonomousSystemNumber = $null; Enriched = $true }
                # Same client, different address. Also must stay separate.
                [pscustomobject]@{ UserPrincipalName = 'noisy@contoso.com'; TimeStamp = '2026-06-21T07:00:00Z'
                    Tier = 'Confirmed'; Signal = @('SourceAddressSeenInValidationActivity:Confirmed')
                    IpAddress = '185.220.101.44'; IpPrefix = '185.220.101.0/24'; UserAgent = $agentBroker
                    ApplicationId = 'dddd4444-4444-4444-4444-444444444444'; RecordId = 'n4'; ClientAppUsed = 'Other clients'
                    ConditionalAccessStatus = 'notApplied'; AuthenticationRequirement = 'singleFactorAuthentication'
                    AuthenticationProtocol = 'ropc'; RiskLevelDuringSignIn = 'high'; AutonomousSystemNumber = $null; Enriched = $true }
                # A second signal on an existing pairing, so the union can be checked.
                [pscustomobject]@{ UserPrincipalName = 'noisy@contoso.com'; TimeStamp = '2026-06-22T07:30:00Z'
                    Tier = 'Confirmed'; Signal = @('ResourceOwnerPasswordCredentialsGrantSucceeded:Confirmed')
                    IpAddress = '185.220.101.44'; IpPrefix = '185.220.101.0/24'; UserAgent = $agentBroker
                    ApplicationId = 'dddd4444-4444-4444-4444-444444444444'; RecordId = 'n5'; ClientAppUsed = 'Other clients'
                    ConditionalAccessStatus = 'notApplied'; AuthenticationRequirement = 'singleFactorAuthentication'
                    AuthenticationProtocol = 'ropc'; RiskLevelDuringSignIn = 'high'; AutonomousSystemNumber = $null; Enriched = $true }
                # An unrecorded address and client. The pairing has to survive an empty key.
                [pscustomobject]@{ UserPrincipalName = 'noisy@contoso.com'; TimeStamp = '2026-06-23T07:30:00Z'
                    Tier = 'Possible'; Signal = @('NoveltyCouldNotBeAssessed:Possible')
                    IpAddress = ''; IpPrefix = ''; UserAgent = ''
                    ApplicationId = ''; RecordId = 'n6'; ClientAppUsed = ''
                    ConditionalAccessStatus = ''; AuthenticationRequirement = ''; AuthenticationProtocol = ''
                    RiskLevelDuringSignIn = ''; AutonomousSystemNumber = $null; Enriched = $false }
            )

            $noisyVerdict = @(
                [pscustomobject]@{ UserPrincipalName = 'noisy@contoso.com'; Verdict = 'Confirmed'
                    ConfirmedSignalCount = 2; ProbableSignalCount = 1; PossibleSignalCount = 3
                    DistinctSignal = @('SourceAddressSeenInValidationActivity:Confirmed')
                    FirstValidation = '2026-06-10T02:00:00Z'; LastValidation = '2026-06-10T02:00:00Z'
                    ValidationErrorCode = @('700016'); ValidationSourceAddress = @('185.220.101.44')
                    ValidationTimestampAssumed = $false; PostValidationSignInCount = 40; FlaggedSignInCount = 6
                    FollowOnActionCount = 0; BaselineAssessed = $true; BaselineSignInCount = 30
                    NoveltyAssessment = 'Assessed' }
            )

            $noisyFixture = [pscustomobject]@{
                Summary         = $script:Fixture.Summary
                AccountVerdict  = $noisyVerdict
                ValidationEvent = @($script:Fixture.ValidationEvent)
                FlaggedSignIn   = $manyFlagged
                FollowOnAction  = @()
            }

            $script:PairPath = Join-Path $TestDrive 'pairings\TriageReport.html'
            New-Item -Path (Split-Path $script:PairPath -Parent) -ItemType Directory -Force | Out-Null
            InModuleScope CredEcho -Parameters @{ Fixture = $noisyFixture; Target = $script:PairPath } {
                New-CredEchoHtmlReport -TriageResult $Fixture -Path $Target | Out-Null
            }
            $script:PairHtml = Get-Content -LiteralPath $script:PairPath -Raw
            $script:PairData = ([regex]::Match($script:PairHtml, 'var REPORT_DATA = (?<json>.+?);</script>')).Groups['json'].Value | ConvertFrom-Json
            $script:NoisyAccount = @($script:PairData.Account)[0]
        }

        It 'collapses repeated sign-ins into one row per address and client' {
            # Six sign-ins, four distinct pairings: the broker at 203.0.113.9, Chrome at the same
            # address, the broker at the attacker address, and the unrecorded pair.
            @($script:NoisyAccount.SignIn).Count | Should -Be 6
            $script:NoisyAccount.SourceClientCount | Should -Be 4
            @($script:NoisyAccount.SourceClient).Count | Should -Be 4
        }

        It 'accounts for every sign-in exactly once across the pairings' {
            $total = (@($script:NoisyAccount.SourceClient) | Measure-Object -Property SignInCount -Sum).Sum
            $total | Should -Be 6
            $total | Should -Be $script:NoisyAccount.FlaggedSignInCount
        }

        It 'keeps a shared address with different clients on separate rows' {
            $atAddress = @($script:NoisyAccount.SourceClient | Where-Object { $_.IpAddress -eq '203.0.113.9' })
            $atAddress.Count | Should -Be 2
            @($atAddress.UserAgent | Sort-Object -Unique).Count | Should -Be 2
        }

        It 'carries the highest tier any sign-in in the pairing earned' {
            $attacker = @($script:NoisyAccount.SourceClient | Where-Object { $_.IpAddress -eq '185.220.101.44' })[0]
            $attacker.Tier | Should -Be 'Confirmed'
            $attacker.SignInCount | Should -Be 2
        }

        It 'unions the signals of every sign-in in the pairing' {
            $attacker = @($script:NoisyAccount.SourceClient | Where-Object { $_.IpAddress -eq '185.220.101.44' })[0]
            @($attacker.Signal).Count | Should -Be 2
            $attacker.Signal | Should -Contain 'SourceAddressSeenInValidationActivity:Confirmed'
            $attacker.Signal | Should -Contain 'ResourceOwnerPasswordCredentialsGrantSucceeded:Confirmed'
        }

        It 'reports the true first and last sighting regardless of input order' {
            $broker = @($script:NoisyAccount.SourceClient | Where-Object { $_.IpAddress -eq '203.0.113.9' -and $_.UserAgent -like '*AzureAD*' })[0]
            $broker.FirstSeen | Should -Be '2026-06-18 08:00:00'
            $broker.LastSeen | Should -Be '2026-06-20 10:00:00'
        }

        It 'sorts the highest tier first so the worst pairing is never below the fold' {
            @($script:NoisyAccount.SourceClient)[0].Tier | Should -Be 'Confirmed'
        }

        It 'states an absent address and client rather than rendering an empty cell' {
            $blank = @($script:NoisyAccount.SourceClient | Where-Object { $_.SignInCount -eq 1 -and $_.Tier -eq 'Possible' })
            $blank.Count | Should -Be 1
            $blank[0].IpAddress | Should -Be 'not recorded'
            $blank[0].UserAgent | Should -Be 'not recorded'
        }

        It 'shows the pairing summary in the card and moves the per-event record behind the flyout' {
            $script:PairHtml | Should -BeLike '*Unique source and client pairings*'
            $script:PairHtml | Should -BeLike '*class="view-all"*'
            $script:PairHtml | Should -BeLike '*Every scored sign-in*'
        }

        It 'ships a flyout that is closed until asked for' {
            $script:PairHtml | Should -BeLike '*<aside id="flyout" hidden*'
            $script:PairHtml | Should -BeLike '*<div id="flyout-scrim" hidden>*'
            # An id selector beats the user agent [hidden] rule, so the closed state is explicit.
            $script:PairHtml | Should -BeLike '*#flyout[[]hidden], #flyout-scrim[[]hidden] { display: none; }*'
        }

        It 'prints the exhaustive record even though the screen hides it' {
            $script:PairHtml | Should -BeLike '*.full-detail { display: none; }*'
            $script:PairHtml | Should -BeLike '*.full-detail { display: block !important; }*'
            $script:PairHtml | Should -BeLike '*.detail-actions, #flyout, #flyout-scrim { display: none !important; }*'
        }

        It 'closes the flyout before printing so pagination is not locked' {
            $script:PairHtml | Should -BeLike "*addEventListener('beforeprint', closeFlyout)*"
        }

        It 'keeps the flyout free of external resources' {
            $script:PairHtml | Should -Not -Match '(?i)<(link|img|iframe|object|embed)\b'
        }
    }

    Context 'New-CredEchoReport round-trip' {

        BeforeAll {
            $script:JsonPath = Join-Path $TestDrive 'roundtrip\TriageResults.json'
            New-Item -Path (Split-Path $script:JsonPath -Parent) -ItemType Directory -Force | Out-Null
            $script:Fixture | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $script:JsonPath -Encoding UTF8
        }

        It 'renders beside the source data by default' {
            New-CredEchoReport -InputPath $script:JsonPath
            Join-Path (Split-Path $script:JsonPath -Parent) 'TriageReport.html' | Should -Exist
        }

        It 'produces the same account set as the direct render' {
            $written = New-CredEchoReport -InputPath $script:JsonPath -OutputPath (Join-Path $TestDrive 'roundtrip\Explicit.html') -PassThru
            $written | Should -Exist
            $roundTripped = Get-Content -LiteralPath $written -Raw
            $parsed = ([regex]::Match($roundTripped, 'var REPORT_DATA = (?<json>.+?);</script>')).Groups['json'].Value | ConvertFrom-Json
            @($parsed.Account).Count | Should -Be 4
            @($parsed.Account | ForEach-Object { $_.Verdict }) | Should -Be @('Confirmed', 'Probable', 'Possible', 'NoIndicators')
        }

        It 'keeps the attacker user agent encoded through the JSON round-trip' {
            $written = New-CredEchoReport -InputPath $script:JsonPath -OutputPath (Join-Path $TestDrive 'roundtrip\Encoded.html') -PassThru
            $roundTripped = Get-Content -LiteralPath $written -Raw
            $roundTripped | Should -Not -BeLike '*<img src=x*'

            # Decoded, for the reason given on the direct render assertion above.
            $payload = ([regex]::Match($roundTripped, 'var REPORT_DATA = (?<json>.+?);</script>')).Groups['json'].Value | ConvertFrom-Json
            $agent = @($payload.Indicator.UserAgent) -join ' '
            $agent | Should -BeLike '*&lt;img src=x*'
            $agent | Should -Not -BeLike '*<img*'
            ([regex]::Matches($roundTripped, '(?i)</script')).Count | Should -Be 2
        }

        It 'writes the round-tripped file without a byte order mark' {
            $written = New-CredEchoReport -InputPath $script:JsonPath -OutputPath (Join-Path $TestDrive 'roundtrip\NoBom.html') -PassThru
            $bytes = [System.IO.File]::ReadAllBytes($written)
            ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) | Should -BeFalse
        }

        It 'creates the output directory when it does not exist' {
            $target = Join-Path $TestDrive 'roundtrip\deeper\nested\Report.html'
            New-CredEchoReport -InputPath $script:JsonPath -OutputPath $target
            $target | Should -Exist
        }

        It 'throws a clear message for a missing file' {
            { New-CredEchoReport -InputPath (Join-Path $TestDrive 'absent.json') } |
                Should -Throw -ExpectedMessage '*TriageResults.json*'
        }

        It 'throws a clear message for a file that is not a triage result' {
            $wrong = Join-Path $TestDrive 'roundtrip\wrong.json'
            '{"something":"else"}' | Set-Content -LiteralPath $wrong -Encoding UTF8
            { New-CredEchoReport -InputPath $wrong } | Should -Throw -ExpectedMessage '*Summary*'
        }
    }
}
