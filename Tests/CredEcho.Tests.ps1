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

        It 'exports only the triage cmdlet' {
            @(Get-Command -Module CredEcho).Name | Should -Be 'Invoke-CredEchoTriage'
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
