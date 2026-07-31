@{
    RootModule           = 'CredEcho.psm1'
    ModuleVersion        = '1.0.0'
    GUID                 = 'cf08803a-b3f3-4b0d-a697-b80e14013db0'
    Author               = 'Soteria LLC'
    CompanyName          = 'Soteria LLC'
    Copyright            = '(c) 2026 Soteria LLC. All rights reserved.'

    Description          = 'Identifies Microsoft Entra ID accounts whose passwords an attacker confirmed valid through the token endpoint error response, then scores which of those accounts were subsequently accessed by someone other than their owner. Read only, and produces investigative leads only.'

    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')

    RequiredModules      = @(
        @{ ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '2.0.0' }
    )

    FunctionsToExport    = @('Invoke-CredEchoTriage', 'New-CredEchoReport')
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()

    PrivateData          = @{
        PSData = @{
            Tags         = @('Security', 'EntraID', 'AzureAD', 'IncidentResponse', 'AuditLog', 'DFIR', 'Microsoft365')
            ProjectUri   = 'https://github.com/soteria-security/CredEcho'
            ReleaseNotes = 'Initial release.'
        }
    }
}
