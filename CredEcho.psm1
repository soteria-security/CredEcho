# CredEcho module loader.

foreach ($folder in 'Private', 'Public') {
    $folderPath = Join-Path -Path $PSScriptRoot -ChildPath $folder
    if (Test-Path -LiteralPath $folderPath) {
        foreach ($file in Get-ChildItem -LiteralPath $folderPath -Filter '*.ps1' -File) {
            . $file.FullName
        }
    }
}

<#
Error code classes.

Verified against the Microsoft Entra authentication and authorization error codes reference
at https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes. The
descriptions of these codes are documented. The order in which the security token service
evaluates a request is not, so each code also carries a confidence value that says how far
the post-password classification can be defended:

  Documented  Microsoft states that Conditional Access and multifactor authentication are
              evaluated after first factor authentication completes, so reaching one of
              these codes means the submitted password validated.
  Observed    Independent research observed the behavior and Microsoft has never committed
              to it. Treat as current implementation behavior, not a contract.
  Ambiguous   Microsoft's own detection content classifies the code both ways. Leads derived
              from it are the weakest in the set.

Both tables are exposed as parameters on Invoke-CredEchoTriage so an analyst can add the
codes Microsoft's password spray analytics also treat as post-password, including 50072,
50057, 50155, 50105, and 53000, without editing this file.
#>

$script:CredEchoUsernameOracleError = @{
    '50126' = 'InvalidUserNameOrPassword'
    '50034' = 'UserAccountNotFound'
    '50053' = 'IdsLocked'
}

$script:CredEchoPostPasswordError = @{
    '700016' = 'UnauthorizedClient_DoesNotMatchRequest'
    '50076'  = 'UserStrongAuthClientAuthNRequired'
    '50079'  = 'UserStrongAuthEnrollmentRequired'
    '50158'  = 'ExternalSecurityChallengeNotSatisfied'
    '53003'  = 'BlockedByConditionalAccess'
    '50055'  = 'InvalidPasswordExpiredPassword'
}

$script:CredEchoErrorConfidence = @{
    '53003'  = 'Documented'
    '50158'  = 'Documented'
    '50076'  = 'Documented'
    '50079'  = 'Documented'
    '700016' = 'Observed'
    '50055'  = 'Ambiguous'
}

$script:CredEchoStsRecordType = 'azureActiveDirectoryStsLogon'

$script:CredEchoFollowOnRecordType = @('azureActiveDirectory', 'exchangeAdmin', 'exchangeItem')

# Two Entra operation names contain an en dash that Microsoft assigned, so the character is
# built from its code point rather than typed, which keeps dash characters out of the source
# while still matching the operation exactly.
$script:CredEchoFollowOnOperation = [ordered]@{
    'Add strong authentication method'                                                  = 'AuthenticationMethodRegistration'
    'Delete strong authentication method'                                               = 'AuthenticationMethodRegistration'
    'User registered security info'                                                     = 'AuthenticationMethodRegistration'
    'Admin registered security info'                                                    = 'AuthenticationMethodRegistration'
    'User changed default security info'                                                = 'AuthenticationMethodRegistration'
    'User deleted security info'                                                        = 'AuthenticationMethodRegistration'
    'Reset user password'                                                               = 'PasswordReset'
    'Change user password'                                                              = 'PasswordReset'
    'Reset password (self-service)'                                                     = 'PasswordReset'
    'Add member to role'                                                                = 'RoleAssignment'
    'Add eligible member to role'                                                       = 'RoleAssignment'
    'Add member to role outside of PIM (permanent)'                                     = 'RoleAssignment'
    'Add member to role in PIM completed (timebound)'                                   = 'RoleAssignment'
    'Consent to application'                                                            = 'ApplicationConsent'
    'Add app role assignment to service principal'                                      = 'ApplicationConsent'
    'Add app role assignment grant to user'                                             = 'ApplicationConsent'
    'Add OAuth2PermissionGrant'                                                         = 'OAuth2PermissionGrant'
    'Add delegated permission grant'                                                    = 'OAuth2PermissionGrant'
    'Add service principal'                                                             = 'ServicePrincipalChange'
    'Add service principal credentials'                                                 = 'ServicePrincipalCredential'
    "Update application $([char]0x2013) Certificates and secrets management"             = 'ServicePrincipalCredential'
    "Update service principal $([char]0x2013) Certificates and secrets management"       = 'ServicePrincipalCredential'
    'New-InboxRule'                                                                     = 'InboxRule'
    'Set-InboxRule'                                                                     = 'InboxRule'
    'Enable-InboxRule'                                                                  = 'InboxRule'
    'UpdateInboxRules'                                                                  = 'InboxRule'
    'Set-Mailbox'                                                                       = 'MailboxConfiguration'
    'Set-MailboxAutoReplyConfiguration'                                                  = 'MailboxConfiguration'
    'Add-MailboxPermission'                                                             = 'MailboxPermission'
    'Add-RecipientPermission'                                                           = 'MailboxPermission'
    'Add-MailboxFolderPermission'                                                       = 'MailboxPermission'
    'New-TransportRule'                                                                 = 'TransportRule'
    'Set-TransportRule'                                                                 = 'TransportRule'
    'Enable-TransportRule'                                                              = 'TransportRule'
}

# Sign-in log client application values that are not legacy. Anything else that the sign-in
# log reports is a legacy authentication client.
$script:CredEchoModernClientApp = @('Browser', 'Mobile Apps and Desktop clients')

# Client strings that no interactive user produces. A success carrying one of these is a
# script, not a person at a keyboard.
$script:CredEchoNonBrowserAgent = @(
    'python-requests'
    'python-urllib'
    'curl/'
    'Go-http-client'
    'okhttp'
    'libwww'
    'axios/'
    'node-fetch'
    'aiohttp'
    'restsharp'
    'httpx'
    'powershell'
    'wget'
)

Export-ModuleMember -Function 'Invoke-CredEchoTriage'
