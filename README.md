# CredEcho

CredEcho identifies Microsoft Entra ID accounts whose passwords were confirmed valid by an
attacker, then determines which of those accounts were subsequently accessed by someone other
than their owner.

CredEcho is read only. It produces investigative leads and nothing else.

## The technique it follows

An adversary submits a fabricated `client_id` to the Entra token endpoint using the Resource
Owner Password Credentials grant. Because the security token service returns different errors
depending on whether the username exists and whether the password is correct, the response
itself functions as a credential oracle. The attacker learns which stolen credentials remain
live without ever completing a sign-in, so no success-based alert fires.

The consequence for a defender is the part that matters. Enumeration of this kind is often
noticed, and the accounts whose credentials were actually confirmed are not, because nothing in
the tenant recorded a successful authentication. CredEcho exists to close that gap.

## Error code classes

Two classes of error are relevant, and the distinction between them is the whole detection.

| Code | Name | Class | Confidence |
| --- | --- | --- | --- |
| 50126 | InvalidUserNameOrPassword | Username oracle | Documented |
| 50034 | UserAccountNotFound | Username oracle | Documented |
| 50053 | IdsLocked | Username oracle | Inferred |
| 53003 | BlockedByConditionalAccess | Post-password | Documented |
| 50158 | ExternalSecurityChallengeNotSatisfied | Post-password | Documented |
| 50076 | UserStrongAuthClientAuthNRequired | Post-password | Documented |
| 50079 | UserStrongAuthEnrollmentRequired | Post-password | Documented |
| 700016 | UnauthorizedClient_DoesNotMatchRequest | Post-password | Observed |
| 50055 | InvalidPasswordExpiredPassword | Post-password | Ambiguous |

Only post-password events produce triage targets. Username oracle events are counted and
reported as campaign context, because they establish the scale of the probing, but the accounts
they name are not triaged. An account that produced only 50126 was probed and not validated, and
including it buries the real leads.

The confidence column is not decoration. Microsoft documents what each of these codes means. It
does not document the order in which the security token service evaluates a request, so the
post-password classification rests on different evidence from code to code:

- **Documented.** Microsoft states that Conditional Access is enforced after first factor
  authentication completes, and multifactor authentication is by definition a second factor.
  Reaching one of these codes means the submitted password validated.
- **Observed.** Independent research published in July 2026 documented that 700016 is returned
  for a valid username and password in this flow, and offensive tooling has independently
  treated it the same way. Microsoft has never committed to this ordering, so treat it as current
  implementation behavior rather than a contract.
- **Ambiguous.** Microsoft's own password spray detection content classifies 50055 both as a
  failure code and as a success code. Leads derived from it are the weakest in the set.
- **Inferred.** Smart lockout and malicious address blocks short-circuit the credential check, so
  50053 is treated as a username oracle. Microsoft does not document the ordering.

Every validation event in the output carries its `ErrorConfidence`, so a weak lead is visibly
weak. Both tables are exposed as parameters, so an analyst can add the further codes that
Microsoft password spray analytics also treat as post-password, including 50072, 50057, 50155,
50105, and 53000, without editing code.

## Evidence source

CredEcho reads the unified audit log through the Microsoft Graph AuditLogQuery API. It does not
use Entra sign-in logs as the primary source, and it does not use `Search-UnifiedAuditLog`.

- Entra sign-in logs retain only 30 days on Entra ID P1 and P2, which is useless for a campaign
  that ran for months.
- Microsoft Entra audit records are retained 180 days under Purview Audit Standard, and one year
  by default for users licensed for E5 or the Purview Suite. Records for guest users and
  unlicensed users fall back to 180 days.
- `Search-UnifiedAuditLog` has documented completeness problems. Its `HighCompleteness` switch
  exists because the default query, in Microsoft's words, "might have missing search results."
  Microsoft's best practices guidance for the cmdlet states that "the returned data might contain
  duplicate records." Switching `SessionCommand` values on one `SessionId` silently caps output at
  10,000 results.

Every query is sliced into configurable chunks, 30 days by default, because a single audit log
query over a long range returns unreliable volumes and the Purview audit search documentation
caps a search at a 180 day range. Records are deduplicated by identifier across chunk boundaries.

## Requirements

- PowerShell 5.1 or later, on Windows PowerShell or PowerShell 7.
- `Microsoft.Graph.Authentication` version 2.0.0 or later. CredEcho does not take a dependency on
  the full `Microsoft.Graph` meta-module.
- An existing Microsoft Graph connection. CredEcho does not call `Connect-MgGraph` on the
  caller's behalf. It validates the context that is already present and throws a message naming
  the missing scope.

## Required scopes

| Scope | Purpose |
| --- | --- |
| `AuditLogsQuery-Entra.Read.All` | Sign-in and directory audit records. Least privilege. |
| `AuditLogsQuery.Read.All` | Broad alternative to the above, covering every workload. |
| `AuditLogsQuery-Exchange.Read.All` | Inbox rule and mailbox follow-on actions in phase three. |
| `Application.Read.All` | Service principal enumeration for the application registration test. |
| `AuditLog.Read.All` | Sign-in log enrichment only. |

`Application.Read.All` is sufficient for the service principal enumeration. It is the documented
least privileged permission for `GET /servicePrincipals`, for both delegated and application
permission types. `Directory.Read.All` is listed only as a higher privileged alternative and is
not required.

`AuditLogsQuery-Entra.Read.All` is the documented least privileged permission on both the create
query and the list records operations. `AuditLogsQuery.Read.All` is documented as the higher
privileged option, so prefer the Entra scoped variant unless a run needs workloads beyond Entra
and Exchange.

Phase three degrades rather than failing when the Exchange scope is absent: directory audit
actions are still collected, a warning states what was skipped, and the summary records
`ExchangeFollowOnAvailable` as false.

## Installation

Clone the repository and import the manifest.

```powershell
git clone https://github.com/soteria-security/CredEcho.git
Import-Module ./CredEcho/CredEcho.psd1
```

## Usage

```powershell
Connect-MgGraph -Scopes 'AuditLogsQuery-Entra.Read.All', 'AuditLogsQuery-Exchange.Read.All', 'Application.Read.All'
Invoke-CredEchoTriage -OutputDirectory 'C:\Cases\1042'
```

With enrichment and the stronger corroboration control:

```powershell
Connect-MgGraph -Scopes 'AuditLogsQuery-Entra.Read.All', 'AuditLogsQuery-Exchange.Read.All', 'Application.Read.All', 'AuditLog.Read.All'
Invoke-CredEchoTriage -OutputDirectory 'C:\Cases\1042' -IncludeSignInEnrichment -TenantWideCorroboration -Verbose
```

When the validation events have already aged out and the indicators come from outside the tool:

```powershell
Invoke-CredEchoTriage -OutputDirectory 'C:\Cases\1042' `
    -Account 'jdoe@contoso.com', 'asmith@contoso.com' `
    -AttackerIpAddress '185.220.101.44' `
    -AttackerUserAgent 'python-requests/2.32.3'
```

Both analyst overrides supplement phase one rather than replacing it. When an account is supplied
with no derivable validation timestamp, the start of the search window is used and the output
records `ValidationTimestampAssumed` as true.

Run `Get-Help Invoke-CredEchoTriage -Full` for the complete parameter set.

## How it works

### Phase one: detect the validation events

CredEcho derives its own target list. It does not accept a findings file from anything else.

1. Query the unified audit log for `UserLoginFailed` operations under record type
   `azureActiveDirectoryStsLogon` across the search window.
2. Keep records whose error code falls in the post-password class, meaning the submitted password
   validated.
3. Of those, keep records whose application identifier does not correspond to a service principal
   in the tenant. These are the validation events.

The unified audit log carries no application display name, so the registration test runs against
the application identifier alone. Two false positive controls guard it, because some legitimate
Microsoft first party applications have no service principal object provisioned in a given
tenant:

- **Tenant-wide corroboration.** An application identifier observed in successful sign-ins across
  three or more distinct accounts during the baseline period is treated as legitimate regardless
  of whether a service principal exists. The threshold is the
  `-CorroborationAccountThreshold` parameter.
- **Explicit allowlist.** The `-AllowedApplicationId` parameter carries identifiers to exclude, so
  an analyst can suppress a known internal client without editing code.

The count of identifiers suppressed by each control is reported in the summary and in
`TriageResults.json`, so the suppression is visible rather than silent.

A client identifier that is not a well formed GUID is not recorded in the application identifier
field at all. Records with an empty application identifier are therefore retained as validation
events, because a test against an absent value cannot clear them.

### Phase two: score subsequent access

Flagging every successful sign-in after the validation timestamp would flag every active user in
the tenant, because the legitimate owner also signs in. CredEcho scores baseline-relative novelty
instead. Three windows are built per account:

- **Baseline.** A configurable period, 90 days by default, ending immediately before that
  account's first validation event. Establishes known source addresses, network prefixes, user
  agents, and client application identifiers.
- **Validation window.** Yields the attacker indicators: source addresses, network prefixes, and
  user agents.
- **Post-validation window.** Every successful sign-in from the validation timestamp forward,
  scored against both of the above.

An account with no baseline activity produces an explicit `NoveltyCouldNotBeAssessed` signal and a
`NoveltyAssessment` explaining why, rather than a false clean result.

| Signal | Tier |
| --- | --- |
| Successful sign-in from a source address seen in validation activity | Confirmed |
| Successful sign-in with a user agent seen in validation activity | Confirmed |
| Non-browser client string, for example `python-requests`, `curl/`, `Go-http-client`, `okhttp`, or `libwww` | Confirmed |
| Resource Owner Password Credentials grant succeeded | Confirmed |
| Successful sign-in from a network prefix seen in validation activity | Probable |
| First-seen network prefix for the account with no multifactor authentication satisfied | Probable |
| Conditional Access status of `notApplied` or `failure` on a success | Probable |
| Legacy client application on a success | Probable |
| Entra ID Protection risk level of low, medium, or high | Probable |
| First-seen source address only, with multifactor authentication satisfied | Possible |

Account-level verdicts are Confirmed, Probable, Possible, and NoIndicators. Any Confirmed-tier
sign-in makes the account Confirmed. A follow-on persistence action combined with any flagged
sign-in also makes the account Confirmed.

The unified audit log carries no autonomous system number and no geolocation, so infrastructure
novelty falls back to an IPv4 /24 or IPv6 /48 prefix. This is a coarse proxy and it is scored
accordingly: a large hosting provider or a carrier grade NAT range will place unrelated traffic in
the same prefix, so prefix matches score one tier below exact address matches, and a prefix signal
is suppressed when the exact address already matched.

Six of the ten signals require sign-in log enrichment, because multifactor authentication state,
Conditional Access result, client application, risk level, and authentication protocol do not
exist in the unified audit log. Without `-IncludeSignInEnrichment`, a first-seen address is
reported as `FirstSeenSourceAddressMultifactorUnknown` rather than being asserted either way.

### Phase three: follow-on persistence actions

Actions taken after the earliest validation event, across record types `azureActiveDirectory`,
`exchangeAdmin`, and `exchangeItem`. Coverage includes authentication method registration,
password resets, role additions, application consent and OAuth2 permission grants, service
principal credential additions, inbox rule creation and modification, mailbox forwarding, mailbox
permission grants, and transport rule changes.

These are collected regardless of the sign-in verdict, since an actor who validated a credential
months ago and registered their own authenticator remains visible in the directory audit log after
the corresponding sign-in record has aged out.

## Output artifacts

Written to the directory given by `-OutputDirectory`. The delimiter for the delimited files is a
semicolon by default and is exposed as the `-Delimiter` parameter. Every file is written even when
it has no rows, because an empty artifact and a missing artifact mean different things.

| File | Contents |
| --- | --- |
| `AccountVerdicts.csv` | One row per triaged account, sorted with Confirmed first. |
| `ValidationEvents.csv` | The phase one detections with their error codes and application identifiers. |
| `FlaggedSignIns.csv` | One row per scored sign-in with its signal list. |
| `FollowOnActions.csv` | The phase three persistence actions. |
| `TriageResults.json` | A structured summary suitable for downstream report rendering. |

This repository generates no HTML.

## Limitations

- **Read only, by design.** CredEcho performs no remediation. There is no password reset, no token
  revocation, no session invalidation, and no blocking anywhere in this module. Output is
  investigative leads only. Acting on those leads is a separate, deliberate decision.
- **The 700016 classification is observed, not documented.** See the confidence discussion above.
- **Retention bounds everything.** A campaign older than the tenant's audit retention is invisible.
  Phase three exists because directory audit evidence of persistence outlives the sign-in evidence
  of access.
- **Enrichment reaches 30 days only.** An absent enrichment match is not evidence of anything.
- **Corroboration scope.** Without `-TenantWideCorroboration`, the corroboration corpus is limited
  to the accounts already under triage. That suppresses fewer identifiers than a genuine
  tenant-wide count would, which leaves more false positives in the output rather than fewer. The
  summary records which scope was used.
- **Cloud availability.** The AuditLogQuery API is documented as available in the global service
  only, and not in the US Government or 21Vianet clouds.
- **Query volume.** A large validated-account set produces many audit log queries, since account
  filters are chunked. Runs against a wide campaign take time.

## Repository layout

```
CredEcho/
  CredEcho.psd1
  CredEcho.psm1
  Public/
    Invoke-CredEchoTriage.ps1
  Private/
    Get-CredEchoAuditRecord.ps1
    Get-CredEchoValidationEvent.ps1
    Get-CredEchoKnownApplication.ps1
    ConvertFrom-CredEchoLogonRecord.ps1
    Get-CredEchoIpPrefix.ps1
    Get-CredEchoSignInEnrichment.ps1
    Test-CredEchoGraphContext.ps1
    Export-CredEchoResult.ps1
  Tools/
    Probe-AuditDataCasing.ps1
  Tests/
    CredEcho.Tests.ps1
  .github/workflows/ci.yml
```

The public surface is a single cmdlet, `Invoke-CredEchoTriage`. Everything else is private.

`Tools/Probe-AuditDataCasing.ps1` pulls one audit record from a live tenant and dumps its
`auditData` node, reporting the .NET type of each node, the exact key casing as returned, whether
lookups are case sensitive, and the shape of `ExtendedProperties`. The documented schema is one
thing, and how PascalCase property names survive deserialization through `Invoke-MgGraphRequest`
is another. Run the probe before trusting the flattening layer against an unfamiliar tenant.

## Development

```powershell
Invoke-ScriptAnalyzer -Path . -Recurse
Invoke-Pester -Path ./Tests
```

The test suite mocks every Graph call. No test touches a live tenant. Continuous integration runs
the parser over every file, imports the module and checks the public surface, then runs
PSScriptAnalyzer and Pester on both PowerShell 7 and Windows PowerShell 5.1, on push and on pull
request.

## License

Copyright (c) 2026 Soteria LLC. All rights reserved.

[LICENSE]

A license has not been selected. See the `LICENSE` file.
