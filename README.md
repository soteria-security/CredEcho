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

Adding the branded HTML report:

```powershell
Invoke-CredEchoTriage -OutputDirectory 'C:\Cases\1042' -IncludeHtmlReport
```

With enrichment, the stronger corroboration control, and the report:

```powershell
Connect-MgGraph -Scopes 'AuditLogsQuery-Entra.Read.All', 'AuditLogsQuery-Exchange.Read.All', 'Application.Read.All', 'AuditLog.Read.All'
Invoke-CredEchoTriage -OutputDirectory 'C:\Cases\1042' -IncludeSignInEnrichment -TenantWideCorroboration -IncludeHtmlReport -Verbose
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

#### What Confirmed actually asserts

Confirmed is a triage priority, not a finding of abuse. It means the post-validation activity for
that account matches the activity this attack produces, so the account goes to the front of the
queue. It does not assert that an intruder used the account, and it says nothing at all about what
was accessed, read, or taken.

The tier name describes what was confirmed, and what was confirmed is the pattern match, not the
compromise. Every signal in the Confirmed tier has a benign explanation available:

- A shared egress address puts the legitimate owner and the attacker on the same source address. A
  corporate VPN concentrator, an office NAT gateway, or a mobile carrier range will do this.
- A non-browser client string can be the account's own automation, a monitoring job, or a scheduled
  PowerShell task rather than an adversary.
- A Resource Owner Password Credentials success can be a legacy line of business application that
  legitimately uses the flow.
- A follow-on persistence action can be the user genuinely enrolling a new authenticator, or an
  administrator resetting the password in response to the incident itself.

Stating that the evidence is consistent with the attack is the strongest claim retained audit data
supports on its own. Deciding whether the account was actually abused requires an analyst, and in a
regulatory or contractual context it requires an incident commander and counsel. CredEcho ranks the
queue. It does not adjudicate it.

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
| `TriageResults.json` | A structured summary, and the input to the report renderer. |
| `TriageReport.html` | The branded report. Written only when `-IncludeHtmlReport` is specified. |

## Reporting

`-IncludeHtmlReport` writes `TriageReport.html` alongside the delimited files. `New-CredEchoReport`
renders the same report from a saved `TriageResults.json`, so the presentation can be regenerated
without querying the tenant again.

```powershell
New-CredEchoReport -InputPath 'C:\Cases\1042\TriageResults.json'
New-CredEchoReport -InputPath 'C:\Cases\1042\TriageResults.json' -OutputPath 'C:\Cases\1042\Deliverables\AccountTriage.html' -PassThru
```

### Self-contained by design

The generated file opens from a file URI with networking disabled. There is no external
stylesheet, no web font, no content delivery network script, no image file, and no dependency on
any path outside the module. The stylesheet and both script blocks are inlined, the triage data is
injected as a single JSON object, and vanilla JavaScript renders the account list and drives the
filters. The only absolute address in the file is the footer link.

Values that originate in tenant data are encoded before they reach the page. User agent strings
are attacker controlled and do arrive carrying angle brackets, quotes, and closing tags, so they
are encoded rather than trusted, and they render as literal text.

The report carries a sidebar with section and verdict navigation, a verdict summary strip, an
engagement context strip, a scope and limitations panel, an attacker indicator panel, and one
expandable card per account. Filters cover the four verdict tiers and a free-text search across user
principal name, source address, user agent, and follow-on target object, with a live count of
accounts shown. A theme toggle follows the system preference on first load and then persists the
choice.

#### Summary in the card, detail in the flyout

An expanded card is a summary, not a dump. It shows the validation error codes with the basis on
which each was classified, a table of unique source address and client pairings, the follow-on
actions, and the distinct signals for the account.

The pairing table is the change that keeps the card readable. An account an adversary hammered
produces hundreds of scored sign-ins that mostly repeat the same address and the same client, and a
row-per-event table buries the shape of the activity in a list nobody scrolls. One test account
produced 132 scored sign-ins across nine pairings. The table collapses to one row per address and
client pairing, carrying the sign-in count, the first and last sighting, the highest tier any sign-in
in the pairing earned, and the union of their signals.

Three properties of that collapse matter:

- **The counts reconcile.** The sign-in counts across the pairings sum to the account's flagged
  sign-in total, so the summary can be read as complete rather than sampled.
- **Severity never drops.** A pairing carries the highest tier any of its sign-ins earned, so
  collapsing rows cannot lower what a reader sees, and the highest tier sorts first.
- **Absent values are stated.** Where the audit record carried no address or no user agent, the cell
  says so rather than rendering empty.

A **View all details** button opens a flyout carrying the exhaustive record: the timeline, every
individual scored sign-in, and the follow-on actions. Escape, the close button, or a click outside
dismisses it.

That detail is not fetched or rebuilt. It is authored once into a hidden node inside the card, and
the flyout renders a copy of that same node, so the card, the flyout, and the printed page cannot
disagree with each other. The same node is what makes the PDF complete, as described under Print and
PDF below.

Three further details in the layout exist because their absence made the report read as more complete
than it was.

**Follow-on actions name their target object.** The table reports the timestamp, operation,
category, target object, and source address. An operation alone states that something was created
without stating what, which is the part an analyst acts on. The target object is the rule, the
forwarding address, or the role, and it is searchable. Where the audit record carried no target,
the cell states that rather than rendering empty.

**Error codes are reported with the basis for their classification.** Each code appears with its
name, its confidence tier, and how many validation events carried it, alongside a note explaining
that Documented means Microsoft states the check runs after the password is verified, Observed means
the behavior is reported by third-party research rather than documented, and Ambiguous means
Microsoft categorizes the code inconsistently. The same annotation appears on each account card. A
code an account cites that no retained validation event names still appears, with no basis claimed.

**Coverage gaps are stated where they apply.** Where the Exchange record types were unavailable in
the collection, an additional limitation is appended to the scope panel saying that inbox rules,
forwarding changes, mailbox permission grants, and transport rules were not evaluated, so the
follow-on section is not read as complete when it is not.

### Print and PDF

Use the browser print dialog to produce a PDF. The sidebar, export bar, theme toggle, and filter
controls are hidden, a brand header appears on page one, every account card is expanded so no
finding is lost inside a collapsed panel, page breaks are avoided inside a card where practical,
and dark mode backgrounds are reset to white so the PDF renders on white regardless of the active
theme.

The detail that the screen hides behind the flyout is printed in full. A reader cannot click a button
on paper, so the hidden detail node becomes visible for print and the flyout controls disappear:
the PDF carries the pairing summary and every individual sign-in, and no finding is trapped behind an
interaction the medium does not support. A print started while the flyout is open closes it first, so
pagination is never computed against a locked page.

### Verdict ladder

The same four tiers appear in the summary strip, the filter chips, the sidebar, and the account
sort order. All four cards render even at a count of zero, so the reader sees the complete picture.

| Verdict | Color | Meaning |
| --- | --- | --- |
| Confirmed | `#dc2626` | Post-validation activity matches the attack pattern. Investigate first. Not a finding of compromise. |
| Probable | `#ea580c` | Anomalous against baseline, short of a direct indicator match. |
| Possible | `#7c3aed` | Unresolved rather than lesser. Requires analyst triage. |
| NoIndicators | `#16a34a` | No anomalous post-validation access found within the retained window. |

Possible is deliberately violet rather than amber. It is not a lesser severity claim, it is an
unresolved one. Blue is reserved for the brand accent and is never used for a verdict.

`Docs/Reading-The-Verdicts.md` explains the ladder for executives and non-technical reviewers. It
covers what a verdict does and does not assert, why Confirmed is not a compromise ruling, why No
Indicators is not a clean result, the four annotations that override the verdict at face value, and
the questions worth asking in a review meeting. Hand it to the client alongside the report.

## Limitations

- **Read only, by design.** CredEcho performs no remediation. There is no password reset, no token
  revocation, no session invalidation, and no blocking anywhere in this module. Output is
  investigative leads only. Acting on those leads is a separate, deliberate decision.
- **Confirmed is a priority, not a ruling.** No verdict in this tool determines that an account was
  abused. Confirmed states that the retained evidence for an account is consistent with the pattern
  this attack produces, which means investigate it first. It is not a compromise finding, it is not
  a breach determination, and it must not be reported to a client, a regulator, or an insurer as
  either. See the earlier discussion of what Confirmed asserts.
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
    New-CredEchoReport.ps1
  Private/
    Get-CredEchoAuditRecord.ps1
    Get-CredEchoValidationEvent.ps1
    Get-CredEchoKnownApplication.ps1
    ConvertFrom-CredEchoLogonRecord.ps1
    Get-CredEchoIpPrefix.ps1
    Get-CredEchoSignInEnrichment.ps1
    Test-CredEchoGraphContext.ps1
    Export-CredEchoResult.ps1
    New-CredEchoHtmlReport.ps1
  Docs/
    Reading-The-Verdicts.md
  Tools/
    Probe-AuditDataCasing.ps1
  Tests/
    CredEcho.Tests.ps1
  .github/workflows/ci.yml
```

The public surface is two cmdlets, `Invoke-CredEchoTriage` for collection and
`New-CredEchoReport` for rendering a saved result. Everything else is private.

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
