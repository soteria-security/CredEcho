# Reading the Verdicts

A guide for executives, business owners, and reviewers who are not security analysts.

This document explains how to read the CredEcho Post-Validation Account Triage report. It assumes
no knowledge of authentication protocols, audit logs, or Microsoft Entra ID.

---

## Start here: what the report is actually telling you

An attacker obtained a list of usernames and passwords for your organization, most likely from a
password reuse breach, a phishing page, or malware on a personal device. Rather than trying to sign
in with each one, which would have raised alarms, the attacker used a technique that asks Microsoft
a quieter question: *is this password still valid?* Microsoft answered. No successful sign-in was
recorded, so no alert fired.

**Every account listed in this report is one where the answer came back yes.** The attacker holds a
password that works. That is already established before any verdict is assigned.

The verdict answers a different and separate question:

> Once the attacker knew the password worked, is there evidence that someone actually used it?

Two questions, two answers. The first one is settled for every account in the report. The verdict
grades the second one.

An analogy. A burglar walks down a street trying a stolen key in every door and notes which doors it
unlocks. The report lists the doors where the key turned. The verdict states how much evidence there
is that someone then walked in.

---

## The four verdicts

| Verdict | Plain reading | What the evidence shows |
| --- | --- | --- |
| **Confirmed** | Investigate this one first. | Activity after the password was tested matches the pattern this attack produces. It came from the same internet address or the same automated tooling the attacker used, or the account was signed into by an automated method a real person does not use, or a persistence change was made alongside suspicious access. |
| **Probable** | Something is wrong with this account. | Activity after the password was tested does not match how this account normally behaves, but it does not carry the attacker's exact fingerprints. Examples include access from an unfamiliar part of the internet without multifactor authentication, access flagged as risky by Microsoft, or access using outdated software that bypasses modern protections. |
| **Possible** | Not resolved. Someone has to look. | There is one unexplained detail, and the available evidence cannot settle it either way. This is not a lesser finding. It is an open question. |
| **No Indicators** | No evidence of misuse was found in the records that still exist. | Nothing anomalous was found after the password was tested, within the period the logs cover. |

The report colors Possible violet rather than yellow or amber on purpose. Amber reads as "a little
bit bad," and that is the wrong reading. Possible means unresolved, and an unresolved account can
turn out to be the worst one in the report once someone looks at it.

---

## What Confirmed does not mean

**Confirmed is not a ruling that the account was compromised.**

It is a priority. Confirmed means the activity on the account after the password was tested matches
the activity this kind of attack produces, so this is the account to look at first. What has been
confirmed is the match to the attack pattern. Whether the account was actually misused is the
question the investigation answers, and this report does not answer it.

The distinction is not a technicality. Every piece of evidence behind a Confirmed verdict has an
innocent explanation that is entirely possible:

- **Shared internet addresses.** The report matches on the address the attacker used. If the office
  network, the corporate virtual private network, or a mobile carrier puts many people behind one
  shared address, the legitimate owner of the account can appear at the same address as the attacker
  with no connection between them.
- **Automated sign-ins.** The report flags sign-ins made by software rather than a person at a
  keyboard. That software may be the organization's own script, a monitoring tool, or a scheduled job.
- **Older sign-in methods.** The report flags an older authentication method that attackers favor. A
  legitimate older business application may use the same method.
- **Security changes made afterward.** The report flags actions such as registering a new
  authentication app. The account owner may have done that themselves, or the help desk may have done
  it in response to this very incident.

An analyst can usually resolve each of these quickly once they look at the account. Until someone
looks, the verdict says exactly what it says: this account is the highest priority to examine, and
the evidence is consistent with the attack.

Two consequences worth stating plainly.

**Do not report a Confirmed count as a number of compromised accounts.** It is a number of accounts
requiring urgent investigation. Those are different figures, and the second is normally larger than
the first.

**Do not treat Confirmed as a breach determination.** Whether an incident triggers notification
obligations under contracts, regulation, or an insurance policy is a decision for the incident
commander and counsel, informed by the completed investigation. It is not something a tool decides
from audit logs.

---

## What No Indicators does not mean

**No Indicators does not mean safe.**

It means the attacker holds a working password for that account, and no one appears to have used it
yet within the window the logs cover. The password is still compromised. It still needs to be reset,
and active sessions still need to be revoked.

The same action applies to every account in the report regardless of verdict. The verdict determines
how urgently an investigator needs to examine the account, not whether the credential needs to be
changed. If a single decision comes out of this report, it is that every listed account gets a
password reset and a session revocation.

---

## What a verdict is not

- **It is not a legal or forensic determination.** The report produces investigative leads. A
  Confirmed verdict states that the retained evidence for an account matches the pattern this attack
  produces. It does not constitute proof of unauthorized access, and it is not on its own a breach
  determination for regulatory or contractual notification purposes. That decision belongs to counsel
  and the incident commander, informed by this report and other evidence.
- **It is not a measure of damage.** The verdict describes access, not what the intruder did once
  inside, what was read, what was copied, or whether anything was taken. Answering that requires
  separate work.
- **It is not a measure of the account's importance.** A Confirmed verdict on a shared mailbox and a
  Confirmed verdict on the finance director carry identical evidence weight and very different
  business consequences. Business impact is a judgment the organization makes, not something the
  tool calculates.
- **It is not a ranking of employee behavior.** Appearing in this report means a password was
  exposed somewhere and an attacker tested it. It is not a finding against the account holder.

---

## Reading the numbers correctly

Three properties of the underlying data change how the totals should be interpreted.

**The account count is a floor, not a total.** When the attacker tested a username that does not
exist in your directory, nothing was recorded at all. The attacker's target list is larger than
anything this report can show. The number of accounts listed is the minimum size of the problem.

**A clean result is bounded by how long the logs are kept.** Microsoft retains these records for a
limited period, typically 180 days or one year depending on licensing. If the campaign began before
that window, the earliest activity is simply gone. Absence of a finding is not evidence that nothing
happened.

**Some evidence is only available for the last 30 days.** Details such as whether multifactor
authentication was satisfied, and whether Conditional Access applied, come from a separate log with
much shorter retention. For older activity those details are unavailable, so the report says
"unknown" rather than guessing. An account may be graded lower than the truth simply because the
evidence needed to grade it higher has expired.

Taken together: the report is confident about what it found and deliberately silent about what it
could not see. Read it as a lower bound in every direction.

---

## Four phrases that change the reading

If any of these appear on an account card, they override the first impression the verdict gives.

**"Novelty could not be assessed."** This account had no normal sign-in history to compare against,
often because it is a rarely used, dormant, or service account. The report cannot tell unusual
activity from usual activity for this account, because it does not know what usual looks like. An
account carrying this note may show No Indicators and still be entirely unexamined. These accounts
require manual review and must not be dismissed on the strength of the verdict alone.

**"Validation timestamp assumed."** The exact moment the attacker tested this password could not be
recovered, so the analysis had to assume it happened at the start of the search period. The findings
for this account are less precisely anchored in time than the others.

**Error code confidence marked "Observed" or "Ambiguous."** The report classifies each account using
Microsoft error codes. Most of those codes have documented meanings. Two do not: one is based on
published third-party research rather than a Microsoft commitment, and one is a code Microsoft itself
categorizes inconsistently. Accounts resting only on those codes are the weakest leads in the report,
and the report labels them so they are visibly weaker rather than silently equal.

**"Exchange record types were unavailable."** The permissions granted for this run did not allow
mailbox activity to be examined. Mail forwarding rules, inbox rules, and mailbox permission changes
were not checked. The follow-on activity section is incomplete, and it says so rather than reading as
complete.

---

## What to do with each verdict

| Verdict | Urgency | Typical next step |
| --- | --- | --- |
| **Confirmed** | Immediate | Treat as a possible active intrusion until an analyst rules it out. Reset the password, revoke sessions, and open a full investigation of the account, including mailbox rules, data access, and anything the account could reach. |
| **Probable** | Same day | Reset the password, revoke sessions, and assign an analyst to resolve the activity to either a legitimate explanation, such as travel or a new device, or an intrusion. |
| **Possible** | Same week | Reset the password, revoke sessions, and review. Expect a portion of these to resolve as benign and a portion to escalate. |
| **No Indicators** | Same week | Reset the password and revoke sessions. The credential is compromised even though no misuse was observed. |

CredEcho performs none of these actions. It is read only by design: it changes nothing, resets
nothing, and blocks nothing. Every action above is a deliberate human decision made outside the tool.

---

## Questions worth asking in the review meeting

1. How many accounts are in the report in total, and how many of those hold privileged or
   administrative access?
2. Which listed accounts have access to regulated data, financial systems, or customer information?
3. Have all listed accounts had passwords reset and sessions revoked, including the No Indicators
   ones?
4. For each Confirmed account, has an analyst examined it, and did they find actual misuse or an
   innocent explanation? Until that question is answered per account, the Confirmed count is a
   workload figure and not a damage figure.
5. How many accounts carry the "novelty could not be assessed" note, and who is reviewing them?
6. Where did the exposed passwords originate, and does that source suggest other accounts not visible
   here?
7. Does the retention window cover the full suspected duration of the campaign, and if not, what is
   the gap?
8. What would have detected this earlier, and what would it cost to put that in place?
9. Does anything in this report trigger a notification obligation under our contracts or regulatory
   obligations, and who is making that call?

---

## The one-paragraph version

An attacker used a quiet technique to confirm which of a set of stolen passwords for our accounts
still work. Because the technique never completes a sign-in, nothing alerted at the time. This report
lists every account whose password the attacker confirmed as valid, and grades how much evidence
exists that each account was then actually used by someone other than its owner. Confirmed means the
activity on that account matches what this attack looks like, so it is the first one to investigate.
It is not a ruling that the account was compromised, and the Confirmed count is a measure of urgent
work rather than a count of compromised accounts. Probable means the account behaved abnormally
afterward. Possible means the question is open and an analyst has to resolve it. No Indicators means
no misuse was found in the records that still exist, which is not the same as safe: the password is
compromised either way. Every account in this report needs its password reset and its sessions
revoked. The verdict sets the investigation priority, not whether that action is required.
