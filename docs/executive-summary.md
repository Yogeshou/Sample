# VulnTracker: Executive Security Summary

**Bottom line:** VulnTracker holds a list of our own unfixed security weaknesses, which is exactly the information an attacker wants most. Before this review, **anyone who could reach the application could read every team's list, impersonate any user, and use the system to reach our internal network.** Those issues are now fixed and covered by automated tests that block any change reintroducing them. The service is **fit for a controlled internal pilot**. It is **not yet ready for external customers** until the four actions under "Before go-live" are complete.

## Where we were

- **Anyone could become anyone.** The login check could be skipped entirely, and the master key for logins was published in our source code.
- **Any user could read everyone's data.** Basic mistakes let one account pull every other team's vulnerability records, plus the password store.
- **Passwords were written to logs** in readable form, including typos of people's other passwords.
- **The notification service had no lock on the door.** Anyone on the network could subscribe to a live feed of newly found vulnerabilities, or use it to reach our cloud credentials.
- **Outdated third-party components** with 78 publicly known weaknesses.

## Where we are now

- All **Critical** and **High** issues found are fixed: 3 Critical and 7 High (including 1 High in the new feature). Every fix has a test that fails if it regresses.
- The new **"share a report with an auditor" link** was built secure by default. Links expire after 24 hours, can be revoked, can carry a password that locks after 10 wrong guesses, and show the outside party only what they need.
- Known weaknesses in third-party components went from **78 to 0**.
- **Every code change is now checked automatically** for insecure code, vulnerable components, container problems and cloud misconfiguration, and **is blocked** if serious issues appear.
- The deployment design keeps secrets in a managed vault, runs with minimum privileges, and lets only the traffic it needs reach the service.

## Top 3 remaining risks

| # | Risk | Why it is not closed yet | What protects us meanwhile |
|---|---|---|---|
| 1 | **The old leaked keys still work anywhere they were ever used.** They remain in our code history. | Changing a key is an operational step in each environment, not a code change. | The new code no longer trusts them. **Rotating them is a hard go-live condition.** |
| 2 | **Password guessing against user accounts**, and anyone can sign up for an account. | The right fix is company single sign-on with MFA, which is a product decision and a short project. | Each user now sees only their own data. Request-rate limits slow guessing. Failed logins are logged for alerting. |
| 3 | **Data durability.** The prototype database has no backups and cannot scale beyond one server. | Moving to a managed database is a 2–3 day infrastructure task. | The database disk is encrypted, and the app is already built to switch over by configuration only. |

## Recommended next steps

**Before go-live (about 1 week):**

1. Rotate all exposed keys and turn on automatic secret-leak blocking in our code host.
2. Put the application behind company single sign-on with MFA, and close public sign-up.
3. Move data to a managed, backed-up database.
4. Run an independent penetration test focused on access control.

**Ongoing:** keep the automated security checks mandatory, review component updates weekly, and set alerts on failed logins and share-link lockouts.

**Ask:** approve the one-week hardening sprint above and name an owner for key rotation. With those done, I would be comfortable putting customer-facing share links into production.
