# B2B sharing failure on the partner's side

**Date:** 2026-09-21. **Tools:** the read-only Graph runner with a cached device code token ([`tools/Invoke-GraphRead.ps1`](../../tools/Invoke-GraphRead.ps1) is the rewrite).
**Status:** [built, ran on real tickets]

## Symptom

A senior leader at my employer could not open a workbook a partner company
had shared with them in the partner's Teams. It was due in a couple of
days. The browser landed on a SharePoint error page on the partner's
domain.

## Read the error page first

The page said "External sharing is disabled" and, further down, gave an
issue type: "Guest user is signing in but external sharing is disabled." It
also showed the guest identity it had resolved, in the
`user_contoso.com#EXT#@<partner>.onmicrosoft.com` form, and a correlation id.

Three facts follow from that text alone:

1. **Sign-in succeeded.** The page named a resolved guest identity, which
   exists only after authentication.
2. **A guest object already existed** in the partner's directory. This was
   not a missing invitation.
3. **The block was SharePoint's external sharing setting in the partner's
   tenant,** evaluated after authentication. That setting belongs to the
   tenant hosting the site.

## Prove the tenants are separate

Public OpenID Connect discovery maps any verified domain to its tenant id:

```
GET https://login.microsoftonline.com/<domain>/v2.0/.well-known/openid-configuration
```

The `issuer` value carries the tenant id. The partner's domains resolved to
one tenant; ours to another. The failing URL also carried our tenant id in
its originating-visitor parameter: the user was arriving as our guest, as
expected.

## Prove our side with our own telemetry

With a read-only device code token:

| Query | Finding |
|---|---|
| `v1.0/users/{id}?$select=accountEnabled,userType,onPremisesSyncEnabled` | Account enabled, member, synced. Nothing wrong with the account. |
| `beta/auditLogs/signIns?$filter=userId eq '{id}' and createdDateTime ge ...` | Five SharePoint Online sign-ins to the partner's tenant that day, all `crossTenantAccessType` b2bCollaboration, all errorCode 0, none blocked by Conditional Access. One succeeded one second before the time stamped on the error page. |
| `v1.0/policies/crossTenantAccessPolicy/partners/{partnerTenantId}` | 404: no partner-specific settings, so the default applies. |
| `v1.0/policies/crossTenantAccessPolicy/default` | Our outbound settings allowed B2B collaboration with this partner. |

Later the same day there were two Teams sign-ins to the partner: one
interrupted for MFA (50074), then a success. Authentication was never the
problem.

## Verdict

Nothing on our side caused it or could fix it. Our outbound cross-tenant
settings allowed collaboration with this partner, and our Conditional
Access was not the blocker. Had our side blocked it, the user would have
failed at sign-in with an AADSTS error and never reached SharePoint. The
control point was the partner's SharePoint external sharing setting, at the
organization level or, more likely since a guest object existed and
resolved cleanly, on that one site.

I wrote up what the partner's admin would need to find it fast: the
correlation id, the timestamp, the guest identity form, the site, and the
exact issue type string. I also listed ways for our user to keep moving
while that happened: have the file emailed, have it moved to a location
where the partner allows guests, or have a partner-side owner enter the
numbers.

## Lessons

- **The error text is evidence.** Read it word by word before running a
  single query.
- **Prove the boundary of responsibility with your own logs.** Sign-in logs
  plus the cross-tenant access policy answer "is it us?" in minutes, and
  they make the conversation with the other company short and specific.
- **OIDC discovery is a free tenant lookup** for any domain.
- **Separate authentication from authorization.** Here the first worked
  and the second was someone else's setting.
