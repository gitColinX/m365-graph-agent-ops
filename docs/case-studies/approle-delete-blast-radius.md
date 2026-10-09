# App role delete that removed a group's access

**Date:** 2026-09-25, late evening into just after midnight.
**Tools:** [`tools/Start-QueueWorker.ps1`](../../tools/Start-QueueWorker.ps1); the fix is [`tools/Remove-UserAppRoleAssignment.ps1`](../../tools/Remove-UserAppRoleAssignment.ps1).
**Status:** worker [built, ran on real tickets]; safe-delete helper [in progress]

## Context

An audit of a departed consultant's account found leftovers from an
offboarding that had been requested twice: MFA methods still registered, a
workplace-registered device, and an app role assignment to a print
management app. I closed the gaps through the queue worker: one Graph
sign-in and one Exchange sign-in, then nine small steps, each one a file
the agent wrote into the queue. I approved the steps that wrote to
production before they ran.

## What happened

| Step | What it did | Result |
|---|---|---|
| 10 to 13 | Discovery, app access investigation, mailbox recheck | Read-only. Confirmed the gaps. |
| 20 | Remove MFA methods, the app assignment and the registered device; revoke sessions | Phone method deleted; Authenticator delete returned BadRequest (it was the default method). **App assignment delete through the user's path returned BadRequest.** Device deleted and gone on read-back. Sessions revoked. |
| 21 | Retry the two failures | Authenticator deleted once the phone method was gone; read-back showed password only. For the app assignment, the output printed **`principalType=Group`**, and then the step deleted it through the service principal's `appRoleAssignedTo` collection. DELETE accepted. Read-back: the user had no app role assignments. |
| 22 | Blast-radius check, written because of that `principalType=Group` line | Tried to decode the deleted assignment's id to its principal and failed ("Guid should contain 32 digits"). Listed the app's remaining assignments: three, all groups. |
| 23 | Identify and restore | Validated the decode on a known assignment first, then decoded the deleted id: it was the **All Users** group's grant. Re-POSTed it to `appRoleAssignedTo`. Read-back: four assignments, up from three. |
| 30 | Final verification | Account disabled, no licenses, password only, no devices, no mailbox, and the app's four assignments, All Users included. |

From the delete to the restore POST took about two minutes. The incident
went into the ticket's audit record, plainly.

## Why it happened

`GET /users/{id}/appRoleAssignments` returns the user's own grants and also
the grants made to groups the user is a direct member of. Microsoft
documents this. A group-conveyed row has the group as `principalId` and
`Group` as `principalType`.

The user's path refused to delete it (BadRequest) because it was not the
user's grant. That refusal was the system telling me something. Instead of
asking why, the retry went to a different door, the service principal's side,
where an assignment is just an assignment, and the delete succeeded. It
removed the app from every member of All Users.

## The second mistake, found while writing this up

Step 23 also checked "is the user a member of All Users?" and printed
`False`. It was wrong. The check read one page of 999 members and did not
follow `@odata.nextLink`. The final verification listed the user in All
Users. The wrong answer did not change what I did that night, but I would
have quoted it if I had not gone back through the transcripts for this
write-up.

(The user still reaches the app through All Users, like everyone else.
For a disabled account that is fine. Removing a person's access is done on
the account or the group membership, never on the group's grant.)

## What I changed

The rule went into the offboarding playbook right after: delete an app role
assignment only when `principalType` is `User`; anything else is an
org-wide grant.

The helper in this repo, `Remove-UserAppRoleAssignment.ps1`, makes that rule
code:

- Picks exactly one assignment from the user's list.
- Refuses unless `principalType` is `User`, `principalId` is this user, and
  the assignment id decodes to the same principal (it fails closed if the id
  does not decode, and the decode is cross-checked, never trusted alone).
- For a group grant, reports the group and its member count across all
  pages, and tells you to change membership instead.
- Deletes only through `/users/{id}/appRoleAssignments/{id}`, never through
  the service principal side.
- Snapshots the assignment to a file that holds the exact restore call.
- Counts the app's assignments before and after, and fails unless exactly
  the target disappeared.

`tests/Run-Tests.ps1` covers the refusal, the decode, and the 999-member
paging case.

## Lessons

1. **A refusal from an API is information.** When one endpoint says no and
   another says yes, find out why before taking the yes.
2. **Know what an object is before you delete it.** A row in the user's
   list is not necessarily the user's.
3. **Measure the blast radius before the write, not after.** Count what the
   resource has before and after; anything other than "minus one" is a
   stop.
4. **Validate a decoder on a known value first.** Step 22's decode failed;
   step 23's worked because it proved itself on a known assignment.
5. **Page everything.** One page is a sample, not an answer.
6. **Disclose plainly.** The ticket record says what happened, when, and
   how it was restored.
