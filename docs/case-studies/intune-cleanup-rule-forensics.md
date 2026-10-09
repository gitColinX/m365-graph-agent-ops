# Who deleted this laptop from Intune? Nobody did.

**Date:** 2026-09-18. **Tool:** [`tools/Get-IntuneDeviceHistory.ps1`](../../tools/Get-IntuneDeviceHistory.ps1).
**Status:** [built, ran on real tickets]

## The question

A contractor had left months earlier and their laptop was overdue for return.
Before escalating to their manager I wanted to know the obvious thing: can
we still wipe it? The device was not in the Intune device list any more. The
next question was who removed it, because a human deleting the record of an
unreturned laptop would be a problem of its own. It turned out the
contractor had been issued two laptops over time (the first one had failed
and been replaced), and neither was in Intune.

## What the exports already said

Before any live query, older exports I had pulled for other reasons told
part of the story:

- The Autopilot identity for the serial was still there, but its
  enrollment state had gone to "not contacted" and its last-contacted date
  was empty. The link to an Intune record was already broken.
- The Entra device object was still there and still said managed and
  compliant, with no MDM attached. Entra only sets those flags because
  Intune once managed the device, so it had been enrolled, and the Intune
  record had been removed while the Entra object and the Autopilot identity
  survived.

That signature (Entra says managed, Intune has no record, Autopilot still
knows the hardware) is the mark of a removal on the Intune side: either an
admin clicked Delete, or the Intune device cleanup rule fired.

## Getting the live evidence

The live run took a few tries, and those tries are why this repo signs in
the way it does. Four sign-in attempts that afternoon did not complete. The
first two used the SDK's device code sign-in, and its client timeout ended
both before I had entered the code. I switched the script to the raw device
authorization grant with the full 15-minute window. The next attempt hit a
bug in my script, and the one after that produced a code that expired
unused. The run after that went through.

`Get-IntuneDeviceHistory.ps1` then collected, for both serial numbers and
device names:

| Source | What it showed |
|---|---|
| Intune managedDevices (by serial, by name, by user) | Nothing. Both records gone. |
| Entra device objects | Both present, registered owner the contractor, enrollment by Autopilot pre-provisioning, `isManaged` true. Last sign-ins: mid-May 2026 for the replacement, mid-July 2025 for the original. |
| Autopilot identities | Both present, "not contacted", each still pointing at a `managedDeviceId` that no longer existed. |
| `managedDeviceCleanupRules` | One rule: retire devices inactive for 90 days. (The older `managedDeviceCleanupSettings` endpoint returned 403 for my role; the rules endpoint worked.) |
| Intune audit events, one full year | About 5,600 by my notes (the saved extract keeps the 365 delete, wipe and retire events). None references either serial, device name, user or managed device id. |
| Entra directory audits | No admin delete of either Entra device object. |

## Conclusion, by elimination

Both Intune records were removed by the 90-day inactivity cleanup rule:

- No admin removal event matches either device in a year of audit events.
- Each device was inactive well past 90 days: the replacement last checked
  in mid-May, so it became eligible in mid-August. That fits every other
  data point: still in an Autopilot export in early June, "not contacted"
  by late August, gone from the Intune list in mid-September.
- The Entra and Autopilot objects survived, which is what an Intune-side
  removal leaves behind.
- The Intune audit log had no actor event for either device, which fits a
  system-run cleanup rather than an admin action.

The tool encodes the same reasoning in `Resolve-DeviceRemovalVerdict`. It
answers "Undetermined" instead of guessing when the audit window does not
reach back to the date the rule could have fired, and when any query the
conclusion rests on failed, returned 403 or hit its page cap. An empty
audit log only counts if the query that produced it worked.

## The offboarding lesson

- **Wipe or retire early.** Issue the Intune wipe or retire on the last day,
  or as soon as the hardware recovery task opens, instead of waiting for the
  device to come back. Once an inactivity cleanup rule removes the record,
  the remote wipe path goes with it.
- **A query worth running in any tenant:** Entra devices that say managed
  with no Intune record have lost their Intune record. Run that query in
  your own tenant before the cleanup rule decides for you.

## What I would tell someone doing this

- Collect every surviving trace before concluding anything: Intune, Entra,
  Autopilot, both audit logs.
- An empty audit log is evidence only if you checked the window that
  matters.
- If the conclusion is "by elimination", say so, and say what would
  overturn it. The last place to look is the unified audit log for the
  Intune workload.
