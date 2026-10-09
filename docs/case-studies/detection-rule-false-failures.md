# Win32 detection rule false failures

**Date:** 2026-09-11. **Tool:** [`tools/Set-IntuneWin32AppField.ps1`](../../tools/Set-IntuneWin32AppField.ps1) (the rewrite of what I ran).
**Status:** [built, ran on real tickets]

## Symptom

A self-updating remote-support agent had been deployed a month earlier as an
Intune Win32 app with an MSI inside, Required for all devices. It had been
packaged with the Intune default for an MSI: detect by product code. Four
weeks later the app's device status read:

| Status | Devices |
|---|---|
| Installed | 38 |
| Failed | 707 |
| Install pending | 18 |
| Not installed | 1 |

The dominant error was 0x80070643 (MSI fatal error). Failures were rare
until one day, then several hundred landed at once and kept trickling in.

## Cause

A colleague suggested it in a team chat: the agents had auto-updated. I set
out to prove or disprove it with data rather than argue it.

Through Graph I pulled the managed device list (about 1,100 devices) and the
discovered-apps inventory for the client, broken out by version. Then I
joined it per device against the app's install status export:

| Report says | Newer client actually installed | Devices |
|---|---|---|
| Failed | yes | **667** |
| Failed | no | **40** |
| Installed | yes | 30 |
| Installed | no (inventory lag) | 8 |

The mechanism:

1. The vendor's cloud server upgrades and pushes the new client version to
   every agent.
2. Every client version is a new MSI with a new product code.
3. Intune's detection rule looks for the old product code, finds nothing,
   and decides the app is missing.
4. It runs the older MSI again, which fails over the newer running client
   (MSI 1603, reported as 0x80070643).
5. The device shows Failed while the agent is installed and healthy.

So 667 of 707 failures were false, and the real remediation list was 40
devices. Product-code detection was not a mistake; it is the right default
for software that does not update itself. This one does.

Turning off the agent's auto-update was not an option; staying current was
the point.

## Fix, through Graph

One PATCH per field on `beta/deviceAppManagement/mobileApps/{id}`, each
read back, with the full object saved before and after as the rollback:

| Field | Change |
|---|---|
| `detectionRules` | MSI product code replaced by a file rule: the agent's service executable exists |
| `installCommandLine` | added `/L*v` verbose MSI logging, for the 40 real failures |
| `description`, `publisher`, `developer`, `owner` | filled in properly |
| `notes` | Graph returned BadRequest on the long change log; I pasted it in the portal |

## What went wrong along the way

I made the detection change through Graph at 21:03 UTC. At 21:06 I uploaded
a logo in an Intune portal blade I had opened before the change, and saved.
The blade still held the whole app object as it had loaded it, and the save
re-sent all of it, including the old detection rule. My change was gone
without an error anywhere.

The revert showed up in the next snapshot I took of the app. I re-applied
at 21:20 one field per PATCH, read each one back, and wrote the rule down:
do not save from a portal blade that was opened before a Graph change. The
portal saves also flipped "Allow available uninstall" from Yes to No,
harmless for a Required-only app, and the reason the rewrite's collateral
check compares that flag explicitly.

One more thing the rewrite learned from this run's before and after
snapshots: Intune returns a detection rule with defaults it added itself,
and keeps a second copy of the rule in the app's `rules` collection. A
read-back that compares JSON text, or a collateral check that watches
`rules`, would call this successful change a failure. The rewrite compares
what was sent field by field and leaves the detection entries in `rules`
out of the collateral check.

## What else I flagged at the time

- The uninstall command also hard-coded the old product code and would
  break the same way; I suggested a small script that finds the current
  uninstall entry by display name.
- The extra Required assignment to all users doubled evaluation and report
  rows (1,222 rows for 764 devices); all devices is enough for a
  system-context app.
- Collect verbose MSI logs from the 40 real failures.

## What the numbers cover

The 667 and 40 come from the per-device join on the day. I did not record a
re-measurement of the Failed count after the detection change, so this
write-up has no after number.

## Lessons

- A failure report is a claim about detection, not about the device. Check
  what is actually installed before remediating anything.
- Self-updating software needs a detection rule that survives the update:
  a file, folder or registry key unique to the install, not a product code.
- Graph and the portal both write the whole object. Whichever writes last
  wins, silently. Read back, and check what you did not mean to change.
