# LiberNT-sec publication plan, 2026-11-14

PRIVATE. Kept in LiberNT-sec only. Under the owner order of 2026-11-14 (point 5), nothing below is
published until god approves this plan, a fix is reviewed and regression-tested, and the
fixed build is available.

Author: Stanley. Inventory taken on 2026-11-14 from `git ls-remote` of LiberNT-sec, LiberNT-CI and
LiberNT-LDW. "Public" means present on `leeway/main` (2f05fd0484f) by patch identity, or on a public
LiberNT-CI branch. U = unknown, still to be confirmed.

## 1. Rules for every publication

1. **One public commit per fix, with a neutral message.**
   - The message describes the correctness defect: what was wrong and what the code does now.
   - It never states reachability ("unprivileged", "user-triggerable"), never says how to trigger it,
     and contains no proof of concept and no advisory wording.
   - The private commit messages below DO contain such detail, so they are never pushed as they are.
     Every fix is replayed with `git cherry-pick -n` plus a new message.
2. **Identity.** Author and committer must be `LeewayOpenSoftware` with the noreply address, and no AI
   trailer.
   - The older private commits (11-11 and 11-12) carry the old spaced name "Leeway Open Software",
     which is one more reason the replay creates new commits.
   - Pushed history is never rewritten.
3. **Tests go public in the same batch as the fix, never before it.**
   - A fail-first test published before its fix is a reproducer.
   - The host and kmtest cases may keep their names, but their comments must not say "exploit" or
     "attacker".
4. **Order: fix, then build, then advisory.**
   - Batch the fixes into one integration merge, so that no single commit stands out.
   - Ship the next build that contains them.
   - Publish the advisory only after that build is available.
   - Builds already handed to users (LBI ≤ the current cut) are the "unpatched users"; the advisory
     names the first fixed build.
5. **Advisory content.**
   - Component, impact class, required privilege (local user / admin / physical media), affected
     builds, the build it is fixed in, and a workaround if there is one.
   - No offsets, no structure layouts, no trigger sequence.

## 2. Inventory

Columns: fix · LiberNT-sec branch and head · review · test · regression · public exposure today.

| # | Fix (impact class) | Branch / head | Review | Test | Regression | Public today |
|---|---|---|---|---|---|---|
| P1 | COW commit charge at DISPATCH; WasValid retry (local DoS bugcheck; skipped executable-write check) | sec/mm-cow-commit-charge-irql ab7f22c1e64 (d7f6a1d9990, 5d62b5f99fe, ab7f22c1e64), base 2f05fd0484f | Dwight OK (SHOULD-1 folded into ab7f22c1e64) | host t_section 934/945 pass; sandbox_apitest job-limit COW case (not built yet) | not in sec-batch-1113; no VM leg | NO. Its absence is visible: mmcc host test 934/945 is red on public main (known residual) |
| P2 | Thread context: segment selectors, user RIP/RSP range, IRETQ fault (local DoS / kernel-mode control) | sec/ke-context-segments bbaa29d0977 (+ -tests e9c219eda1a) | Dwight OK (IRETQ handling ported from upstream) | kmtest KeContext (in -tests) | sec-batch-1113 43dca639835 builds on the private runner; no VM run recorded (U) | Partial: the upstream counterpart b7ba27ad19b is public in ReactOS |
| P3 | NtRaiseException record probe and uninitialised local (kernel stack disclosure, false access violations) | sec/ke-raise-exception-init dc2a252aa3d (+ -tests 39637a5da05) | Dwight OK | ntdll_apitest NtRaiseException | in sec-batch-1113 | YES for the probe half: ce58d3ada9c is on public LiberNT-CI fix/ke-raise-exception-probe-1113. dc2a252aa3d (init) is private |
| P4 | ALPC canceled-queue reply (UAF) | sec/alpc-cancel-free f6f2e7838c1 | Dwight OK | NtAcceptConnectPort apitest (public, crashes before the fix) | in sec-batch-1113 | The crashing test is public; the fix is private |
| P5 | CM key body init on create failure (UAF/teardown) | sec/cm-notify-uaf b3472d71289 | Dwight OK | LinkReparseLimit apitest (public, crashes before the fix) | in sec-batch-1113 | The crashing test is public; the fix is private |
| P6 | Mount-point reparse bounds, C-1 (kernel OOB, owner SEC-P0) | sec/reparse-bounds 33cb9cb5010 (+ exp/rust-c1-reparse 52e5152efde, not for publication) | U (authored by Stanley; no second review recorded) | host fail-first, 17 malformed inputs; crafted image rejected | VM leg (repro + Driver Verifier + Lab04) never run (was billing-blocked) | PARTIAL: the I/O-manager validator IopValidateMountPointBuffer is on public LiberNT-CI fix/io3-name-grafting 1d45eab8da4 (IO-3, Dwight reviewed), not yet on main. The NTFS half is private |
| P7 | Security descriptor / SID / ACL capture and validation, plus the access-check-and-audit worker (privilege / access-check bypass, OOB read) | sec/access-check f2a713ce64b (7 commits) | U (no review recorded) | S5 host fail-first; S1 apitest written, not run; S2/S3 race harness host-only | never built on a kernel (billing) | NO. Base is the old sec root, so a rebase onto 2f05fd0484f is needed (all 7 conflict) |
| P8 | FsRtl oplock: double unlock, lost STATUS_PENDING, list UAF (D1/D3/D6) | fix/fsrtl-oplock-ex 30e3ff5ce4c | U (spec M1-2-OPLOCK-FLAGS.md; no reviewer recorded) | host 19/19; ASan+UBSan 19/19 | never built in tree (billing) | NO. No split possible (commit 2 needs D2). Needs a rebase |
| P9 | NSI provider lifetime: late CSQ cancel and nsiproxy unload (UAF) | fix/nsi-lifetime 2b6826ee204 | reviewed OK per INTEGRATION-READINESS 11-12 (reviewer U) | NSI kmtest (deregister vs cancel, drain) | kmtest legs never run | NO. Needs a rebase |
| P10 | IoQueueWorkItemEx MustSucceed allocation (DoS under memory pressure) | sec/ioqueueworkitemex 02467aeafe2 | U | none | public mirror CI green 43146032427 | YES: identical fix on public LiberNT-CI fix/ioqueueworkitemex-alloc 1e5628ef95c. Low severity |
| P11 | MountMgr dos-volume-paths retry bound (DoS loop) | fix/mountmgr-dosvolpaths-bound 231fe2991aa | U | none possible | the public backoff mirror FAILED in VM (loop is below the worker); trigger unidentified | The public mirror branch exists (withdrawn) |

Already public on leeway/main by patch identity, so nothing remains to disclose (data-integrity
class; an advisory is optional): A-1 fix/cc-coherency-a1-v3, A-2 fix/mm-purge-partial-v3, A-3
fix/ntfs-noncached-purge-a3-v3, B-1 fix/mm-section-acquire-b1, and fix/ntfs-durability-fua. These
LiberNT-sec branches can be deleted after god confirms.

## 3. Proposed batches

Batch S1, ready now (reviewed, base 2f05fd0484f, already in a private build):
- P1 COW, P2 context, P3 raise (init), P4 ALPC, P5 CM.
- Gates:
  1. private CI on the sec-batch plus P1;
  2. kmtests KeContext and NtRaiseException;
  3. apitests NtAcceptConnectPort and LinkReparseLimit go from crash to pass;
  4. mmcc 934/945 pass;
  5. desktop gate smp1 and smp2.
- Then replay with neutral messages onto the main candidate and ship in the next build.
- Urgency: P4 and P5 have public crashing tests and P3 has a public half, so these are the
  most exposed. Publish S1 first.

Batch S2, needs review and a build:
- P6 C-1: second review plus the VM leg.
  - Its IO-3 half is already public on a CI branch, so land IO-3 and the NTFS half together.
- P7: rebase, build, review, then the S1/S2/S3 legs.
- P8: rebase, in-tree build, review, then fastfat/ntfs oplock smoke.
- P9: rebase, then the kmtest legs.

Batch S3, low severity, no advisory needed:
- P10: already public. Merge the public mirror and delete the sec branch.
- P11: hold until the loop trigger is understood; it may not be the right fix.

## 4. Public-safe commit messages (drafts)

- P1 `[NTOS:NVS] Charge copy-on-write commit outside the PFN lock`. Body: the charge can call a
  commit-owner callback that must not run at DISPATCH_LEVEL; take the charge before the lock and
  retry the page; reset the per-page state on retry.
- P2 `[NTOS:KE] Sanitise amd64 user contexts set through NtSetContextThread`. Body: segment
  selectors are fixed to the user values, the stack pointer stays in the user range, and a fault on
  the return to user mode is delivered to the thread.
- P3 `[NTOS:KE] Size and initialise the raised exception record by its parameter count`.
- P4 `[NTOS:ALPC] Keep a replied message on the canceled queue until it is reclaimed`.
- P5 `[NTOS:CM] Initialise a new key body before any failure path`.
- P6 `[NTOS:IO][NTFS] Validate mount-point reparse buffers before use`.
- P7 `[NTOS:SE] Validate captured security descriptors, SIDs and ACLs after copying`, plus
  `[NTOS:SE] Perform the access check in NtAccessCheckAndAuditAlarm`.
- P8 `[NTOS:FSRTL] Fix oplock break waits and pending status`.
- P9 `[NETIO] Keep deregistered providers valid for late cancels; drain nsiproxy on unload`.

## 5. Advisory draft (template, one per batch)

LiberNT security advisory LNSA-2026-00N

- Component: ...
- Impact: local denial of service (bug check) / local privilege escalation / information disclosure.
- Required access: local authenticated user | administrator | crafted removable volume.
- Affected: LiberNT integration builds up to and including LBI <last unfixed>.
- Fixed in: LBI <first fixed build>, commit <public sha>.
- Workaround: none (or: do not mount untrusted NTFS media, for P6).
- Credit: LiberNT kernel team.
- Technical details are withheld for 30 days after the fixed build is released.

## 6. Open items for god

1. Approve this plan and batch S1.
2. Confirm who reviews P6, P7, P8, P10 and P11. I propose Dwight for P7 and P8 (SE and FsRtl), and
   Dwight for P6 (I wrote it).
3. Confirm the advisory numbering, and where advisories live (a SECURITY.md in LDW plus advisories/).
4. Confirm that the five LiberNT-sec branches already public on main may be deleted.
