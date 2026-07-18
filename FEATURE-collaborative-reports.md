# Feature Spec — Collaborative (Multi-Admin) Reports

**Status:** Design locked, not yet implemented.
**Author of spec:** design agreed with the product owner over 2026-07-17/18.
**Audience:** the engineer or AI agent who will implement this later.

---

## 1. Summary

Today a report is a one-person, one-sitting action: an admin loads a **live** 5-minute
Prometheus snapshot, annotates it, and immediately **downloads or e-mails** it — each
generation is an independent, final `ReportSubmission`.

This feature turns a report into a **collaborative artifact** that several admins co-author
over time before it is finalized:

- Metrics are **frozen once** when the report is created.
- Admins take **turns** editing it (a single-writer lock — never concurrent).
- Editing continues until a designated **last contributor submits**, which is the only step
  that **e-mails** the report and stores it as **final** (the version that appears in History).
- Reports are **typed** (System Admin / Network Admin / Gov Systems Admin); a type is gated by
  the matching user role. **Only the System Admin Report is content-defined for now**; the type
  dimension is built to be extensible.

### Goals
- Multiple admins contribute to one report, safely (no edit conflicts), with a clear audit of
  who did what.
- Standalone e-mail is removed; e-mail happens only at final submission.
- Accountability: incomplete submissions are allowed but must be justified and are flagged.

### Non-goals
- Real-time / simultaneous multi-cursor editing (we use turn-based locking instead).
- Defining the content of the Network Admin and Gov Systems Admin reports (deferred; certain to
  come, but out of scope here).
- Changing the `.xlsx` layout/structure (only the per-system "By" attribution source changes).

---

## 2. Concepts & terminology

| Term | Meaning |
|------|---------|
| **Report type** | A first-class kind of report: `system_admin`, `network_admin`, `gov_systems_admin`. Chosen **before** creation. Each maps to a required **user role** and (eventually) its own content scope. Only `system_admin` is content-defined now. |
| **Frozen snapshot** | The engine `Store` + systems captured once at creation and persisted, so the final `.xlsx` can be rebuilt later with Prometheus offline. |
| **Contributor** | An admin on the report's **ordered** list. Must hold the report type's role. |
| **Lock** | A report-level, single-writer lock. A `pending` report is `released` or `locked_by` one admin. |
| **Turn** | The period an admin holds the lock. "Took a turn" = acquired the lock at least once. |
| **Completeness** | `complete` iff the **last** contributor submits **and** every contributor took a turn; else `incomplete` (+ required reason). |

---

## 3. Locked design decisions (with rationale)

1. **Freeze metrics at creation.** A report reflects a point in time; collaboration spans time.
   Freezing makes the whole feature coherent and removes the live-snapshot TTL from the flow.
2. **Report-level single-writer lock (turn-based).** Eliminates edit conflicts by construction
   (≤1 editor per report at any moment) — no merge logic anywhere. Chosen over per-system claiming.
3. **Lifecycle `pending → final`** (optional `cancelled`). Only `final` appears in History.
4. **Report type chosen before creation, = creator's role.** Multi-role creators pick which type.
   Contributor eligibility is gated by holding the type's role.
5. **Ordered contributor list; last = designated submitter.** Creator is contributor #1 and holds
   the lock first. The list is **mutable while `pending`** — the creator (or an Administrator) can
   **add** contributors up to submission (proposed: also reorder / remove not-yet-contributed).
6. **Submit anytime, but classified.** `complete` only when the last contributor submits and all
   contributed; otherwise `incomplete` with a **mandatory written reason**, badged in History.
7. **Idle auto-release = 5 min** (tunable) + **Administrator force-release** as manual override.
   A keep-alive ping counts *genuine* inactivity so an active editor isn't yanked.
8. **Per-system "By" = whoever edited that system; summary "By" = the submitter.**
9. **Draft preview** allowed (throwaway `.xlsx`, nothing stored, no e-mail).
10. **E-mail only at Submit.** Standalone "Generate & e-mail" is removed. History filters `final`.
11. **Notifications:** contributors are notified when a report is released / it is their turn.
12. **Administrators** oversee any report (view, force-release, submit-override) but only
    **contribute content** where they also hold the type's functional role. *(working default)*

---

## 4. Roles ↔ report types

| Report type | Required user role | Content (now) |
|-------------|-------------------|---------------|
| `system_admin` | System Admin | The current full System Admin Report (today's behaviour). |
| `network_admin` | Network Admin | **Undefined — to be specified when the report is designed.** |
| `gov_systems_admin` | Gov Systems Admin | **Undefined — to be specified.** |

- **Administrator** is oversight, not a report type.
- A user may hold several roles → may create/contribute to several types.
- **Content scoping is an extension point.** A type declares its content via a selector (a subset
  of systems and/or a subset of check categories). Only `system_admin` is populated today; adding a
  type later is config + a selector, not framework rework. Source of truth stays
  `generate_report.py` / `prometheus.yml` labels (NOT `systems_config.yml`, which is downstream).

---

## 5. State machines

### 5.1 Report status
```
        create                     submit
  (none) ─────► pending ───────────────────────► final
                  │                               (Complete | Incomplete)
                  └──── cancel ────► cancelled
```

### 5.2 Lock (only meaningful while `pending`)
```
 released ──(contributor takes it)──► locked_by:X
    ▲                                     │
    │   release (X)                       │
    ├─────────────────────────────────────┤
    │   idle > 5 min  (auto-release)       │
    │   Administrator force-release        │
    └─────────────────────────────────────┘
                     submit (X) ──► report becomes final (lock retired)
```

### 5.3 Completeness (computed at submit)
```
last := contributor with the highest position
complete := (submitter == last) AND (all contributors have taken_turn == true)
if not complete: incomplete_reason is REQUIRED
```

---

## 6. Data model

Extend the existing `ReportSubmission` (one table, single source of truth) plus two small related
models. Rationale: minimal surface; History already reads this table.

### 6.1 `ReportSubmission` — new/changed fields
| Field | Type | Notes |
|-------|------|-------|
| `report_type` | char choices | `system_admin` \| `network_admin` \| `gov_systems_admin`. Legacy rows → `system_admin`. |
| `status` | char choices | `pending` \| `final` \| `cancelled`. Legacy rows → `final`. |
| `snapshot_blob` | JSON | Frozen `Store` + systems + threshold values (see §7). Empty for legacy finals. |
| `lock_state` | char | `released` \| `locked`. Null/unused once `final`. |
| `locked_by` | FK User (null) | Current holder while `locked`. |
| `locked_at` | datetime (null) | When the current lock was acquired. |
| `lock_heartbeat` | datetime (null) | Last keep-alive; drives idle auto-release. |
| `completeness` | char (null) | `complete` \| `incomplete`. Set at submit. |
| `incomplete_reason` | text blank | Required when `completeness == incomplete`. |
| `submitted_by` | FK User (null) | Who submitted. |
| `submitted_at` | datetime (null) | When. |

Existing fields keep their meaning: `generated_by` = **creator/initiator**; `created_at` = creation;
`author`, `theme`, `delivery`, `recipients`, `summary_comment`, `annotations`, `report_content`,
`filename`, counts. `annotations` gains per-system attendance: `{flags, comment, attended_by_id,
attended_at}`.

### 6.2 `ReportContributor` (ordered list + turn tracking)
| Field | Type | Notes |
|-------|------|-------|
| `report` | FK ReportSubmission | |
| `user` | FK User | Must hold the report type's role at add-time. |
| `position` | int | Order; **max position = designated submitter**. |
| `added_by` | FK User | Creator or Administrator. |
| `added_at` | datetime | |
| `taken_turn` | bool | Set true the first time they acquire the lock. |
| `last_turn_at` | datetime (null) | |

Unique together `(report, user)`.

### 6.3 `ReportTurn` (audit trail = the "phases") — optional but recommended
| Field | Type | Notes |
|-------|------|-------|
| `report` | FK | |
| `user` | FK | |
| `action` | char | `take` \| `release` \| `auto_release` \| `force_release` \| `submit`. |
| `at` | datetime | |

### 6.4 Notifications
Reuse/extend the existing hamburger notification mechanism (currently computes pending role
requests on the fly). Add "reports available to you / your turn" events. Recommended: a small
generic `Notification(user, kind, ref, created_at, seen_at)` model so both role-requests and report
events flow through one system with the existing red-dot/seen logic. Minimum viable: compute on the
fly — for the current user, pending reports where they are a contributor and `lock_state=released`.

---

## 7. Snapshot freezing & serialization (the technical crux — Phase 1)

The final `.xlsx` is built by the engine from a `Store` + `systems` + `cfg`. To rebuild days later
with Prometheus offline, persist enough at creation.

**`Store`** (`reports/services.py`) fields are JSON-friendly with two caveats:
- `services: Dict[str, List[Tuple[str,bool,str,str]]]` — tuples → lists on save, lists → tuples on load.
- `cob`, `swift` may be `NaN` floats — serialize `NaN`/`None` explicitly (e.g. store `null`, restore as needed).

**`systems`** (`List[System]`): serialize each as `{name, components:[{label, target}]}`. Do **not**
serialize the `Service` check callables — at rebuild, reconstruct `System` objects from the frozen
`name`+`components` and **re-attach `SERVICE_CHECKS[_norm(name)]` from code** (they are static config,
already evaluated into `store.services`).

**`cfg`**: at rebuild, re-load `config.ini`; additionally snapshot the few numerics that affect
rendering (`overview_threshold`, `chip_amber`, `chip_red`) into `snapshot_blob` for exact fidelity if
config changes between create and submit.

`snapshot_blob` shape:
```json
{
  "store": { "...serialized Store..." },
  "systems": [ {"name": "...", "components": [{"label": "...", "target": "..."}]} ],
  "thresholds": {"overview_threshold": 85, "chip_amber": 75, "chip_red": 90},
  "captured_at": "ISO-8601"
}
```

**Acceptance for Phase 1:** a round-trip test — capture live, serialize, deserialize, build `.xlsx`,
and assert it equals (structurally) the `.xlsx` built directly from the live snapshot; and that the
rebuild path performs **zero** Prometheus calls.

---

## 8. Permissions / authorization

| Action | Allowed for |
|--------|-------------|
| Create report of type T | User holding T's role. |
| Be added as contributor on T | User holding T's role. |
| View a `pending` report | Its contributors + Administrators. |
| Take the lock (edit) | A contributor, when `lock_state=released` (or the current holder). |
| Release | Current holder, or Administrator (force-release). |
| Submit | Current holder (any contributor holding the lock); completeness computed. |
| Add / reorder / remove contributor | Creator or Administrator; adds limited to eligible same-role users; cannot remove someone who has taken a turn. |
| Cancel | Creator or Administrator. |
| Oversight (view all, force-release, submit-override) | Administrator. Administrators may only **edit content** where they also hold T's role. |

All enforced server-side (never trust the client); the existing `RoleRequiredMiddleware` +
role helpers are the basis.

---

## 9. User flows

### 9.1 Create
1. Admin opens **Create report**.
2. **Pre-create checkpoint:** if they are a contributor on any not-yet-submitted reports, show them
   (type, status `Released ▸ take it` / `Locked by X since T`) and nudge them to finish those first.
3. Pick **report type** (only types their roles permit; single-role → preselected).
4. Pick **contributors** (ordered, from eligible same-role users). Creator auto-added as #1.
5. Create → capture **live** metrics, freeze into `snapshot_blob`, `status=pending`,
   `lock_state=locked`, `locked_by=creator` (creator holds the first turn).

### 9.2 Contribute (a turn)
1. Contributor opens the report.
   - `released` → **Take report** button (acquires the lock atomically; see §10).
   - `locked_by me` → editable, with **Release** and **Submit**, plus a keep-alive ping.
   - `locked_by other` → **read-only**, "Locked by X since T".
2. The editor is the annotate form rendered from the **frozen** `report_content` (no Prometheus).
   Editing a system's answers/comment stamps `attended_by = me` on that system.
3. **Draft preview:** a "Download preview" builds a throwaway `.xlsx` from current state (nothing
   stored, no e-mail).
4. **Release** → `lock_state=released`, record `ReportTurn(release)`, mark `taken_turn`, notify the
   remaining contributors it is available. (Edits are already persisted — see §10 autosave.)

### 9.3 Submit
1. From a held lock, the holder clicks **Submit & e-mail**.
2. Compute completeness (§5.3). Warn + list any **unattended flagged systems** regardless.
3. If **incomplete**, require a written **reason** (a modal); include which contributors never took
   a turn for context.
4. Build the final `.xlsx` from `snapshot_blob` + final annotations, with **per-system "By" = each
   system's `attended_by`**, **summary "By" = submitter**.
5. E-mail to the report's recipients (reusing the existing mail engine).
6. Set `status=final`, `completeness`, `submitted_by/at`; the report now appears in History with a
   **Complete / Submitted incomplete** badge.

---

## 10. Concurrency, locking, keep-alive, auto-release

- **Atomic acquire:** `UPDATE report SET lock_state='locked', locked_by=me, locked_at=now,
  lock_heartbeat=now WHERE id=? AND (lock_state='released' OR heartbeat_expired)`. Row-count 1 = won
  the lock; 0 = someone else holds it. Prevents the two-people-take-it race.
- **Autosave:** edits persist to `annotations` as they are made (per system), so a release /
  auto-release / navigation never loses work.
- **Keep-alive:** while the holder is active (typing/interacting), the client pings (~60 s) to update
  `lock_heartbeat`. Idle = no ping.
- **Idle auto-release (5 min):** evaluated **lazily** (no background worker required) — on any access
  to the report, if `locked` and `now - lock_heartbeat > 5 min`, treat as `released` (and record
  `auto_release`). Optionally also a periodic sweep if a scheduler exists.
- **Force-release:** an Administrator can release a stuck lock at any time (`force_release`).

---

## 11. Engine change (report engine, `generate_report.py`)

`ReportBuilder` / `build_report_bytes` currently take a single `author` written into every "By" cell
(recent fix). Extend to accept a **per-system author map** and a **summary author**:
- `authors: Dict[str, str]` — system name → attending admin's display name (each card's "By").
- `summary_author: str` — the submitter (the summary/overall "By").
- Backward compatible: if only the single `author` is given (CLI/legacy), use it everywhere (current
  behaviour). No layout/structure change — only which name each existing "By" cell holds.

---

## 12. E-mail, History, Download changes

- **Remove** the standalone "Generate & e-mail" button from the create/annotate flow.
- **Download preview** stays but only as an unstored draft; the stored/e-mailed artefact is produced
  **only** by Submit.
- **History** filters `status=final`; the row/detail shows the **Complete / Incomplete** badge, the
  `incomplete_reason`, the contributor list with who took a turn, and the per-system attribution.
- **Reports in progress** = a new list of `pending` reports for the user's types.

---

## 13. Edge cases

- **Solo report** (creator is the only contributor and the last): behaves like today's flow through
  the new machinery; complete if the creator took a turn and submits.
- **Contributor added after others contributed:** their `taken_turn=false` counts toward the
  completeness check until they take a turn.
- **Last contributor never shows:** another contributor submits → incomplete + reason.
- **Mid-edit pause > 5 min:** keep-alive prevents release while genuinely active; if truly idle the
  lock frees, but autosave means no lost work; the next taker sees the latest state.
- **Simultaneous take:** atomic acquire ensures exactly one winner.
- **Prometheus down at submit:** irrelevant — rebuild uses `snapshot_blob`.
- **Config thresholds changed between create and submit:** use the snapshot's `thresholds` for
  fidelity.
- **User loses the required role while a contributor:** they can no longer take a turn (re-check at
  acquire time); an Administrator can remove/replace them.

---

## 14. Backward compatibility / migration

- Data migration for existing `ReportSubmission` rows: `status=final`, `completeness=complete`,
  `report_type=system_admin`, `submitted_by=generated_by`, `submitted_at=created_at`, one
  `ReportContributor(user=generated_by, position=0, taken_turn=true)`, `snapshot_blob={}` (legacy
  finals aren't rebuilt; their detail view uses the stored `report_content` as today).
- History behaviour for legacy rows is unchanged (they are `final`, `complete`).

---

## 15. Implementation phases (each independently testable, app stays working)

1. **Persist the snapshot.** Add `snapshot_blob`; serialize/deserialize `Store`+systems+thresholds;
   prove the final `.xlsx` rebuilds from the blob with Prometheus off (§7 acceptance). *No user-facing
   change yet.*
2. **Model + migration + History filter.** Add the new fields/models; migrate legacy rows; History
   filters `final`; detail shows completeness badge (trivially "complete" for legacy).
3. **Create/freeze flow.** Report-type + ordered-contributor picker (role-gated); create `pending`
   with the creator holding the lock; frozen capture.
4. **In-progress list + pre-create checkpoint + contribute screen.** Report-level lock: take /
   read-only / release; autosave; keep-alive; lazy 5-min auto-release; Administrator force-release.
5. **Submit.** Completeness algorithm; incomplete-reason prompt; unattended-systems warning;
   per-system "By" (engine change §11); e-mail; finalize. Remove standalone e-mail.
6. **Preview download + notifications.** Draft preview; notify contributors on release/their turn;
   polish.

---

## 16. Testing strategy

- **Serialization:** `Store` round-trip (incl. tuples, NaN); build-from-blob ≡ build-from-live;
  rebuild makes zero Prometheus calls.
- **Locking:** atomic acquire race (two takers → one wins); release; lazy auto-release after idle;
  force-release; autosave persists across release.
- **Completeness:** last-submits-all-contributed → complete; non-last → incomplete; missing turn →
  incomplete; incomplete requires reason.
- **Permissions:** create/contribute gated by role↔type; Administrator oversight vs contribute;
  add-contributor eligibility.
- **Attribution:** per-system "By" = attendant; summary "By" = submitter; legacy single-author path.
- **Flow:** e-mail only at submit; History shows finals with badge/reason; preview stores nothing.

---

## 17. Open items (small, decide at build time)

- Whether Administrators may *contribute* to any type or only where they hold the role (working
  default: oversight-yes, contribute-only-with-role).
- Reorder / remove-not-yet-contributed contributor operations (proposed: allowed for creator/Admin).
- Notification model vs on-the-fly computation (recommended: a small generic `Notification` model).
- The content selectors for `network_admin` / `gov_systems_admin` — **deferred until those reports
  are defined**; their existence is certain, their content is not yet specified.
