# Changelog

## 0.5.3 – 2026-11-03

Takeover check: can B carry the traffic when A fails.

- Default scope is every subnet the firewall serves, not only interfaces classed as inside.
- Site translation: site-specific subnets are matched (same subnet, then name, then shared host numbers) and A is
  rewritten into B's addresses before the compare, so rules, NAT and objects are judged as they must be on B.
- Traffic follows B's routes: a source behind a tunnel on B is checked on that tunnel.
- A broad L7 rule whose name says block no longer covers everything on B, which hid real gaps.
- New whole-config compare with a coverage ledger: interfaces, OSPF, policy routing, path tracking, HA, VPN, AAA, DNS,
  inspection, certificates, management, logging, SNMP, timeouts. Every running-config line lands in one category.
- Every A object is listed with its translated value and its match on B.
- New Takeover tab, report section and CSV exports. Shut interfaces, missing standby IPs, missing PBR, OSPF networks and
  items a config cannot prove are listed with an action.

Report and UI wording, for an engineer who has never seen the tool:

- The Takeover tab and the report are a runbook: Fix before failover, Do during failover, Check on the firewall,
  Review later, Can't be proven from this config. Each item names its subnet or interface, the reason and the action;
  the verdict sentence gives the count per group. Shut interfaces, standby IPs and OSPF networks are one item each.
- Readiness lines read "192.0.2.0/24 (VLAN 20 dmz) - Not ready: 1 thing to fix", "... - Check on firewall: 1 thing to
  verify" or "... - Ready", with correct singular and plural and a one-line reason. Not-ready networks come first.
- Every finding and runbook item has the same four parts: What's wrong / Why it matters / What to do (FMC path and
  CLI) / How to verify.
- The report starts with the A = / B = mapping and uses the real firewall names after that, then a short "How to read
  this report". Plain status words replace jargon on screen ("B allows more than A", "uses a different path than A",
  "same on both", "only partly allowed", "blocked by an earlier rule", "your choice needed"); JSON and CSV keep the
  internal values. Decisions is now "Your choices".
- Long raw tables (settings, every object, coverage, whole-firewall checks) are collapsed under Details; tables scroll
  sideways on a small screen instead of widening the page.

Fixes:

- Next hop of a proposed static route: the lowest-distance route on that interface, broadest non-default first. A
  floating route (distance 250, or a backup for a prefix another route carries with a lower distance) is never used;
  with no good route the CLI shows `<next hop on IFACE>`.
- When B runs OSPF or BGP, a missing static route is "Check first" (counted as "to check on the firewall", not as a
  thing to fix). The first step is `show route <ip>` on B: if it points to the expected interface, no change is needed;
  if it points elsewhere, add the route given.
- A B object group with every A address plus extra entries (status `B has extra entries`) is a low-priority note, not
  a Readiness action; an object whose B value is wider than A's is a note too. Only A addresses missing from B are a
  thing to fix, and the fix lists them.
- Networks owned by B (inside B's outside subnet, a B VPN pool, or B's public range when the sites do not share one)
  read "B's own network, not part of takeover" and are left out of the verdict counts. Routing rows carry `b_own`.
- "VLAN" is used only for a connected subnet; routed subnets are a "network", a /32 a "host".
- Findings lead with the subnet. Route labels ("via inside"), chain tags ("A1:inside") and object names such as
  obj-NO_NAT-x are no longer used as network names.
- B rules that allow more than A are Review later items, not things to fix before failover.
- A subnet on a shut-down B interface is never "Ready", whether it is connected there or routed behind it. It reads
  "... - Do during failover: bring up IFACE on B", the reason line carries the same action (also when the subnet has
  other things to fix), and the runbook gets one "Do during failover" item per shut interface.
- "B would send it to the internet" is said only when B's matching route is its default route. When a broader
  non-default route matches, the finding reads "B uses IFACE via ROUTE; A uses IFACE" and the reason says "No specific
  static route".
- Public addresses published on A with no NAT on B ("Other public addresses with no NAT on B") are Review later items
  with the action "Decide which of these must work after failover", not things to fix before failover. A published
  server that already has its own finding is not listed again, so each one is counted once.
- Names no longer end with a double bracket ("(DMZ-WEB on A))"), and routing protocols are listed once ("OSPF", not
  "OSPF, OSPF").

## 0.5.2 – 2026-11-03

Accuracy fixes from a real FTD pair.

- Interface match: the same connected subnet now wins over name and role. A name match with different subnets and a
  fallback match are flagged.
- Roles: an interface with a private address and a default route elsewhere is no longer outside because of a public
  NAT. `route ... tunneled` is no longer treated as a default route.
- Routing findings name the route that actually matches. No static route is proposed for a subnet that is not on the
  expected B interface.
- PAT: every default-route exit is checked, `source dynamic any` on a real interface counts, and the fix uses the
  subnet's own interface.
- Reverse rule compare: a B rule with an identical mapped A permit is `also on A`, even if a narrow A deny sits above it.
- New whole-firewall checks: A blocks missing on B, published A addresses with no B NAT, B rules whose source is not
  behind their source interface.

## 0.5.1 – 2026-11-03

Windows support. Native Windows with a bundled Python is the main path; WSL is the fallback. No .exe, no code signing.

- `fwsync-<ver>-windows.zip`: the official Python 3.12 embeddable package (win_amd64, sha256-pinned) in `python\`
  with `site-packages` enabled, `vendor\wheels` (win_amd64 + pure), `fwsync.cmd` (double-click: first run installs
  offline into `python\`, then the web UI opens in the browser), `selftest.cmd`, `README-FIRST.txt`. Without
  `python\` the launchers fall back to `py -3.12`, then `python`, with a venv in `%LOCALAPPDATA%\fwsync`. Clear
  messages for SmartScreen / downloaded-file marks (offers Unblock), files missing (run from inside the zip), port in
  use and a failed install.
- Paths through pathlib; settings in `Path.home()/.fwsync` (`%USERPROFILE%\.fwsync`); no shell-outs that need bash.
- Config input: utf-8, utf-8 with BOM, then cp1252; CRLF, LF and CR line endings (files, web uploads, profiles,
  allowlist, credential files). Reports and other output written as UTF-8.
- Owner-only files (`fwsync/osutil.py`): chmod 600 on macOS/Linux; on Windows `icacls /inheritance:r /grant:r` for the
  current user's SID (falls back to `%USERNAME%`), then the DACL is read back (Win32 API, locale independent) and
  explicit entries of other accounts (e.g. SYSTEM / Administrators copied from a 0o700 folder) are removed with
  `icacls /remove:g`. Reports, profiles, snapshots, copy plans, undo files. A failure is a warning naming the file,
  never silent.
- Web UI: 127.0.0.1 only, first free port from 8765 (`--port N` fails with a clear message when taken), opens the
  default browser (`--no-browser`), clean Ctrl-C / Ctrl-Break stop on Windows (no fork, no POSIX-only signals, one
  worker, no reload); `__main__` spawn guard.
- FMC API: **TLS certificate verification is now on by default** (0.5.0 did not verify). `--ca-bundle FILE`, profile
  `fmc.ca_bundle` or `FWSYNC_CA_BUNDLE` for the FMC or corporate CA; `--insecure` for isolated labs (warns).
  `HTTPS_PROXY` / `NO_PROXY` honoured. A failed verification exits with a message naming the fix.
- `scripts/fetch_wheels.py`: wheels for win_amd64, macOS arm64 and x86_64, Linux x86_64 and aarch64, cp310 - cp313,
  including compiled ones (pydantic-core, PyYAML, charset-normalizer, tomli) and Windows-only dependencies (colorama);
  lists any missing wheel. `scripts/build_release.py`: both zips and their sha256 from `git archive` (a clean tree),
  refuses to ship reports, `prod/`, venvs or caches.
- Selftest (`scripts/selftest.py`, `selftest.cmd`, `packaging/macos/selftest.command`): offline install, test suite,
  synthetic compare 1:1 and 2:1, web UI 10 s on 127.0.0.1 and clean stop, report protection check;
  `selftest-result.txt`.
- CI (`.github/workflows/ci.yml`, replaces `build.yml`): tests + selftest on windows-latest, macos-14 and
  ubuntu-latest with Python 3.10 and 3.12; both zips built and selftested on their OS (the Windows zip with its
  bundled Python only); a `v*` tag publishes them with sha256 files as a GitHub Release. No secrets;
  `contents: write` only on the release job. The PyInstaller app/exe and signing jobs are gone.
- Wheels and the bundled Python are no longer committed (`vendor/wheels/`, `python/` in `.gitignore`); fetched at
  build time.
- Tests: 29 new (paths, CRLF/BOM/cp1252, icacls mocked off Windows and real on Windows, port selection, web bind,
  TLS/CA/proxy); test data uses documentation and private test ranges only.

## 0.5.0 – 2026-11-01

- FMC REST API reader (`fwsync fmc-read`, `fwsync/fmc.py`): reads a device (interfaces, static routes, assigned access
  control policy, prefilter policy, NAT policy, objects) or a policy alone into a JSON snapshot (mode 600). GET only:
  the client refuses every other method; use an FMC user with a view-only role. Real ACP actions: Allow -> permit,
  Trust -> trust, Block / Block with reset / interactive -> deny, Monitor left out, default action and prefilter
  (fastpath -> trust, block -> deny, tunnel default) included, disabled rules inactive.
- FMC snapshots are rendered as the LINA the FTD compiles (rule-id = the FMC rule id, FMC_INLINE groups, nat, route)
  and read by the LINA adapter (`fwsync/adapters/fmc_json.py`), so every compare, finding and report works on them.
- Compare any two devices or policies: `fwsync compare fmc:device:A fmc:device:B --fmc URL --user RO` (or
  `fmc:policy:NAME`, snapshot files, LINA files, mixed). Snapshots are kept next to the report.
- Staged copy through the FMC API (`fwsync fmc-copy`): objects -> routes -> NAT -> rules, dry run unless `--apply`;
  `--apply` needs `--allow-push` and the FMC host in `~/.fwsync/fmc_allowlist.txt`. Access rules are created disabled
  in the category `fwsync-staged`, NAT rules disabled; references are resolved by name on the target FMC; same-name
  objects with another value are reported, never changed. Never deploys (deployment endpoints are refused). Stops at
  the first FMC error. An undo file is written after every change; `fwsync fmc-undo` deletes newest first (dry run
  unless `--apply --allow-push`, and only on the FMC that the undo file names).
- Known gaps, ranked, in every report (HTML, `<prefix>_gaps.csv`, plan Markdown/HTML, JSON `known_gaps`, web UI plan
  tab, copy and undo reports).
- Packaging: extra `fmc` (requests); the macOS launcher installs `fwsync[web,yaml,fmc]` so the FMC commands work from
  its venv. The .app stays the offline web UI.

## 0.4.2 – 2026-10-31

- NAT first-match order (`fwsync/natorder.py`): manual NAT section 1 in order, then auto NAT (static before dynamic,
  smaller real first), then manual after-auto; a rule matches its interface pair or (any,any)-style wildcards; twice NAT
  with a destination does not translate or shadow general traffic.
- Effective translation per scope subnet (first match per address range) drives the PAT rows and findings; rules that
  can never match are flagged "never hit: covered by line N" (statics: outbound only; inbound to the mapped address
  still applies). The NAT detail table lists order, line, kind (shared / 1:1) and never-hit rules.
- PAT finding source = what the source firewall really translates (e.g. a /26 many-to-one static), default target
  interface PAT; a subnet covered only by 1:1 statics on the target counts as no PAT.
- Public IPs for static NAT = size of the mapped object (a /26 mapped to one host = 1 address).

## 0.4.1 – 2026-10-31

- Published servers: one target access rule per source rule, with the same name, the same source objects
  (FMC_INLINE_src groups expanded into their named members) and the same ports; source "any" only when the source
  rule uses any/any4. Network and port objects (and group members) are listed to create first.
- Rule findings grouped by FMC rule name (one finding per rule, not per CLI line). A rule whose in-scope destinations
  are all published servers is folded into those servers' findings (`folded_rules`).
- PAT findings translate only the sources the source firewall translates (e.g. a host group, not the whole subnet)
  and default to the target's interface PAT; "match A's address" is a decision (default: interface).
- Public IPs split per scope into (a) published servers with no target NAT (counted), (b) static NATs with no inbound
  rule (decision "keep the outbound identity?", counted only if kept, by address count) and (c) PAT addresses (only
  with "match A's address"). The pool decision shows the math and appears only when IPs are needed. Readiness and the
  plan use the same count.
- Access Control steps say where: Mandatory section, above the first broad target rule (e.g. Site-Default-Out, or
  "so above it" when that rule is in the Default section), numbered in the source firewall's rule order.
- DNS: every inbound fix is listed; without a target public IP it shows "pending public IP".
- Routing verify is `show route <host>` only.

## 0.4.0 – 2026-10-31

Results redesigned around findings.
- Readiness page: verdict and six-line card per scope subnet (Ready / Action needed / Decision needed).
- Findings: what / why / evidence with config line numbers / fix (FMC steps, LINA CLI, objects first) / verify
  (packet-tracer, show), sorted routing -> PAT -> published servers -> rules -> objects; Fix / Not needed (reason) /
  Later saved in the profile (`finding_state`).
- Decisions: public IP pool (extra pool -> suggestions), L7 unknown action, test/dev servers, [0 hits]/[VERIFY] rules,
  public IP conflicts (incl. proposed IPs in a gap of the used block).
- Remediation plan grouped by FMC page (Objects, Routing, NAT, Access Control, DNS) with verify commands;
  Markdown / CSV / HTML export; objects that already exist on the target are not re-created.
- Plain language and device names everywhere (`names`, `--name`); status tooltips (glossary).
- VPN / tunnel interfaces ignored by default with the reason shown.
- Per-subnet summary counts only rules that name the subnet (`rules_any` for rules via any).
- Raw tables under Details (advanced). CLI: --finding, --decision, --fix-all, --name.

## 0.3.2 – 2026-10-31

- Every L7 rule is flagged `action unknown (L7)` (column `action_check`, count `l7_actions`) until the profile sets
  its action; rules held by a block-like name or marked block move to a separate `held_rules` section and never reach
  the gap list or the generator. Chain (2:1) rows inherit the flag from both rules.
- CLI flags for every control: --map, --role, --scope-add, --whatif-route / -public / -ifc / -nat, --exclude,
  --not-needed, --rule-action, --save-profile on compare.
- Profile key `scope_add` (prefixes added to the auto-detected scope).
- macOS launcher: Python 3.12 preferred, first free port from 8765.

## 0.3.1 – 2026-10-31

- macOS launcher `packaging/macos/fwsync.command` (zsh): finds Python 3.10+, one-time offline venv in
  ~/Library/Application Support/fwsync, free port, opens the browser, stops with the Terminal window.
- Native app: PyInstaller spec + pywebview window (`packaging/macos/fwsync_app.py`), placeholder icon,
  entitlements; GitHub Actions workflow builds fwsync.app + dmg (macos-14) and fwsync.exe (windows-latest) on tags,
  optional signing / notarization from secrets.
- UI: HTML report download works inside the native window (download link instead of a new window).

## 0.3.0 – 2026-10-31

Granular control.
- Interfaces: include checkbox, role (outside / inside / chain link / ignore), B interface incl. `ignore` and
  "new on B" (planned interface, listed as a change).
- Scope editor: add / edit / remove with names, bulk all / none / filter / invert, expand summaries into the
  connected / static subnets of A1, A2 and B, warning + fix when a prefix length differs from the connected subnet.
- What-if on B: planned routes, public ranges, interfaces, NAT pools; used in the compare and listed as PLANNED.
- Row control in every tab: exclude / not needed with reason, bulk by filter; stable row keys saved in the profile.
- Rule action overrides (permit / block / ignore) and bulk "mark as block"; L7 rules with block-like names are
  "action unknown (L7)" until confirmed.
- Profile load in the UI; every control saved in the profile.
- Tests: backup-site routing readiness case, what-if, L7 actions, interfaces, scope checks, row states.

## 0.2.1 – 2026-10-31

- Interface map value `ignore` (UI option, `--ignore-ifc`, profile): drops rules naming the interface and NATs on it;
  interface-less rules lose the addresses routed out of it; its subnets leave the scope and the 2:1 regions.
- `--public-b` CLI override.
- Profile `interface_map` entries now override single interfaces; the rest is still auto-detected.
- Tests for ignore (1:1, 2:1, "any" rules stay out of inbound readiness).

## 0.2.0 – 2026-10-31

"Just load the backups": no profile needed.

- Auto-detect (`fwsync/detect.py`): interface roles (default route / public NAT), connected + routed subnets per
  interface (longest prefix match), interface map by role, name, security level and routing with flags, public ranges,
  site type (shared public subnet vs separate sites), scope candidates with friendly names. `fwsync detect` shows it and
  `--save-profile` writes it.
- 2:1 mode (`fwsync/chain.py`): edge + inner firewall combined into one virtual firewall; path from routing;
  intersection policy for flows that cross both, single-firewall rules elsewhere; edge found by its public NAT.
- New sections: access rules B -> A (over-permitted), NAT B -> A, objects B -> A, routing readiness, summary per scope
  subnet (HTML + CSV); public IP budget total (needed vs free in B's ranges).
- NAT kinds: identity / exemption and twice NAT compared with destination; `differs` status; inactive B statics
  reserve their public IPs; mapped conflicts on a shared public subnet.
- `FMC_INLINE_*` groups are treated as literals (display, object compare, generator).
- FTD `L7 RULE` lines flagged.
- Web UI rebuilt: mode radio, A / A1 + A2 / B uploads, one Compare button, editable Auto-detected panel, Save as
  profile, summary table, HTML report download. Push removed from the UI (out of scope for 0.2.0).
- CLI: `fwsync compare A B` or `fwsync compare A1 A2 B`; profile optional.
- Tests: synthetic 1:1 and 2:1 cases (intersection, over-permit, routing, identity/twice NAT, FMC_INLINE, web API).

## 0.1.0 – 2026-10-31

First release.

- LINA adapter (FTD `show running-config`, ASA): interfaces (nameif, IP, VLAN, standby), routes, network objects
  (host/subnet/range/fqdn), nested network and service groups, protocol/port ranges, `CSM_FW_ACL_` with policy and
  rule names from the rule-id remarks (`RULE:`, `L4 RULE:`, `L7 RULE:`), plain ACLs with `access-group`, twice NAT
  (before/after auto), object NAT, static/dynamic/PAT, inactive, description, destination and service translation.
- Value-based compare (address and port interval sets), A -> B or B -> A: access rules (covered / partial / shadowed /
  denied / missing), NAT (match / missing / inactive / mapped conflict / reuse / outside public range), PAT coverage
  per scope subnet with per-address detail, inbound readiness, DNS failover sheet, B public IP budget, objects.
- Profiles in JSON or YAML: scope, interface map, public IP map or pool, rename rules, zone map, shared-edge mode.
- Reports: HTML (filterable tables), CSV per section, JSON; written with mode 600.
- Generator: FMC REST payload bundle in dependency order with a dry-run plan, LINA CLI view, change list.
- Guarded FMC push (`--allow-push`, allowlist, dry run first, skips existing names).
- Web UI (FastAPI, 127.0.0.1 only).
