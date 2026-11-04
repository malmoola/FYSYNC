# fwsync

Offline firewall **compare** tool for Cisco FTD (LINA view) and ASA. Give it two config backups (`show running-config`
text) or two FMC devices/policies, and it tells you, **by value** (addresses and ports, not object names), what the
target firewall (B) is missing compared with the source (A), what B allows beyond A, and a ranked change plan with
FMC steps, CLI and verification commands. It can also copy selected items between FMC devices as a staged, disabled
change, and it never deploys.

- **1:1**: A -> B (one firewall replaced or backed up by another).
- **2:1**: A1 + A2 -> B, e.g. an edge firewall plus an inner firewall combined into one. The path is worked out from
  routing; flows that cross both get the intersection of both policies.
- Everything is auto-detected from the configs (interface roles and map, public ranges, scope); a profile is optional.
- Runs locally: a command line and a web UI on 127.0.0.1. No cloud, no telemetry, no network access except the FMC
  you point it at.

## Install

Download the release zip from the [Releases](../../releases) page and check its sha256 against the `.sha256` file.

### Windows (no admin rights, no Python needed)

1. `fwsync-<ver>-windows.zip`: right-click > Properties > tick **Unblock** > OK, then right-click > **Extract All**.
2. Double-click **`fwsync.cmd`**. If Windows shows "Windows protected your PC": **More info** > **Run anyway**
   (the zip is not code-signed; `python\python.exe` is the official signed python.org build).
3. First run: installs fwsync offline into the bundled `python\` folder (about a minute). Every run: starts the web UI
   on 127.0.0.1 (first free port from 8765) and opens your browser. Keep the window open; Ctrl-C or closing it stops it.

Without the `python\` folder the launcher falls back to an installed Python 3.12 (`py -3.12`, then `python`) and a
venv in `%LOCALAPPDATA%\fwsync\venv`. `selftest.cmd` checks the installation and writes `selftest-result.txt`.
Details, the command line and the **WSL** fallback: [WINDOWS.md](WINDOWS.md).

### macOS

1. `fwsync-<ver>.zip`, unzip. Needs Python 3.10+ (3.12 preferred, python.org or Homebrew).
2. Double-click `packaging/macos/fwsync.command` (first time: right-click > **Open** > Open; the zip is not signed).
   Or in Terminal: `xattr -dr com.apple.quarantine ~/Downloads/fwsync-<ver>`.
3. First run: creates `~/Library/Application Support/fwsync/venv` and installs offline from `vendor/wheels`. Every run:
   web UI on 127.0.0.1, browser opens; closing the Terminal window stops it. `packaging/macos/selftest.command` runs
   the selftest.

### Linux (and WSL)

```
unzip fwsync-<ver>.zip && cd fwsync-<ver>
python3 -m venv .venv
.venv/bin/pip install --no-index --find-links vendor/wheels "fwsync[web,yaml,fmc]"
.venv/bin/fwsync web
```
If `python3 -m venv` fails (Debian/Ubuntu without `python3-venv`): `python3 -m venv --without-pip .venv` and
`.venv/bin/python vendor/wheels/pip-*.whl/pip install --no-index --find-links vendor/wheels pip`.

Wheels are included for Windows x64, macOS arm64/x86_64 and Linux x86_64/aarch64, Python 3.10 - 3.13. From source:
`pip install ".[web,yaml,fmc]"`. Extras: `web` (UI), `fmc` (FMC REST API), `yaml` (YAML profiles), `test`.

## Safety defaults

- **Read-only by default.** Compare and `fmc-read` never change anything. The FMC reader sends GET requests only and
  refuses every other method itself; use an FMC user with a view-only role (see FMC REST API below).
- **Writing to FMC is off** unless all of these are true: `--apply`, `--allow-push`, the FMC host is listed in
  `~/.fwsync/fmc_allowlist.txt`, and a separate write user is given. Without `--apply` every copy and undo is a dry run.
- **Never deploys.** Every `/deployment` call is refused in every mode. Copied access rules are created disabled in the
  category `fwsync-staged`, NAT rules disabled; you review, enable and deploy in FMC yourself. An undo file is written
  after every change (`fwsync fmc-undo`), and a copy stops at the first FMC error.
- **TLS verified.** FMC certificates are verified by default; give the FMC or corporate CA with `--ca-bundle FILE`
  (or profile `fmc.ca_bundle`, or `FWSYNC_CA_BUNDLE`). `--insecure` exists for isolated labs and warns.
  `HTTPS_PROXY` / `NO_PROXY` are honoured.
- **Your data stays yours.** Reports, profiles, snapshots and undo files are written readable by your user only
  (mode 600, or an icacls grant to your user alone on Windows; fwsync warns if it cannot). The web UI listens on
  127.0.0.1 only. Keep reports out of shared folders and out of git (`.gitignore` excludes `reports/`, `prod/`,
  `*.json` except the samples).
- Passwords: `--cred FILE` (JSON, owner-only), `FWSYNC_FMC_PASSWORD` / `FWSYNC_FMC_WRITE_PASSWORD`, or a prompt.
  Nothing is stored by fwsync.

## FMC REST API

fwsync can read devices and policies from FMC instead of config backups, compare any two of them, and copy selected
items between them as a staged change. Nothing is ever deployed.

1. Create a view-only FMC user for reading (System > Users > User Roles > Create User Role: tick only Access Control
   Policy, Prefilter Policy, Device Management, NAT List and Object Manager, untick every "Modify ..." and "Deploy";
   then a user with only that role). FMC rejects every write from it, and the fwsync reader refuses non-GET calls itself.
2. Read: `fwsync fmc-read --fmc https://FMC --cred ro.json --device NAME --out snap.json [--lina]`
   (`ro.json` = `{"user": "...", "password": "..."}`, owner-only; or `--user` with `FWSYNC_FMC_PASSWORD` / a prompt).
3. Compare: `fwsync compare fmc:device:A fmc:device:B --fmc https://FMC --cred ro.json --out DIR`. A policy alone:
   `fmc:policy:ACP[,nat:NAT]` (zone names stand in for interfaces; give `--scope`). Snapshot files and LINA backups
   can be mixed with live reads.
4. Copy (dry run): `fwsync fmc-copy --fmc https://FMC --cred ro.json --from device:A --to device:B[,policy:ACP,nat:NAT]
   [--parts objects,routes,nat,rules] [--rules "rule 1,rule 2"] [--map AIFC=BIFC] --out DIR`.
   Apply: add `--write-user USER --apply --allow-push` (password from `FWSYNC_FMC_WRITE_PASSWORD` or a prompt) and put
   the FMC host name in `~/.fwsync/fmc_allowlist.txt` (`%USERPROFILE%\.fwsync\fmc_allowlist.txt` on Windows). Order: objects, routes, NAT (disabled), category
   `fwsync-staged`, access rules (disabled, in that category). Review in FMC, move the category, enable, deploy by hand.
5. Undo: `fwsync fmc-undo DIR/<prefix>_<time>_undo.json --fmc https://FMC --write-user USER --out DIR --apply --allow-push`.

Every report ends with the ranked known gaps (what fwsync does not see and how to check it by hand).

## Reading the results

The report starts with the firewall names (A = the site that fails, B = the site that takes over; both are called by
their real names below) and a short **How to read this report** (ready, not ready, check on firewall, thing to fix,
your choice needed, scope, translated address).

The **Takeover** tab and the report open on a runbook, in this order: **Fix before failover**, **Do during failover**
(for example no shutdown on interfaces that are shut on B), **Check on the firewall** (for example a route B may learn
by OSPF: run the given `show route` first), **Review later** (B allows more than A, objects with extra entries on B,
networks that belong to B itself) and **Can't be proven from this config**. The verdict sentence counts each group.

**Readiness** shows one line per network, not-ready first, then check-first, then ready:
`192.0.2.0/24 (VLAN 20 dmz) - Not ready: 1 thing to fix`, `... - Check on firewall: 1 thing to verify`, `... - Ready`,
or `... - <B>'s own network, not part of takeover` (B's own public subnet or VPN pool, left out of the counts), each with
a one-line reason. The card per network (Routing, Outbound internet (PAT), Published servers, Access rules, DNS changes,
Public IPs) is collapsed below.

**Findings**, one per issue, in order of work (routing, PAT, published servers, rules, objects). Each one leads with its
subnet and has the same four parts: **What's wrong**, **Why it matters**, **What to do** (FMC path and fields, LINA
reference CLI, objects to create first) and **How to verify** (packet-tracer / show commands), plus the evidence (the
exact config lines with line numbers, collapsed) and buttons **Fix / Not needed (reason required) / Later**, saved in
the profile.

Status words in the report are plain: "B allows more than A", "uses a different path than A", "same on both", "only
partly allowed", "blocked by an earlier rule", "your choice needed". JSON and CSV keep the internal values
(`over-permitted`, `wrong way`, `covered`, `partial`, `shadowed`). Long raw tables (settings, every object, coverage)
are collapsed under Details.

**Your choices** lists what the tool cannot decide: the target public IP pool (size, used, needed; enter an extra pool),
L7 rules whose action is unknown (block / permit), test / QA / dev servers (suggested Not needed), rules named
`[0 hits]` / `[VERIFY]`, public IP conflicts (one public IP mapped to two inside hosts, or a proposed IP that is a gap
inside a used block and may belong to a device not in the config).

**Remediation plan**: every finding marked Fix as an ordered change list grouped by FMC page (Objects, Routing, NAT,
Access Control, DNS), with counts and verify commands; export Markdown / CSV / HTML (`<prefix>_plan.*` from the CLI).
Nothing is pushed.

Device names: profile `names: {A: "Edge (FW-A)", B: "Backup site (FW-B)"}` (2:1: `A1`, `A2`) or `--name`.
Interfaces whose name looks like a VPN / tunnel are ignored by default (reason shown; override with `--map` or the
profile); a small transfer subnet with only a few specific routes behind it is only hinted. The raw tables are under
**Details (advanced)**; status words have tooltips. Per-subnet summary counts only rules that name the subnet; rules
that reach it through `any` (or a /8 or wider range) are counted in `rules_any`.

CLI: `--finding KEY=fix|later|"not needed:REASON"`, `--decision ID=CHOICE`, `--fix-all` (plan for every open finding).

## What it compares

| Area | Result per item |
|---|---|
| Access rules A -> B (A rules that touch the scope) | covered, partial, shadowed (an earlier B deny), denied, missing (only B's default action matches) |
| Access rules B -> A (B permits that touch the scope) | also on A, over-permitted (B allows traffic A does not), over-permitted (partial) |
| NAT (A NAT whose real address is in scope) | static, identity/exemption, dynamic, PAT, twice NAT: match, missing, inactive on B, differs, mapped conflict, mapped reuse, mapped outside B public |
| NAT B -> A | B NATs in scope: also on A, also on A (other public IP), B only |
| PAT | coverage per scope subnet on A and B, plus every address that is or is not translated today |
| Inbound readiness | each A static NAT with an inbound permit: B needs a static NAT and an inbound permit |
| DNS failover sheet | host, real IP, A public IP, B public IP (existing or proposed), ports |
| B public IP budget | statics needing a B public IP per scope subnet; total needed vs. free addresses in B's public ranges |
| Routing readiness | does B route every scope subnet out of the right interface (ok, other interface, wrong way, no route)? |
| Objects | missing on B, same name / different value, same value / different name; B -> A: B only |
| Summary | counts per category per scope subnet (first table of the HTML report, `<prefix>_summary.csv`) |

## Auto-detect

| Item | How |
|---|---|
| Interface roles | outside = holds the default route, or is the mapped side of a NAT with public addresses; inside = the rest (management/diagnostic and interfaces without an IP are ignored) |
| Subnets per interface | connected + static routes (longest prefix match) |
| Interface map A -> B | by role, then by name, security level, then B's routing of the A interface's subnets; many-to-one is noted, guesses are flagged |
| Public ranges | public outside-interface subnets + public NAT mapped addresses, summarised per /24 to the smallest covering prefix (an assumption: edit it if the allocation is larger) |
| Site type | shared public subnet when the two sides' public ranges overlap (B must use the same public IPs), else separate sites |
| Scope | every inside subnet, with names from VLAN, nameif and matching objects (default: all) |
| 2:1 path | an address A2 routes to an inside interface that A1 also routes to its inside is behind both. internet <-> such addresses = intersection (A2 first-match permits walked through A1 first-match); campus <-> DC = A2 rules only; everything else = A1 rules only. NAT comes from whichever firewall does it. The edge is the one doing public NAT (the order you give is corrected) |

**Ignore an interface**: map it to `ignore` (UI: B interface `ignore`; CLI `--ignore-ifc`; profile
`interface_map: {vpn1: ignore}`; in 2:1 use `A1:<nameif>` / `A2:<nameif>`). Rules that name it and NATs on it are
dropped, rules without an interface lose the addresses routed out of it, and its subnets leave the scope.

`FMC_INLINE_*` groups are FMC-generated rule literals: they are shown and generated as literal values, never as objects.

Outputs: HTML (filterable), one CSV per section, JSON. Report files are written readable by your user only (mode 600 on macOS/Linux,
an icacls grant to your user alone on Windows) because they contain your network data. Write them outside this folder.

## Run

Command line (no profile needed):
```
fwsync compare A.txt B.txt --out ~/fwsync-reports --prefix a-to-b                 # 1:1
fwsync compare EDGE.txt INNER.txt B.txt --out ~/fwsync-reports --prefix chain     # 2:1, B is always last
fwsync detect EDGE.txt INNER.txt B.txt --save-profile ~/fwsync-reports/p.json     # show / save what was inferred
fwsync compare A.txt B.txt --profile p.json --scope 10.1.0.0/16 --out ~/fwsync-reports   # override anything
fwsync compare EDGE.txt INNER.txt B.txt --ignore-ifc A1:vpn1,A1:vpn2 --public-b 192.0.2.0/24 --out ~/fwsync-reports
```
Try it on the samples (expected output in `samples/report/` and `samples/chain/report/`):
```
fwsync compare samples/edge-a.txt samples/edge-b.txt --out ~/fwsync-reports --prefix sample
fwsync compare samples/chain/edge.txt samples/chain/inner.txt samples/chain/target.txt --out ~/fwsync-reports --prefix chain
```

Web UI:
```
fwsync web            # first free port from 8765, opens the browser; --port N, --no-browser
```
Or open http://127.0.0.1:8765. Pick 1:1 or 2:1, load A (or A1 + A2) and B, press **Compare**. The **Auto-detected** panel
shows roles, interface map, public ranges, site type, the 2:1 chain path and the scope checkboxes; edit any of it and
press Compare again (the configs stay loaded). **Save as profile** downloads the edited profile as JSON (optional).
Then the summary per scope subnet, one tab per section (filter row, checkboxes), **Generate** for the CLI view and the
change list, and **Download HTML report**.

The UI listens on 127.0.0.1 only. To use it on a remote host, tunnel it:
```
ssh -L 8765:127.0.0.1:8765 user@analysis-host     # then browse http://127.0.0.1:8765 on your laptop
```

## Controls (UI, all saved in the profile)

| Control | What it does |
|---|---|
| Interfaces | one row per A interface (A1 and A2 in 2:1). **include** unticked = drop all its rules and NAT. **role**: outside / inside / chain link (the A1 <-> A2 link; overrides the routing guess) / ignore. **B interface**: any B interface, `ignore`, or **new on B...** (type a name: it is treated as existing for the compare and listed as a change item) |
| Scope | editable list: add any prefix with a name, edit, remove, all / none / filter / invert. **expand** shows the connected and static subnets under a summary (from A1, A2 and B) so you can tick only the ones you want. A warning appears when a scope prefix and a connected subnet share the network address but not the length, with a **use** button for the connected one |
| What-if on B | planned routes (prefix -> B interface, next hop), public ranges, interfaces, NAT pools (PAT). They are treated as already on B and appear as PLANNED items in the change list and CLI view |
| Row control | per row in every tab: include / exclude / not needed (with a reason); bulk for all rows shown by the filter. Excluded and not-needed rows leave the counts and the summary; not-needed rows are hidden unless you tick "show" |
| Rule actions | per rule: as config / permit / block / ignore; bulk **mark as block** by name filter. An L7 rule whose name looks like a block (`l7_suspect` pattern: block, blocklist, deny, drop, unwanted, trojan, stratum miner) is **action unknown (L7)** until you confirm it: it is listed but takes no part in the compare. `block` on an L7 rule = **blocked (L7)** (permits nothing; it denies nothing either, because its L7 condition is not in the config text); `block` on an L4 rule = deny |
| Profile | **Save profile** downloads everything above as JSON; **Profile** (file) loads one before Compare. **Compare again** re-runs with the edits without re-uploading the configs |

Every L7 rule carries `action_check = action unknown (L7)` (rules tab, CSV, counts `l7_actions`) until its action is set
to permit in the profile; rules held out (suspect block names) or marked block are listed in **held_rules** and never
appear in the gap list or the generated changes.

Command line equivalents (repeatable flags, same keys as the profile): `--profile`, `--scope`, `--scope-add PREFIX=NAME`,
`--ignore-ifc`, `--map AIFC=BIFC` (BIFC may be `ignore` or a new B name), `--role AIFC=ROLE`, `--public-b`,
`--whatif-route PREFIX=BIFC@NEXTHOP`, `--whatif-public PREFIX`, `--whatif-ifc NAME=ROLE`,
`--whatif-nat REAL=MAPPED@IN,OUT`, `--exclude ROWKEY=REASON`, `--not-needed ROWKEY=REASON`, `--rule-action RULE=ACTION`,
`--save-profile FILE` (row keys are the `key` field in the JSON report).

## Profiles (optional)

`profiles/example.yaml` (commented) and `profiles/example.json`. Keys: `scope`, `scope_names`, `type`
(`auto`, `standard` or `shared-edge`), `interface_map`, `outside_a` / `outside_b`, `public_a` / `public_b`,
`public_map`, `public_pool_b`, `rename`, `zone_map`, `fmc`, and since 0.3.0 `roles_a` ({nameif: outside|inside|chain link|ignore}),
`whatif` ({routes: [{prefix, ifc, nexthop}], public: [...], interfaces: [{name, role}], nat_pools: [{real, mapped, in_ifc, out_ifc}]}),
`rule_actions` ({rule name or A1:/A2:name: permit|block|ignore}), `l7_suspect` (regex), `row_state`
({row key: {state: exclude|not needed, reason}}). Every key you leave out is auto-detected.

## Known gaps (ranked)

| # | Gap | Impact | Workaround |
|---|---|---|---|
| 1 | Application, URL, user and SGT conditions are not compared | Allow/trust rules with such conditions are compared as plain L3/L4 permits (wider than reality); block rules with them are left out. FMC snapshot: the rule name is listed in the warnings. | Check those rules by hand in FMC. |
| 2 | FlexConfig, Security Intelligence and tunnel endpoints are not read from FMC | A FlexConfig ACL or an SI block list changes the real result. Prefilter rules and the tunnel default are read (fastpath = trust, block = deny); tunnel rules match by encapsulation only, not by tunnel endpoint zones. | Compare the LINA backup (show running-config) as well when FlexConfig or SI block lists are used. |
| 3 | IPv6 is ignored | IPv6 objects, rules and routes are skipped (warning per object). | Review IPv6 rules separately. |
| 4 | FQDN, dynamic and geolocation objects have no addresses | Rules that use them match nothing in the compare (reported as unknown object or empty). | Resolve them by hand; fwsync lists the object names. |
| 5 | Copy: static routes are active on the next deploy | FMC has no disabled state for a static route; access rules are staged disabled and NAT rules disabled, routes are not. Route tracking (SLA monitor) is not copied. | Copy routes only to the target you will deploy, or use --parts objects,nat,rules. |
| 6 | Copy: objects with the same name and another value are not changed | The target keeps its value; rules copied to it use the target value. | The plan lists every "on B with ANOTHER value" object; fix it before enabling the staged rules. |
| 7 | Copy: auto NAT, PAT pools, port translation, interface overrides and object overrides are not copied | Only manual NAT rules are copied (disabled); the rest appear in the compare report only. | Add them by hand from the compare findings. |
| 8 | Copy: rule position | Staged rules are appended to the "fwsync-staged" category; their order relative to other categories is FMC's category order, not the source order. | Move the category to the right place before enabling a rule. |
| 9 | Policy-only compare has no routing | Without a device, zone names stand in for interfaces: routing readiness, PAT and public IP results are not meaningful. | Compare devices (fmc:device:NAME) for routing and NAT. |
| 10 | Source ports, time ranges, VLAN tags, intrusion/file policy and logging are not compared | Two rules that differ only in these are reported as the same. | Check rule details in FMC for critical rules. |
| 11 | FTD LINA rules with L7 conditions show "action unknown (L7)" | In a LINA backup the real action of such a rule is only in FMC. | Use an FMC snapshot of the same device. |
| 12 | Dynamic routing is listed, not evaluated | BGP/OSPF learned routes are not part of routing readiness (only connected and static). | Add what-if routes (--whatif-route) for prefixes learned by BGP. |

## Tests

```
python -m pytest -q tests                      # synthetic configs only (documentation and private test ranges)
python scripts/selftest.py --root . --venv /tmp/st --wheels vendor/wheels   # offline install + checks
```
CI (`.github/workflows/ci.yml`) runs the tests and the selftest on Windows, macOS and Linux (Python 3.10 and 3.12),
then builds both zips with `scripts/build_release.py` and selftests each zip on its OS. A `v*` tag publishes them with
their sha256 files as a GitHub Release.

Build locally: `python scripts/fetch_wheels.py` (all wheels into `vendor/wheels`, lists any missing), then
`python scripts/build_release.py` (both zips into `dist/`, from `git archive HEAD`).
