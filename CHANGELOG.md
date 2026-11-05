# Changelog

## 0.5.5 – 2026-11-05

Tables you can actually read.

- Details tables sit in a box that fits the window, with a horizontal scrollbar along the top as well as the bottom.
  Before, the only horizontal scrollbar was at the very end of a table that could be thousands of pixels tall.
- Long cells (scope, intersected_with, detail and similar) show 3 lines; click one to see all of it. Column filters
  still search the full text.
- Both header rows stay visible while scrolling. Summary per scope subnet is collapsed so the table starts higher.
- The HTML report gets the same box and long-cell behaviour.
- FMC read: Interface Groups now work like security zones. Before, a NAT rule kept the group name as if it were one
  interface, and an access rule using a group lost its interfaces and was left out. A rule on a group that holds both
  inside and a shut shared interface is judged on each member, so it covers today's path and the outage path.
- macOS: the launcher only picks Python 3.10 to 3.13, and the README says so. The bundled wheels do not cover 3.14.

## 0.5.4 – 2026-11-04

Remediation fixes that are safe to follow. A wrong fix is worse than no fix: where the tool cannot be sure, the item
says what to check and gives no command.

Wrong fixes:

- Published servers: the proposed NAT and access rule use the interface the server is behind on B (A's real
  interface mapped to B, or B's route for the address), never the generic inside interface. When neither is known,
  the item is "Check first" with no NAT command.
- An L7 rule that shows as any to any in LINA is never copied: "Compare in FMC: URL, application or geo conditions
  are not visible", with a warning that copying it without its conditions would allow all traffic. It is never
  copied, and counts as coverage only in the narrow case described under "Corrections from real configs".
- Objects: an object B already has (by name or by value) is never created again. A B object with the same name and
  another value is used as it is, never redefined, and the item says what to check. Translated addresses use B's
  object for that address, not A's name.
- Edit, not add: a B NAT for the server on the wrong interface, or a B rule with the same addresses on other zones,
  is edited. Option `any` for a NAT that must work both before and after takeover. A zone that carries traffic from
  the other site today is kept and the new zone added; a zone that carries nothing is replaced.

False positives:

- Inbound rules are judged per A rule, with its real source, ports and interfaces, not from an any source; the same
  source list and ports on B is "same", not "partial".
- Rule status follows first match on both sides: a block A has above the permit takes that traffic on A too, so an
  equal B block before the permit is "same". Tunnel default rules (ipinip, 41, gre, teredo) are skipped.
- Policy routing that only sends traffic to the ISP B's default route already uses needs no action (explained).
- Reusing A's own public IP on B in a shared range, or two B NATs for the same server, is not a conflict.
- Site twins (each site its own server and public IP on translated addresses) read "each site has its own"; no
  conflict, no object to create, no DNS change.
- "Rule cannot match" is optional cleanup when another rule carries the traffic or the source only exists at A.
- No duplicate findings (a server published by object and manual NAT is one finding) and no item without an action.
- Object differences use expanded values before and after site translation; a group that names A's own addresses
  on purpose is "same".

New checks:

- NAT first match after takeover for each published server: a broader rule above the server's rule (for example an
  identity NAT on any interface) is flagged; when it is needed today the fix is "Do during failover" with the exact
  new interface and section.
- B NATs (also dynamic PAT objects) whose real addresses are not behind their real interface.
- Outbound PAT per ISP: A has it on each ISP, B on only some; B's existing PAT address for that ISP is reused.
- NATs a shared network lacks that A has for it or that a sibling network has on B: inside users to public, VPN pool
  to the network, VPN pool to public addresses, identity NAT. Reported only with the concrete rule to add.
- FQDN rules are matched by object name (or FQDN) and port, and reported when A allows them above a block and B has
  no match.
- Copying a block lists the A allows above it that B lacks first, with a warning that the block alone would cut those
  hosts off. The block is proposed disabled.
- A block in a different place among the allow rules (above them on one side, below on the other).
- Remote-access VPN interfaces are compared through the interface map, with each headend's interfaces and addresses.
- Can't be proven: where FMC lives and whether it can deploy to B when A is lost (a go/no-go, also in the verdict),
  and how the servers on shared networks start at B.
- A B static route whose next hop is on no B subnet (not installed, so a public range is not advertised), with the
  outbound PAT that depends on it.

Corrections from real configs (regressions the first 0.5.4 tests missed):

- L7 coverage: an L7 permit ip from a specific source zone to any, whose name does not suggest a block (a final
  "allow all from inside"), counts as coverage again; every row it covers says "confirm in FMC". An L7 any-to-any
  rule with no source zone or a block-like name is not coverage, and the same L7 rule on both sides is "same".
- Block names: `_` and `-` separate words, so Block_X_to_Y is seen as a block. A rule whose name suggests a block is
  never proposed as Action Allow: "Confirm the action in FMC", no CLI.
- Any to any: an L7 rule whose any was narrowed by an ignored interface is still "Compare in FMC". A last check over
  every finding, takeover step, runbook and failback item strips any permit whose source and destination are both
  any, turns the item into "Compare in FMC" and counts it (`safety` in the result, and a warning).
- Backhaul identity NAT: an identity NAT on B whose addresses are behind a shut interface is live today. It is a
  "Do during failover" edit to the shut interface in After Auto NAT, with a failback step and the published servers
  (auto and manual NATs below it) it would otherwise override.
- NAT precedence: a rule is broader only if its addresses contain the server's. A host inside a server group is a
  partial overlap, for review, with no reorder.
- No `no nat` or replacement for a rule that may be live outside a proven during-failover change: the check item
  gives show commands and the edit in words. A NAT for the VPN pool on the VPN interface is review only.
- VPN pools: A's ip local pool maps to B's pool before the compare; new rules use B's pool object (or a new object
  named after B's pool, with B's addresses), never A's pool.
- Sibling NATs: no gap by analogy with an unrelated sibling network, and none when B has the same NAT for its own
  twin of the subnet.
- FQDN rules: L7 rules held as blocks by their name count as blocks below an FQDN allow, so the allow is a real gap
  when B has no rule with that object and port.
- A PAT rule on the wrong interface is one finding with one fix (edit it, keep B's translated address); no extra
  "add PAT" or takeover item for it.
- Add zone: when the new zone is still shut, the zone the rule uses today is kept, in the rule findings and in the
  "source moves" check.
- New public objects reuse A's object name; `dns` is kept on a NAT; standby fixes use A's standby address and B's
  mask; "Published, no NAT" items say what to confirm, with the real addresses.
- A config compared with itself (a healthy pair) gives no fixes: a B block equal to an A block above the rule is
  skipped also when an ignored interface narrowed A's any, when the A block is on one interface and the rule on any,
  and for published servers; PAT is not reported when B translates all that A does; a NAT check is not reported
  when A has the same rule; a rule whose source A also routes elsewhere keeps A's interface; the reverse compare
  leaves out addresses behind ignored A interfaces.
- A rule walk that splits into too many address parts stops splitting (no more than 64), and skips rules that miss
  all of what is left with one check.

Gap list (the default view):

- The report and the web UI open on one table of what B is missing compared to A, and nothing else: Gap, When,
  Address, Object, A (line), B today (line), Required on B, Config. When is Now, Now disabled, At outage, Decision,
  Confirm use, If route needed, Compare in FMC or Only if allow-listed. Rows sort by When, then Gap, and the verdict
  counts are the rows. The runbook, findings and plan stay below as the older view. CSV: `*_gaplist.csv`.
- NAT is a first-match walk, not a name or set match. Every active A NAT line is placed where its real subnet lives on
  B (connected interfaces, also shut ones, then static routes, then the interface map, then inside) and walked through
  B's NAT in real order: manual before auto, auto static first then longest prefix, manual after auto, with real and
  mapped interfaces (also any) and destination-limited rules. Each line is OK same IP (also A's IP through B's dynamic
  PAT), OK B public IP (never a gap), OK site device, Wrong source interface, Missing PAT, Missing static NAT, Missing
  VPN NAT, Missing internal NAT, Missing NAT exemption, Change at outage or Hairpin PAT.
- A catch-all PAT covers only the traffic that enters its interface. A NAT exemption is checked per CIDR and is a gap
  only where B would translate that traffic; a destination-limited identity NAT on B covers it. NAT with destination
  translation is real translation, never "no NAT".
- A second walk with the proposed fixes applied reports the exemptions a fix makes necessary ("needed because of the
  fix").
- Change at outage: a B rule that is right today because the subnet's own interface is shut and the traffic arrives
  through another one, and an identity NAT above B's static NATs, are steps at outage with their failback, not gaps
  to fix now.
- A static NAT with no inbound rule on A, whose traffic B's PAT (or a proposed PAT) translates, is "Only if
  allow-listed".
- NAT fixes: a rule on the wrong interface is edited, never added twice; a new PAT uses the address B's sibling
  subnets use; a new static NAT reuses A's public IP when B already has NATs in that block (added disabled, enabled at
  outage), and is otherwise a Decision with no placeholder object; a NAT that could answer ARP or change traffic today
  is added disabled; a hairpin PAT is "Confirm use". A PAT inside a wider proposed PAT is not proposed again.
- Rules, one result per A rule name: an L7 rule whose LINA line is broad is "Compare in FMC"; another L7 rule is
  copied in FMC with its conditions and no LINA line; a Block* rule that shows permit is an L7 block, never covered,
  shadowed or an allow, and is a Missing block placed below B's rules for the allows above it on A. Missing L4 blocks
  have their objects and position. Addresses on B's rule but not on the zone where they live are "Wrong zone": add
  the zone to the existing rule. Site twin rules match.
- FQDN: an A FQDN allow is a gap when B has no rule naming that FQDN and B's first rule for the traffic is a block
  (also an L7 block held by its name). The old check only looked for an A block below the A rule, never at B's rules,
  so a block on B was missed although the known gaps said FQDN allows were reported.
- "B allows more than A" is a review section, never a gap.
- Other checks: OSPF "default-information originate always" on A is an outage item (with A's firewalls up and its
  internet down, inside traffic keeps going to A). Both outage cases are listed (A's internet down with its firewalls
  up: shut A's shared interfaces first; A's firewalls lost). B NAT lines that use a public block routed to A's ISP are
  one dependency item with their count, which packet-tracer cannot prove.
- Reference views: every A NAT line and every A rule name (also inactive rules and rules with no lines) with B's
  match and the result, and the missing objects marked needed or not needed by what the gap list uses.
- Safety: no output may hold an any-to-any permit, a Block* rule as an allow, a placeholder public object, or
  `no nat` for a B rule that carries traffic today. The guard strips a live `no nat` from every output (the backhaul
  identity step is now an FMC edit with show commands).

Timing and safety:

- Every fix is Fix before failover, Do during failover, Check on the firewall or Review later, by whether it could
  change traffic that works today. A static route that would move live traffic is a during-failover step (routes
  cannot be added disabled). A NAT that would change live traffic is created disabled, with an enable step in the
  runbook.
- A route lists the A NAT exemption it depends on, with B's state.
- New Failback list: one step per during-failover change, in reverse order (report, web UI, JSON `failback`).
- Test commands use a host whose NAT matches the claim (not one a more specific NAT catches) and state the expected
  NAT; a test on a shut interface says it can run only after the interface is up.
- Tests: tests/test_054 and tests/test_054b (28 cases for the corrections above, made-up names and documentation
  addresses, each failing on the first 0.5.4 commit). Three test_054 cases follow the new rules: an L7 allow-all from a
  zone is coverage (7c), a NAT check item gives show commands (15), a sibling-only NAT gap is not reported (17b).
  tests/test_054c covers the gap list (one or more cases per numbered behaviour, plus a guard that fails on any
  any-to-any permit, Block* allow, placeholder public object or live `no nat`). Three test_054b backhaul cases now
  expect the FMC edit instead of `no nat` plus a new line.

### Takeover compare, second round on the real pair

- VPN NAT with destination translation is copied as A's rule: same section and options, source identity with B's
  active pool (the pool a tunnel group hands out), and A's destination real and mapped objects. A's pool object is
  never used on B.
- A PAT with source interface any stays any on B, with B's active pool as one object (no split by B's rules, no
  connected interface chosen). A PAT out of another interface than B's main path (its default route with the lowest
  distance) is Confirm use. A's VPN pool traffic is taken to enter on A's VPN interface.
- A's NAT options are copied (dns, destination static, unidirectional, no-proxy-arp, route-lookup), and none are
  added: exemptions no longer get no-proxy-arp and route-lookup when A's line has neither.
- A B static with real and mapped interface any is no longer B's own choice when B exempts the same traffic toward
  its other shared interfaces: the Missing NAT exemption is reported for the interface that lacks it, with B's source
  group.
- An L7 Block* rule on A's site interface is equal to B's block on the mapped interface when B's rule is named the same
  way with the site mapping and has the same LINA line on the mapped zones (also any to any); it is not listed under
  Compare in FMC.
- Block position text is true: a B rule is said to carry an A allow only when that A allow is above the block in A's
  order and takes some of its traffic, and the allow is named with its line. The block goes above the first B allow
  that lets any of its traffic through (and so above the broad allow after it).
- A copied "destination static" keeps B's object of the same name (an any-network object stays that object, never the
  keyword any), else uses B's object with the same value, else adds the object in the row's config.
- Route rows carry route commands only; the NAT a route depends on is judged by the NAT walk.
- The NAT reference result no longer depends on set order when two results tie.
- Docs: shared interfaces and the unreachable-address assumption are described in the README and known gaps.

### Takeover compare on a real pair (A primary, B takes over)

Root causes found by comparing one real pair end to end; every fix is general logic with a synthetic test
(tests/test_054d.py).

- Shared interfaces are chosen by identical IP address and subnet on both firewalls where B's copy is shut until
  takeover. Only those are shut in the "internet down, firewalls up" steps (and brought up on B). The same addresses
  up on both firewalls are two separate site networks.
- "Not hit on A": when A learns routes (OSPF, BGP) a line is no longer cleared by A's static routes; only A's
  connected subnets and an earlier A line that takes the traffic first count. The gap list stats count the lines
  that still use this result.
- A wrong-interface PAT is one row on the PAT line. A static NAT for a host in that subnet stays its own row: Missing
  static NAT when A has an inbound rule for it, else "Only if allow-listed".
- A B static for the same host and public IP on another interface is a Change at outage that edits that rule, never
  a second rule.
- An identity NAT on B moves at outage only when it takes traffic to a static's public IP (destination any, the
  static's address inside it). Identity NATs with a specific destination are left alone.
- Source "any" is the traffic entering that real interface; it is no longer expanded into A's routed subnets, which
  could include outside or public B blocks.
- Rules: coverage ignores rule names (same or broader addresses and ports on the mapped zones). A rule only B has
  gives Wrong zone only when an A rule B does not carry today needs that zone.
- FQDN allows: an FQDN object written "fqdn [v4] NAME id N" is read correctly, and its ACE lines are no longer dropped
  when an interface is ignored. Every line is compared; a B block that would stop one gives one Missing allow,
  positioned above that block. An any-to-any L7 block (URL categories) cannot prove it stops the traffic.
- L7 Block* rules match only a B block on the same mapped zones that holds their addresses and ports; one that is any
  to any in LINA is "Compare in FMC" unless B has the same rule with the same lines.
- Blocks are placed above B's first rule that would allow their traffic, below the narrower B rules carrying allows A
  has above the block. The report never says to add an A allow first. Assumption: a B block that lacks only private or
  shared address space B's config sends only out of its outside default route (and no crypto map) is equal; B can
  learn routes dynamically that the config does not show (listed in the known gaps).
- New NAT brings the A exemptions above it (second pass, also for internal and reused static NATs). A NAT or
  exemption whose real interface is shut on B, or that could answer ARP, is "Now disabled".
- One row per A line and interface pair: an exemption that splits into CIDRs and B lines is one row, above the
  first B line it needs to precede ("the proposed rule" for a proposed one; no "line 0").
- An exemption whose destination A routes with its own static route and B routes another way is "If route needed".
  An exemption or internal NAT to any is compared for the networks B routes out of that interface, so a B NAT
  limited to the group of all inside networks covers a destination-any NAT on A.
- A public IP in a block where B has a single isolated NAT line is a Decision with no NAT command (two or more B lines
  show that the block moves with B).
- Site devices ("OK, site device"): NATs that only reach the ISP edge or gateway, statics whose only inbound rules
  come from the edge routers (and lines that share their public IP), public IPs in B's own block, hosts whose B twin
  in the same rules has its own public NAT, and exemption parts caught by B's own static NAT for a host A has no NAT
  for. A subnet B reaches through an interface of its own is B's site network.
- Scanner and other L7 rows for a rule B has on fewer zones say which zone to add. Inbound rules to a host whose
  public IP is a decision are a Decision row.
- The top verdict is the gap list's; the older runbook keeps its items and its own text (verdict.runbook_text).

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
