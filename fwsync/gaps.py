"""Known gaps, ranked by how likely they are to make a result wrong (1 = check first). Printed in every report."""

GAPS = [
    (1, 'all', 'Application, URL, user and SGT conditions are not compared',
     'Allow/trust rules with such conditions are compared as plain L3/L4 permits (wider than reality); block rules with '
     'them are left out. An L7 rule that shows as any to any in LINA is never copied, never a match and never coverage: '
     'it is a "Compare in FMC" item. FMC snapshot: the rule name is listed in the warnings.',
     'Check those rules by hand in FMC.'),
    (2, 'all', 'FlexConfig, Security Intelligence and tunnel endpoints are not read from FMC',
     'A FlexConfig ACL or an SI block list changes the real result. Prefilter rules and the tunnel default are read '
     '(fastpath = trust, block = deny); tunnel rules match by encapsulation only, not by tunnel endpoint zones.',
     'Compare the LINA backup (show running-config) as well when FlexConfig or SI block lists are used.'),
    (3, 'all', 'IPv6 is ignored',
     'IPv6 objects, rules and routes are skipped (warning per object).', 'Review IPv6 rules separately.'),
    (4, 'fmc', 'FQDN, dynamic and geolocation objects have no addresses',
     'Rules that use them match nothing in the compare (reported as unknown object or empty).',
     'Resolve them by hand; fwsync lists the object names.'),
    (5, 'fmc', 'Copy: static routes are active on the next deploy',
     'FMC has no disabled state for a static route; access rules are staged disabled and NAT rules disabled, routes '
     'are not. Route tracking (SLA monitor) is not copied.',
     'Copy routes only to the target you will deploy, or use --parts objects,nat,rules.'),
    (6, 'fmc', 'Copy: objects with the same name and another value are not changed',
     'The target keeps its value; rules copied to it use the target value.',
     'The plan lists every "on B with ANOTHER value" object; fix it before enabling the staged rules.'),
    (7, 'fmc', 'Copy: auto NAT, PAT pools, port translation, interface overrides and object overrides are not copied',
     'Only manual NAT rules are copied (disabled); the rest appear in the compare report only.',
     'Add them by hand from the compare findings.'),
    (8, 'fmc', 'Copy: rule position',
     'Staged rules are appended to the "fwsync-staged" category; their order relative to other categories is FMC\'s '
     'category order, not the source order.',
     'Move the category to the right place before enabling a rule.'),
    (9, 'all', 'Policy-only compare has no routing',
     'Without a device, zone names stand in for interfaces: routing readiness, PAT and public IP results are not '
     'meaningful.', 'Compare devices (fmc:device:NAME) for routing and NAT.'),
    (10, 'all', 'Source ports, time ranges, VLAN tags, intrusion/file policy and logging are not compared',
     'Two rules that differ only in these are reported as the same.', 'Check rule details in FMC for critical rules.'),
    (11, 'lina', 'FTD LINA rules with L7 conditions show "action unknown (L7)"',
     'In a LINA backup the real action of such a rule is only in FMC.', 'Use an FMC snapshot of the same device.'),
    (12, 'all', 'Dynamic routing is listed, not evaluated',
     'BGP/OSPF learned routes are not part of routing readiness (only connected and static). When B runs OSPF or '
     'BGP, a missing static route is a "Check on the firewall" item, not a thing to fix.',
     'Run the show route command each check item gives, or add what-if routes (--whatif-route) for learned prefixes.'),
    (13, 'all', 'Before / during failover is judged from the config only',
     'Whether a fix could change traffic that works today comes from the routes and interface state in the config '
     '(a route on a shut interface is not installed). Learned routes and real traffic are not seen.',
     'Check the hit counts (show access-list, show nat detail) of a "Fix before failover" NAT or route on B before '
     'making it.'),
    (14, 'all', 'FQDN objects are matched by name or FQDN and port',
     'Their addresses are not resolved. Every ACE line of an A FQDN allow is compared on its own: it is a Missing allow '
     'when B has no rule naming the same FQDN and B\'s first rule for that line is an L4 block or an L7 block whose LINA '
     'line is not any to any (an any-to-any L7 block, such as a URL category block, cannot be proven to stop it), or '
     'when an A block below it would take its traffic. A B allow with any on the FQDN side counts as allowing it.',
     'Resolve critical FQDN objects by hand.'),
    (15, 'lina', 'Site translation pairs private subnets only',
     'A site-specific subnet is paired only when both sides are private and the same size; other twins are compared '
     'as they are.', 'Set the interface map, or compare the twin servers by hand.'),
    (16, 'all', 'FMC reach and server start-up are not in any config',
     'Where FMC lives, whether it can deploy to B when A is lost, and how the servers on shared networks start at B '
     'are listed as items to prove, with a go/no-go for FMC reach.', 'Confirm them before the takeover window.'),
    (17, 'lina', 'An L7 allow-all is trusted by its shape and name only',
     'A permit ip from a source zone to any, with a name that does not suggest a block, is taken to allow the narrower '
     'rules below it; its URL or application conditions are not visible, so each such row says "confirm in FMC".',
     'Open the L7 rule in FMC and check that its conditions allow that traffic.'),
    (18, 'lina', 'VPN pools are paired by order',
     "A's ip local pool maps to B's pool in the order they are defined (or to B's only pool).",
     'With several pools on each side, check that each new rule names the right B pool.'),
    (19, 'lina', 'The NAT walk places a subnet by B\'s routes',
     'Where an A subnet lives on B comes from B\'s connected interfaces (also shut ones), then B\'s static routes, then '
     'the interface map, then inside; a subnet B reaches through an interface of its own (no A counterpart) is B\'s '
     'site network. A NAT limited to a service matches only the same service; a destination rule matches only when the '
     'A destination is inside it; an exemption or internal NAT to any is compared for the networks B routes out of that '
     'interface. When A learns routes (OSPF, BGP), an A line is only taken as "not hit on A" for its connected subnets '
     'or when an earlier A line takes the traffic first; the gap list stats count those lines.',
     'Check the reference view "Every A NAT line" for a subnet placed on the wrong interface.'),
    (20, 'lina', 'A public block "routed to A\'s ISP" is A\'s outside subnet',
     'A B NAT whose public address is in A\'s outside subnet (and not in B\'s) depends on A\'s ISP routing that block to '
     'B at outage. Other public blocks routed to A by the ISP are not visible in a config.',
     'Confirm every public block with the ISP; packet-tracer cannot prove it.'),
    (21, 'lina', 'Rule and NAT gaps follow the LINA view of an FTD',
     'A Block* rule that shows permit is taken as an L7 block: it matches only a B block on the same mapped zones that '
     'holds its addresses and ports, and one that is any to any in LINA is "Compare in FMC" unless B has the same rule '
     'with the same lines. An L7 rule with any (or a /8 or wider) on a side is "Compare in FMC", and other L7 rules are '
     'copied in FMC with their conditions.',
     'Compare the L7 rules in FMC, or use an FMC snapshot.'),
    (22, 'lina', 'Site devices are recognised from the config',
     'An A NAT is "OK, site device" when it only reaches the ISP edge or gateway (the next hops of the outside routes), '
     'its only inbound rules come from those edge routers, its public IP is in B\'s own outside block or shared with '
     'such a line, or B\'s rules of the same names hold another host with its own public NAT (B\'s twin). An exemption '
     'part caught by B\'s own static NAT for a host A has no NAT for (or a static on every interface) is B\'s own '
     'device.', 'Check the "OK, site device" lines in the NAT reference view when a device must move at takeover.'),
    (23, 'lina', 'A block is equal when what B lacks is unreachable through B',
     'An assumption: a B block on the same mapped zones counts as equal when the only addresses it lacks are private or '
     'shared address space that B\'s config sends only out of its outside default route, with no crypto map that could '
     'carry them. B can learn routes dynamically (OSPF, BGP) that make them reachable another way; the config does not '
     'show that. Blocks are placed above B\'s first rule that would allow any of their traffic, below the B rules that '
     'carry an A allow that is above the block in A\'s order and takes some of its traffic.',
     'Run show route for those addresses on B, and check the position of each new block in FMC before enabling it.'),
    (24, 'lina', 'Shared interfaces are chosen by address',
     'An interface is shared when B has an interface with the identical IP address and subnet and B\'s copy is shut '
     'until takeover. Only those are shut on A in the "internet down, firewalls up" steps and brought up on B. The same '
     'addresses up on both firewalls are taken as two separate site networks; names are not compared.',
     'If a stretched network is up on both firewalls today, add its shutdown step by hand.'),
]


def ranked(area='all'):
    return [{'rank': r, 'area': a, 'gap': g, 'impact': i, 'workaround': w} for r, a, g, i, w in GAPS
            if area == 'all' or a in ('all', area)]


def text(area='all'):
    return 'Known gaps (ranked):\n' + '\n'.join('%2d. %s - %s' % (g['rank'], g['gap'], g['workaround'])
                                                  for g in ranked(area))


def markdown(area='all'):
    rows = ['## Known gaps (ranked)', '', '| # | Gap | Impact | Workaround |', '|---|---|---|---|']
    rows += ['| %d | %s | %s | %s |' % (g['rank'], g['gap'], g['impact'], g['workaround']) for g in ranked(area)]
    return '\n'.join(rows)


def html(area='all'):
    import html as h
    rows = ''.join('<tr><td>%d</td><td>%s</td><td>%s</td><td>%s</td></tr>' % (
        g['rank'], h.escape(g['gap']), h.escape(g['impact']), h.escape(g['workaround'])) for g in ranked(area))
    return ('<h2 id="gaps">Known gaps (ranked)</h2><table><tr><th>#</th><th>Gap</th><th>Impact</th><th>Workaround</th>'
            '</tr>%s</table>' % rows)
