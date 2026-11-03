"""Known gaps, ranked by how likely they are to make a result wrong (1 = check first). Printed in every report."""

GAPS = [
    (1, 'all', 'Application, URL, user and SGT conditions are not compared',
     'Allow/trust rules with such conditions are compared as plain L3/L4 permits (wider than reality); block rules with '
     'them are left out. FMC snapshot: the rule name is listed in the warnings.',
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
     'BGP/OSPF learned routes are not part of routing readiness (only connected and static).',
     'Add what-if routes (--whatif-route) for prefixes learned by BGP.'),
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
