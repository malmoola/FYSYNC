"""Synthetic LINA configs (RFC 5737 / RFC 1918 documentation-style values only)."""
A = """: Saved
NGFW Version 7.4.0
hostname edge-a
interface Port-channel1.10
 vlan 10
 nameif inside
 ip address 10.10.0.1 255.255.255.0 standby 10.10.0.2
interface Port-channel2
 nameif outside
 ip address 198.51.100.2 255.255.255.0
object network WEB1
 host 10.20.0.10
object network WEB2
 host 10.20.0.11
object network LAN20
 subnet 10.20.0.0 255.255.255.0
object network RANGE1
 range 10.20.0.100 10.20.0.110
object network NAME1
 fqdn www.example.com
object network PUB_WEB1
 host 198.51.100.10
object network PUB_WEB2
 host 198.51.100.11
object network PAT_LAN20
 host 198.51.100.20
object-group network INNER
 network-object object WEB1
 network-object host 10.20.0.12
object-group network OUTER
 group-object INNER
 network-object 10.30.0.0 255.255.0.0
object-group service WEBPORTS tcp
 port-object eq www
 port-object eq https
object-group service MIXED
 service-object tcp destination range 8000 8010
 service-object udp destination eq domain
access-list CSM_FW_ACL_ remark rule-id 100: ACCESS POLICY: EDGE-ACP - Mandatory
access-list CSM_FW_ACL_ remark rule-id 100: RULE: Web-In
access-list CSM_FW_ACL_ advanced permit tcp ifc outside any ifc inside object-group INNER object-group WEBPORTS rule-id 100
access-list CSM_FW_ACL_ remark rule-id 101: RULE: Lan-Out
access-list CSM_FW_ACL_ advanced permit ip ifc inside object LAN20 ifc outside any rule-id 101
access-list CSM_FW_ACL_ remark rule-id 102: RULE: Mixed
access-list CSM_FW_ACL_ advanced permit object-group MIXED ifc inside object LAN20 ifc outside any rule-id 102
access-list CSM_FW_ACL_ remark rule-id 103: L7 RULE: Web2-In
access-list CSM_FW_ACL_ advanced permit tcp ifc outside any ifc inside host 10.20.0.11 eq 443 rule-id 103
access-list CSM_FW_ACL_ remark rule-id 9: L4 RULE: DEFAULT ACTION RULE
access-list CSM_FW_ACL_ advanced deny ip any any rule-id 9
access-group CSM_FW_ACL_ global
route outside 0.0.0.0 0.0.0.0 198.51.100.1 1
nat (inside,outside) source static WEB1 PUB_WEB1
nat (inside,outside) source static WEB2 PUB_WEB2 description web two
nat (inside,outside) after-auto source dynamic LAN20 interface
object network RANGE1
 nat (inside,outside) dynamic PAT_LAN20
route inside 10.20.0.0 255.255.255.0 10.10.0.254 1
"""

B = """: Saved
hostname edge-b
interface GigabitEthernet0/0
 nameif OUTSIDE
 ip address 203.0.113.2 255.255.255.0
interface GigabitEthernet0/1
 nameif INSIDE
 ip address 10.10.0.5 255.255.255.0
object network WEB1
 host 10.20.0.10
object network WEB-ONE-RENAMED
 host 10.20.0.11
object network LAN20
 subnet 10.20.0.0 255.255.254.0
object network B_PUB_WEB1
 host 203.0.113.10
object network B_PUB_WEB2
 host 203.0.113.11
access-list CSM_FW_ACL_ remark rule-id 200: RULE: Block-8000
access-list CSM_FW_ACL_ advanced deny tcp ifc INSIDE any ifc OUTSIDE any range 8000 8010 rule-id 200
access-list CSM_FW_ACL_ remark rule-id 201: RULE: Web-In
access-list CSM_FW_ACL_ advanced permit tcp ifc OUTSIDE any ifc INSIDE host 10.20.0.10 eq www rule-id 201
access-list CSM_FW_ACL_ remark rule-id 202: RULE: Lan-Out
access-list CSM_FW_ACL_ advanced permit ip ifc INSIDE 10.20.0.0 255.255.255.0 ifc OUTSIDE any rule-id 202
access-list CSM_FW_ACL_ advanced deny ip any any rule-id 9
access-group CSM_FW_ACL_ global
nat (INSIDE,OUTSIDE) source static WEB1 B_PUB_WEB1
nat (INSIDE,OUTSIDE) source static WEB-ONE-RENAMED B_PUB_WEB2 inactive
route INSIDE 10.20.0.0 255.255.255.0 10.10.0.254 1
route OUTSIDE 0.0.0.0 0.0.0.0 203.0.113.1 1
"""

PROFILE = dict(name='t', scope=['10.20.0.0/24'], scope_names={'10.20.0.0/24': 'VLAN 20'},
               interface_map={'inside': 'INSIDE', 'outside': 'OUTSIDE'}, outside_a=['outside'], outside_b=['OUTSIDE'],
               public_pool_b=['203.0.113.50-203.0.113.52'], zone_map={'INSIDE': 'Z_IN', 'OUTSIDE': 'Z_OUT'},
               fmc={'access_policy': 'ACP-B', 'nat_policy': 'NAT-B'})
