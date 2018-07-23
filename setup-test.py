#!/usr/bin/python


import cps
import cps_object

cps_obj = cps_object.CPSObject('dell-base-if-cmn/if/interfaces/interface')
VLAN_ID=100
cps_obj.add_attr("base-if-vlan/if/interfaces/interface/id",VLAN_ID)
cps_obj.add_attr('if/interfaces/interface/type','ianaift:l2vlan')
if_port_list=['e101-001-0','e101-002-0']
cps_obj.add_attr('dell-if/if/interfaces/interface/untagged-ports',if_port_list)
cps_update = {'change':cps_obj.get(),'operation': 'create'}
cps.transaction([cps_update])

for iface in ["br100", "e101-001-0", "e101-002-0"]:
    cps_obj = cps_object.CPSObject('dell-base-if-cmn/if/interfaces/interface')
    cps_obj.add_attr('if/interfaces/interface/name',iface)
    cps_obj.add_attr('if/interfaces/interface/enabled', 1)
    cps_update = {'change':cps_obj.get(),'operation': 'set'}
    cps.transaction([cps_update])


