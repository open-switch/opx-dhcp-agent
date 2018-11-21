#!/usr/bin/env python

'''CPS Helpers for the DHCP IO Library'''

# Copyright (c) 2018 Inocybe Technologies.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
# LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
# FOR A PARTICULAR PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT.
#
# See the Apache Version 2.0 License for specific language governing
# permissions and limitations under the License.

import cps_utils
import cps
import nas_os_utils
import nas_acl

IFNAME = "if/interfaces/interface/name"
IFOBJ = "dell-base-if-cmn/if/interfaces/interface"
PORTS = "dell-if/if/interfaces/interface/untagged-ports"
TBL_ID = 1 # we may decide to use our own table - check
UDP = 17

#E_STG = {'INGRESS': 1, 'EGRESS': 2}
#E_FTYPE = {'IN_PORTS': 7, 'IN_PORT': 9, 'L4_SRC_PORT':17, 'L4_DST_PORT':18, 'IP_PROTOCOL': 20}
#E_ATYPE = {'PACKET_ACTION': 3}
#E_PTYPE = {'DROP': 1, 'COPY_TO_CPU': 3, 'TRAP_TO_CPU': 5, 'COPY_TO_CPU_CANCEL_AND_DROP': 6}

def get_ports(bridge):
    '''A simple function to return the openswitch perception of the port
       list in a vlan'''
    cps_obj = cps_utils.CPSObject(IFOBJ, data={IFNAME:bridge.encode('ascii')})
    cps_result = []
    if not cps.get([cps_obj.get()], cps_result):
        return None
    result = []
    for value in cps_result[0]['data'][PORTS]:
        result.append(cps_utils.cps_attr_types_map.from_data(PORTS, value))
    return result

def _add_filter(ports, udp_port, prio, entry_name, exclude=None):
    '''Add a filter for a port which drops the packet to CPU so that
       the DHCP agent can work on it'''

    ifaces = []
    for port in ports:
        if exclude is not None and ifaces != exclude:
            ifaces.append(nas_os_utils.if_nametoindex(port))
    entry = nas_acl.EntryCPSObj(table_id=TBL_ID, entry_id=entry_name, priority=prio)
    entry.add_match_filter(filter_type="IP_PROTOCOL", filter_val=UDP)
    entry.add_match_filter(filter_type="L4_DST_PORT", filter_val=udp_port)
    entry.add_match_filter(filter_type="IN_PORTS", filter_val=ifaces)
    entry.add_action(action_type="PACKET_ACTION", action_val="TRAP_TO_CPU")
    cps_upd = ({'operation':'create', 'change':entry.data()})
    return cps.transaction([cps_upd])


def add_filter(bridge, udp_port, prio, entry_name, exclude=None):
    '''Add a filter for a port which drops the packet to CPU so that
       the DHCP agent can work on it'''
    return _add_filter(get_ports(bridge), udp_port, prio, entry_name, exclude=exclude)

def del_filter(name):
    '''Delete a filter based on its unique ID returned by set_filters'''
    cps_obj = cps_utils.CPSObject(module='base-acl/entry', data={'table-id': TBL_ID, 'name':name})
    cps_upd = ('delete', cps_obj.get())
    cps_trans = cps_utils.CPSTransaction([cps_upd])
    return cps_trans.commit()
