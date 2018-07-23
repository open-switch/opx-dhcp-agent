#!/usr/bin/python

'''Mac Search routines for the DHCP Agent'''

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

import os
import struct
from inocybe_dhcp.cps_helpers import add_filter
from inocybe_dhcp.cps_helpers import del_filter

# FDB format
# struct __fdb_entry {
#   __u8 mac_addr[ETH_ALEN];    a6  6
#   __u8 port_no;               c   1
#   __u8 is_local;              c   1
#   __u32 ageing_timer_value;   l   4
#   __u8 port_hi;               c   1
#   __u8 pad0;                  c   1
#   __u16 unused;               S   2
# };
#

DHCPS = 67
DHCPC = 68

class FDB(object):
    '''A python representation of the linux bridge forwarding
       database. By default reads from sysfs and expects a linux
       bridge instance. Read methods can be overriden to support
       other backends.'''

    def __init__(self, bridge):
        self._bridge = bridge
        self._macs = {}
        self._ifaces = {}
        self._refresh()

    def _findportno(self, iface):
        '''Get the ifindex of an interface'''
        with open("/sys/class/net/{bridge}/brif/{iface}/port_no".format(
            bridge=self._bridge, iface=iface)) as ifile:
            return int(ifile.read(), 0)

    def _refresh(self):
        '''Refresh the FDB state'''
        self._macs = {}
        self._ifaces = {}
        for port in os.listdir("/sys/class/net/{}/brif".format(self._bridge)):
            self._ifaces[self._findportno(port)] = port
        with open("/sys/class/net/{}/brforward".format(self._bridge)) as fdb:
            data = fdb.read(16)
            while data is not None and len(data) > 0:
                mac0, mac1, mac2, mac3, mac4, mac5, portno, islocal, aging = \
                    struct.unpack("BBBBBBBBL", data)
                self._macs["{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}".format(
                    mac0, mac1, mac2, mac3, mac4, mac5
                    )] = {"ifname": self._ifaces[portno], "age":aging, "islocal":(islocal > 0)}
                data = fdb.read(16)

    def lookup(self, mac, refresh=True):
        '''Lookup a Mac'''
        if refresh:
            self._refresh()
        return self._macs.get(mac)

class Filters(object):
    '''A python representation of the set of filters needed to make
       a dhcp agent work.'''
    def __init__(self, ifname, trusted=None):
        self._ifname = ifname
        self.server_filter_id = None
        self.client_filter_id = None
        self.trusted = trusted
        self.setup()

    def setup(self):
        '''Setup the filters for this bridge instance'''
        self.server_filter_id = add_filter(
            self._ifname, DHCPS, 512, 'snoop-dhcps-{}'.format(self._ifname), exclude=self.trusted)
        self.client_filter_id = add_filter(
            self._ifname, DHCPC, 512, 'snoop-dhcpc-{}'.format(self._ifname), exclude=self.trusted)

    def cleanup(self):
        '''Delete any filters for this interface'''
        del_filter('snoop-dhcps-{}'.format(self._ifname))
        del_filter('snoop-dhcpc-{}'.format(self._ifname))

    def refresh(self):
        '''Reload the interface - after ports change, etc'''
        self.cleanup()
        self.setup()

    def __del__(self):
        '''Cleanup upon removal'''
        self.cleanup()
