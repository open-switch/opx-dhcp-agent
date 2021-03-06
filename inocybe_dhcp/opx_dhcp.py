#!/usr/bin/env python

'''DHCP message parsing and construction.'''

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

#import inocybe_dhcp.cps_helpers
import logging
from select import epoll
from select import EPOLLIN
import signal # used for mock
import time
import copy
from argparse import ArgumentParser
from inocybe_dhcp.dhcpio import DHCPIo
from inocybe_dhcp.dhcpio import DHCPSERVER
from inocybe_dhcp.dhcpio import format_ip
from inocybe_dhcp.dhcpio import format_mac
from inocybe_dhcp.rfc2131 import Message as DhcpMessage
from inocybe_dhcp.options import BuiltIn as DhcpOptions
from inocybe_dhcp.rfc3046 import RelayAgentInformation
import cps
import cps_object
import cps_utils

#### Constants ####
BOOTREQUEST = 1
BOOTREPLY = 2
TIMEOUT = 300

DO_NOT_RELAY = 0
UDP_RELAY = 1
MITM_RELAY = 3

MODULE_P = "dhcp-agent/if/interfaces/interface"
IFROOT_P = "if/interfaces/interface"
IFNAME_P = "if/interfaces/interface/name"
DHCPPATH_P = "dhcp-agent/if/interfaces/interface"
DHCPSERVER_P = "dhcp-agent/if/interfaces/interface/dhcp-server"
DHCPTRUSTED_P = "dhcp-agent/if/interfaces/interface/trusted"


# Initial assumption is that CPS will do a bound method as
# a callback, if it does not do a bound method cleanly we
# will have to use a global variable which contains the PendingConfig

# the model is designed to support a fairly extensive rewrite of
# dhcp requests and replies. We for now support only a minimal
# interpretation where we can configure a MIM or Relay on a vlan

# it is the job of the config callback to digest the incoming
# data and convert into a suitable format

class Agent(object):
    '''DHCP Agent top level'''
    def __init__(self, mock=None):
        logging.debug("Agent Init")
        self._mock_config_name = mock
        self._pending_config = None
        self._io = DHCPIo()
        self._epfd = epoll()
        self._epfd.register(self._io.udp_sock, EPOLLIN)
        self._pending_config = None
        self._state = {}
        self._active_config = None
        if mock is not None:
            logging.debug("Initializing mock using %s as mock config", mock)
            signal.signal(signal.SIGUSR1, self.mock_callback)
            self.mock_callback(None, None)
            self._pending_config, self._active_config = None, self._pending_config
            self._process_config()

    @staticmethod
    def _narrow_by(sfilter):
        '''Extract if/interface/interfaces/name from filter'''
        try:
            return cps_utils.cps_attr_types_map.from_data(
                IFNAME_P,
                sfilter['data'][IFNAME_P])
        except KeyError:
            return None

    def get(self, sfilter):
        '''Get config, filtering for a particular key'''
        narrow_by = self._narrow_by(sfilter)
        result = []
        for iface in self._active_config:
            if (narrow_by is None) or (iface["name"] == narrow_by):
                try:
                    obj = cps_object.CPSObject(
                        module=MODULE_P, data={"dhcp-server":iface["dhcp-server"]})
                except KeyError:
                    obj = cps_object.CPSObject(
                        module=MODULE_P, data={"trusted":iface["trusted"].encode('ascii')})
                result.append(obj.get())
        return result

    def transaction(self, change):
        '''Transaction handler'''
        return getattr(self, '_' + change['operation'])(change)

    def _delete(self, change):
        '''Delete a config entry'''
        narrow_by = self._narrow_by(change)
        # we delete dhcp agent attributes only on one interface at a time
        if narrow_by is None:
            return False
        new_config = []
        result = False

        for iface in self._active_config:
            if iface["name"] != narrow_by:
                new_config.append(iface)
            else:
                result = True
        if result:
            self._pending_config = new_config
        return result

    @staticmethod
    def _add_change(iface, change):
        '''Add the incoming attribute to the iface'''
        logging.debug("adding %s to %s ", "{}".format(change), "{}".format(iface))
        try:
            iface["dhcp-server"] = cps_utils.cps_attr_types_map.from_data(
                DHCPSERVER_P,
                change['data'][DHCPSERVER_P]
            )
        except KeyError:
            iface["trusted"] = cps_utils.cps_attr_types_map.from_data(
                DHCPTRUSTED_P,
                change['data'][DHCPTRUSTED_P]
            )

    def _create(self, change):
        '''Create entry in config'''
        narrow_by = self._narrow_by(change)
        logging.debug("create for %s %s", "{}".format(narrow_by), "{}".format(change))
        if narrow_by is None:
            return False # we need an interface to be able to create

        if self._active_config is not None:
            for iface in self._active_config:
                if iface["name"] == narrow_by:
                    return False

        new_config = copy.deepcopy(self._active_config)

        if new_config is None:
            new_config = []

        iface = {"name": narrow_by}
        self._add_change(iface, change)
        new_config.append(iface)
        self._pending_config = new_config
        logging.debug("pending config set to %s", "{}".format(self._pending_config))
        return True

    def _set(self, change):
        '''Set entry in config for a particular key'''

        narrow_by = self._narrow_by(change)
        new_config = copy.deepcopy(self._active_config)
        if new_config is None:
            new_config = []

        for iface in new_config:
            if (narrow_by is None) or (iface["name"] == narrow_by):
                iface.pop("dhcp-server", None)
                iface.pop("trusted", None)
                self._add_change(iface, change)
                self._pending_config = new_config
                return True
        return False

    # pylint: disable=unused-argument
    def mock_callback(self, signum, frame):
        '''Mock config read'''
        import json
        if self._mock_config_name is not None:
            logging.debug("Rereading config")
            file_d = open(self._mock_config_name, "r+")
            self._pending_config = json.load(file_d)
            file_d.close()

    def _process_config(self):
        '''Data change notification for if config'''
        old_keys = {}
        io_handler = self._io
        for ifname in io_handler.ifaces:
            old_keys[ifname] = True
        for iface in self._active_config:
            ifname = iface["name"]
            try:
                if io_handler.ifinfo(ifname) is not None:
                    del old_keys[ifname]
            except KeyError:
                try:
                    logging.debug(
                        "Adding interface %s dhcp-server = %s trusted = %s",
                        ifname, iface.get("dhcp-server"), iface.get("trusted"))
                    io_handler.add_if(
                        ifname, dst=iface.get("dhcp-server"), trusted=iface.get("trusted"))
                    self._epfd.register(io_handler.ifinfo(ifname).pcap.fileno(), EPOLLIN)
                # pcap throws something unintelligible so we have to grab everything
                # pylint: disable=broad-except
                except Exception as ex:
                    logging.error("Could not configure interface %s - %s", ifname, ex)
        for ifname in old_keys:
            self._epfd.unregister(io_handler.ifinfo(ifname).pcap.fileno())
            logging.debug("Deleting interface %s", ifname)
            io_handler.del_if(ifname)

    def _run_expiry(self):
        '''Expire potentially stale state entries'''
        to_delete = []
        # we store everything and the kitchen sink in state while for
        # expiry we need just the stamp
        # pylint: disable=unused-variable
        for (xid, (ifinfo, src_ip, src_mac, stamp)) in self._state.items():
            if time.time() - stamp > TIMEOUT:
                to_delete.append(xid)
        for xid in to_delete:
            logging.debug("Deleting xid %x", xid)
            del self._state[xid]

    def process_packet(self, packet, ifinfo, src_ip, src_mac):
        '''Perform the actual packet processing
           It also needs to set, reset and alter src_ip and tx
           handler depending on is this a relay or mitm operation
           as well as which direction the packet is travelling
        '''
        # pylint: disable=no-member
        logging.debug("Processing DHCP Packet")
        relay = DO_NOT_RELAY
        try:
            parsed = DhcpMessage.unpack(packet)
        except ValueError:
            logging.error("Failed to parse DHCP Packet")
            return (None, None, None, None, DO_NOT_RELAY)
        if ifinfo is None:
            if parsed["op"] == BOOTREQUEST:
                # we got a parasitic req on the udp socket, we
                # we are listening only for reps there so drop
                logging.debug("Spurious UDP Read")
                return (None, None, None, None, DO_NOT_RELAY)
            try:
                # pylint: disable=unused-variable
                (ifinfo, src_ip, src_mac, stamp) = self._state[parsed['xid']]
                # received from relay - zero ip and mac so that tx
                # sets ours for the interface
                src_ip = None
                src_mac = None
                parsed['giaddr'] = '0.0.0.0'
                del self._state[parsed["xid"]]
            except KeyError:
                # no state entry
                logging.debug("No matching state entry for %x", parsed["xid"])
                return (None, None, None, None, DO_NOT_RELAY)
        else:
            #incoming packet on an iface we listen to
            if parsed["op"] == BOOTREQUEST:
                self._state[parsed['xid']] = (ifinfo, src_ip, src_mac, time.time())
                port = ifinfo.lookup(parsed['chaddr'])
                if port is not None:
                    logging.debug("Looked up source port as %s", port['ifname'])
                    parsed.encode_options(
                        (RelayAgentInformation({'circuit-id': port['ifname']}),),
                        DhcpOptions, append=True)
                else:
                    logging.error("Failed to lookup port")

        # packet processing goes in here
        # insert giaddr option for relay mode
        if ifinfo.dst is not None and ifinfo.ipaddr is not None:
            if parsed["op"] == BOOTREQUEST:
                parsed['giaddr'] = ifinfo.ipaddr
                relay = UDP_RELAY
        else:
            if parsed["op"] == BOOTREQUEST:
                relay = MITM_RELAY
        logging.debug("Processing complete for %s from %s @ %s %s",
                      parsed, format_ip(src_ip),
                      format_mac(src_mac), relay)
        return (parsed.pack(), ifinfo, src_ip, src_mac, relay)


    def main_loop(self):
        '''Run main loop'''
        while True:
            events = self._epfd.poll(1.0)
            # pylint: disable=unused-variable
            for (file_d, mask) in events:
                ifinfo = None
                packet = None
                src_ip = None
                src_mac = None
                try:
                    ifinfo = self._io.ifinfo_by_fdno(file_d)
                    packet, src_ip, src_mac = ifinfo.get_next()
                except KeyError:
                    # UDP socket
                    packet = self._io.udp_sock.recv(1500)
                (packet, ifinfo, src_ip, src_mac, relay) = self.process_packet(
                    packet, ifinfo, src_ip, src_mac)
                if packet is not None:
                    if relay == DO_NOT_RELAY:
                        ifinfo.send(packet, ipaddr=src_ip, mac=src_mac)
                    elif relay == UDP_RELAY:
                        self._io.udp_sock.sendto(packet, (ifinfo.dst, DHCPSERVER))
                    else:
                        ifinfo.mitm_send(packet, ipaddr=src_ip, mac=src_mac)
            if self._pending_config is not None:
                self._pending_config, self._active_config = None, self._pending_config
                self._process_config()
            self._run_expiry()

### MAIN ###

def main():
    '''Run the dhcp agent'''

    def get_cb(method, params):
        '''CPS get callback'''
        logging.debug("Get CB invoked with %s", "{}".format(params))
        fobj = cps_object.CPSObject(obj=params['filter'])
        params['list'].extend(agent.get(fobj.get()))
        return True

    def trans_cb(method, params):
        '''CPS transaction callback'''
        logging.debug("Trans CB invoked with %s", "{}".format(params))
        return agent.transaction(params['change'])

    agent = None
    cps_utils.add_attr_type('dhcp-agent/if/interfaces/interface/dhcp-server', 'ipv4')
    aparser = ArgumentParser(description=main.__doc__)
    aparser.add_argument(
        '--file',
        help='the file containing the dhcp agent config if used in mock mode',
        type=str)
    aparser.add_argument('--verbose', help='verbosity level', type=int)
    args = vars(aparser.parse_args())
    if args.get('verbose') is not None:
        logging.getLogger().setLevel(logging.DEBUG)
    agent = Agent(mock=args.get("file"))
    dict_cb = {"get": get_cb, "transaction": trans_cb}

    # disable cps pylint warnings - they are spurious
    # pylint: disable=no-member
    handle = cps.obj_init()
    # pylint: disable=no-member
    cps.obj_register(handle, cps.key_from_name("target", DHCPPATH_P), dict_cb)

    agent.main_loop()

if __name__ == '__main__':
    main()
