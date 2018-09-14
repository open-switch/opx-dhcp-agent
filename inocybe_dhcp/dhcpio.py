#!/usr/bin/env python

'''DHCP IO Library for the Inocybe DHCP Agent'''

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

import socket
import os
import struct
import logging
import array
from inocybe_dhcp.bridge import FDB
from inocybe_dhcp.bridge import Filters
import netifaces as ni
import dumbnet
import pcap
import dpkt.ethernet
import dpkt.ip
import dpkt.udp

DHCPSERVER = 67
DHCPCLIENT = 68
MAXPACKET = 1500
FILTER = "udp and (dst port 68) or (dst port 67)"
ETH_BROADCAST = '\xff\xff\xff\xff\xff\xff'

def print_mac(data):
    '''Print out an IP addr as numeric'''
    try:
        mac0, mac1, mac2, mac3, mac4, mac5 = struct.unpack("BBBBBB", data)
        return "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}".format(
            mac0, mac1, mac2, mac3, mac4, mac5)
    except struct.error:
        return "{}".format(data)

def print_ip(data):
    '''Print out an IP addr as numeric'''
    try:
        ip0, ip1, ip2, ip3 = struct.unpack("BBBB", data)
        return "{}.{}.{}.{}".format(ip0, ip1, ip2, ip3)
    except struct.error:
        return "{}".format(data)



class Ifinfo(object):
    '''Interface information object'''

    def __init__(self, iface=None, dst=None, trusted=None):
        self.iface = iface
        self.dst = dst
        self.trusted = trusted
        if trusted is None and dst is None:
            raise ValueError("You need to chose either agent or relay mode")#
        if trusted is not None and dst is not None:
            raise ValueError("You need to chose either agent or relay mode")#
        self.pcap = pcap.pcapObject()
        self.pcap.open_live(iface.encode('ascii'), MAXPACKET, True, 1)
        self.pcap.setfilter(FILTER, 1, 0)
        self.pcap.setnonblock(True)
        self._filters = None
        try:
            # pylint: disable=no-member
            self.ipaddr = ni.ifaddresses(iface)[ni.AF_INET][0]['addr']
        # pylint: disable=unused-variable
        except (IndexError, KeyError) as ignore:
            self.ipaddr = None
        # pylint: disable=no-member
        self.mac = ni.ifaddresses(iface)[ni.AF_PACKET][0]['addr']
        self.rawio = os.fdopen(self.pcap.fileno(), "w+")
        if self.trusted is not None:
            self.trust_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            self.trust_sock.bind((self.trusted, 0))
            self.trust_sock.setblocking(0)
        self._fdb = FDB(iface)
        if self.dst is None:
            self._filters = Filters(iface, trusted=self.trusted)
        logging.debug("Instantiated Ifinfo for %s", iface)

    def get_next(self):
        '''Get Next Packet'''
        # pylint: disable=unused-variable
        logging.debug("Trying pcap read on %s", self.iface)
        try:
            (plen, data, timestamp) = self.pcap.next()
        except TypeError:
            return None
        eth = dpkt.ethernet.Ethernet(data)
        ip_p = eth.data
        udp = ip_p.data
        # pylint: disable=no-member
        return udp.data, ip_p.src, eth.src

    def _send(self, data, ipaddr=None, mac=None, to_server=False):
        '''Write Next Packet'''
        if ipaddr is None:
            ipaddr = self.ipaddr
        if mac is None:
            mac = self.mac
        udp = None
        if to_server:
            udp = dpkt.udp.UDP(
                sport=DHCPCLIENT,
                dport=DHCPSERVER,
                data=data,
                sum=0,
                ulen=len(data) + 8,
            )
        else:
            udp = dpkt.udp.UDP(
                sport=DHCPSERVER,
                dport=DHCPCLIENT,
                data=data,
                sum=0,
                ulen=len(data) + 8,
            )
        udp.pack()
        # pylint: disable=no-member
        ip_p = dpkt.ip.IP(
            src=dumbnet.addr(ipaddr).ip,
            dst=dumbnet.addr("255.255.255.255").ip,
            tos=16,
            ttl=128,
            p=17,
            len=len(data) + 28,
            data=udp,
            )
        # pylint: disable=no-member
        eth = dpkt.ethernet.Ethernet(
            data=_cksum_packet(ip_p),
            src=mac,
            dst=ETH_BROADCAST
        )
        if to_server:
            logging.debug("Raw socket to server on %s using %s/%s",
                          self.iface, print_ip(ipaddr), print_mac(mac))
            self.trust_sock.send(str(eth))
        else:
            logging.debug("Raw socket to client on %s using %s/%s",
                          self.iface, print_ip(ipaddr), print_mac(mac))
            self.rawio.write(str(eth))
            self.rawio.flush() # needed, otherwise python buffering messes it up

    def send(self, data, ipaddr=None, mac=None):
        '''Normal send - to client'''
        return self._send(data, ipaddr=ipaddr, mac=mac, to_server=False)

    def mitm_send(self, data, ipaddr=None, mac=None):
        '''Mitm Mode send modified data to server'''
        return self._send(data, ipaddr=ipaddr, mac=mac, to_server=True)

    def lookup(self, mac):
        '''Lookup Mac in FDB'''
        return self._fdb.lookup(mac, True)


class DHCPIo(object):
    '''Python DHCP IO Handler'''

    def __init__(self):
        self.ifaces = {}
        self.ifaces_by_fd = {}
        self.state = {}
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.bind(("", DHCPSERVER))
        self.udp_sock.setblocking(0)

    def add_if(self, iface, dst=None, trusted=None):
        '''Add an interface to the monitored set, if the dst is not None
           the interface is handled in dhcp relay mode, otherwise in
           man-in-the-middle agent mode. Note - the man-in-the-middle
           mode required appropriate bridge firewall rules which are not
           configured here'''
        if self.ifaces.get(iface) is None:
            ifinfo = Ifinfo(iface=iface, dst=dst, trusted=trusted)
            if ifinfo is not None:
                self.ifaces[iface] = ifinfo
                # hash it by file object so it can be used in select/poll/epoll
                self.ifaces_by_fd[self.ifaces[iface].rawio.fileno()] = ifinfo
                logging.debug("Interface %s configured", iface)
                return
        raise ValueError("Cannot configure interface")

    def del_if(self, iface):
        '''Remove an interface from the monitored set'''
        del self.ifaces_by_fd[self.ifaces[iface].rawio.fileno()]
        del self.ifaces[iface]
        logging.debug("Interface %s deleted", iface)

    def ifinfo_by_fdno(self, ifname):
        '''Pull ifinfo structure from io handler'''
        try:
            return self.ifaces_by_fd[ifname.fileno()]
        except AttributeError:
            return self.ifaces_by_fd[ifname]

    def ifinfo(self, ifname):
        '''Pull ifinfo structure from io handler'''
        return self.ifaces[ifname]


def _udp_pseudo_header(ip_packet):
    '''Compute the UDP pseudo-header
       Note - we have to pass here the IP packet not UDP as an arg'''
    return struct.pack("!4s4sHH",
                       ip_packet.src,
                       ip_packet.dst,
                       ip_packet.p,
                       ip_packet.data.ulen)

def _cksum_header(ip_packet):
    '''Calculate header cksum in ip_packet and put it in the correct place'''
    ip_packet.sum = 0
    ip_packet.sum = _checksum(ip_packet.pack_hdr())

def _cksum_packet(ip_packet):
    '''Calculate all cksums in a UDP packet seen at IP layer'''
    ip_packet.data.sum = 0
    ip_packet.data.ulen = len(ip_packet.data.data) + 8
    ip_packet.data.sum = 0
    ip_packet.data.sum = _checksum(_udp_pseudo_header(ip_packet) + str(ip_packet.data))
    if ip_packet.data.sum == 0:
        ip_packet.data.sum = 0xffff
    _cksum_header(ip_packet)
    return ip_packet

if struct.pack("H", 1) == "\x00\x01": # big endian
    def _checksum(pkt):
        if len(pkt) % 2 == 1:
            pkt += "\0"
        _sum = sum(array.array("H", pkt))
        _sum = (_sum >> 16) + (_sum & 0xffff)
        _sum += _sum >> 16
        _sum = ~_sum
        return _sum & 0xffff
else:
    def _checksum(pkt):
        if len(pkt) % 2 == 1:
            pkt += "\0"
        _sum = sum(array.array("H", pkt))
        _sum = (_sum >> 16) + (_sum & 0xffff)
        _sum += _sum >> 16
        _sum = ~_sum
        return (((_sum>>8)&0xff)|_sum<<8) & 0xffff
