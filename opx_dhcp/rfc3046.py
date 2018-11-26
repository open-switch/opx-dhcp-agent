#!/usr/bin/env python3

'''RFC 3046 DHCP option implementations.'''

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

from six import (add_metaclass, int2byte, byte2int)

from .options import (BuiltIn, Option)

@add_metaclass(BuiltIn)
class RelayAgentInformation(Option):
    '''RFC 3046 Section 2.0 Relay Agent Information Option'''
    option = 'Relay Agent Information'
    tag = 82
    value_type = True
    suboptions = {1: 'circuit-id', 2: 'remote-id'}
    subtags = {'circuit-id': 1, 'remote-id': 2}
    encoding = 'iso-8859-1'
    @classmethod
    def encode_value(cls, val):
        octets = b''
        for key in sorted(val):
            try:
                tag = cls.subtags[key]
            except KeyError:
                raise ValueError(val)
            else:
                octets += int2byte(tag)
            try:
                value = val[key].encode(cls.encoding)
            except AttributeError:
                raise ValueError(val)
            else:
                octets += int2byte(len(value))
                octets += value
        return octets
    @classmethod
    def decode_value(cls, octets):
        if len(octets) < 2:
            raise ValueError(octets)
        value = {}
        while octets:
            tag = byte2int(octets)
            octets = octets[1:]
            if octets:
                length = byte2int(octets)
                octets = octets[1:]
                if length <= len(octets):
                    try:
                        key = cls.suboptions[tag]
                    except KeyError:
                        pass
                    else:
                        value[key] = octets[:length].decode(cls.encoding)
                        octets = octets[length:]
                        continue
            raise ValueError(octets)
        return value
