#!/usr/bin/env python3

'''RFC 2132 DHCP option structures and implementations.'''

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

from struct import error as StructError
from six import (byte2int, int2byte, add_metaclass)

from .types import (ValueType, UInt8, SInt32, IPv4, Enum)
from .options import (BuiltIn, Option)

_UINT8 = UInt8()
_SINT32 = SInt32()
_IPV4 = IPv4()

class Cookie(ValueType):
    '''A value type for the "BOOTP magic cookie" as per RFC 2132 Section 2. The canonical value for
       the cookie is a boolean, where True indicates that the cookie is present, otherwise absent.
    '''
    sfmt = None
    cookie = b'\x63\x82\x53\x63'
    def __call__(self, val):
        '''Return the canonical cookie value for lexical value `val` which is `val` as a boolean.'''
        return bool(val)
    def pack(self, val):
        '''If `val` indicates that the cookie is present, return the magic cookie binary string.
           Otherwise, the cookie is absent: return an empty binary string.
        '''
        return self.cookie if bool(val) else b''
    def unpack(self, octets):
        '''Return (True, trailing octets) if the magic cookie is at the head of `octets`. Otherwise
           the cookie is absent: return (False, `octets`).
        '''
        return (True, octets[4:]) if octets[:4] == self.cookie else (False, octets)

class Options(ValueType):
    '''A value type for a sequence of DHCP options as per RFC 2132. The canonical value for options
       is a sequence of dicts, where each dict represents an option, with the 'end' option as the
       final item.  An option dict must match one of the following forms.

       The pad option is a dict with a solitary pair at key 'tag' with value integer 0.
       The end option is a dict with a solitary pair at key 'tag' with value integer 255.
       Any other option is a dict with three pairs:
       * key 'tag' with integer value between 0 and 255 exclusive
       * key 'length' with integer value between 0 and 255 inclusive
       * key 'value' with binary string value of len 'length'
    '''
    sfmt = None
    pad = 0
    end = 255
    def _option_tag(self, option):
        '''Return the canonical value for `option`, if `option` specifies a tag-only option.
           Otherwise raise :class:`ValueError`.
        '''
        try:
            ### also accepts other lexical forms of integer such as base-encoded string integers
            tag = _UINT8(option['tag'])
        except (KeyError, ValueError):
            pass
        else:
            if tag == self.pad or tag == self.end:
                ### discard all other pairs
                return {'tag': tag}
        raise ValueError(option)
    def _option_tlv(self, option):
        '''Return the canonical value for `option`, if `option` specifies a TLV option.
           Otherwise raise :class:`ValueError`.
        '''
        try:
            ### also accepts other lexical forms of integer such as base-encoded string integers
            tag = _UINT8(option['tag'])
            length = _UINT8(option['length'])
            value = option['value']
        except (KeyError, ValueError):
            raise ValueError(option)
        else:
            if self.pad < tag and tag < self.end and length == len(value):
                ### discard all other pairs
                return {'tag': tag, 'length': length, 'value': value}
        raise ValueError(option)
    def __call__(self, val):
        '''Return the canonical value, a tuple of options, for lexical value `val` where `val` must
           be iterable. Each item in `val` must specify an option as defined in the class docstring.
           The canonical value is always terminated with an 'end' option; all 'end' options in the
           lexical value are discarded.
        '''
        options = []
        for option in val:
            try:
                option = self._option_tag(option)
            except ValueError:
                option = self._option_tlv(option)
            if option['tag'] != self.end:
                options.append(option)
        options.append({'tag': self.end})
        return tuple(options)
    def pack(self, options):
        '''Return a binary string representing the sequence of `options`. `options` will be packed
           exactly as supplied. A missing 'end' option will not be automatically added.
        '''
        octets = b''
        try:
            for option in options:
                tag = option['tag']
                octets += int2byte(tag)
                if tag != self.pad and tag != self.end:
                    octets += int2byte(option['length'])
                    octets += option['value']
        except (KeyError, StructError):
            raise ValueError(options)
        return octets
    def unpack(self, octets):
        '''Unpack options from binary string `octets` and return (list of options, trailing octets).
           A missing 'end' option will be ignored, but only if all `octets` are unpacked.
        '''
        options = []
        while octets:
            tag = byte2int(octets)
            octets = octets[1:]
            if tag == self.pad:
                options.append({'tag': tag})
                continue
            elif tag == self.end:
                options.append({'tag': tag})
                break
            elif octets:
                length = byte2int(octets)
                octets = octets[1:]
                if length <= len(octets):
                    value = octets[:length]
                    octets = octets[length:]
                    options.append({'tag': tag, 'length': length, 'value': value})
                    continue
            raise ValueError(octets)
        return (options, octets)

@add_metaclass(BuiltIn)
class Pad(Option):
    '''RFC 2132 Section 3.1. Pad Option'''
    option = 'Pad'
    tag = 0

@add_metaclass(BuiltIn)
class End(Option):
    '''RFC 2132 Section 3.2. End Option'''
    option = 'End'
    tag = 255

@add_metaclass(BuiltIn)
class SubnetMask(Option):
    '''RFC 2132 Section 3.3. Subnet Mask'''
    option = 'Subnet Mask'
    tag = 1
    length = 4
    value_type = _IPV4

@add_metaclass(BuiltIn)
class TimeOffset(Option):
    '''RFC 2132 Section 3.4. Time Offset'''
    option = 'Time Offset'
    tag = 2
    length = 4
    value_type = _SINT32

@add_metaclass(BuiltIn)
class HostName(Option):
    '''RFC 2132 Section 3.14 Host Name Option'''
    option = 'Host Name'
    tag = 12
    value_type = True
    encoding = 'iso-8859-1'
    @classmethod
    def encode_value(cls, val):
        return val.encode(cls.encoding)
    @classmethod
    def decode_value(cls, octets):
        return octets.decode(cls.encoding)

@add_metaclass(BuiltIn)
class RequestedIPAddress(Option):
    '''RFC 2132 Section 9.1. Requested IP Address'''
    option = 'Requested IP Address'
    tag = 50
    length = 4
    value_type = _IPV4

@add_metaclass(BuiltIn)
class MessageType(Option):
    '''RFC 2132 Section 9.6. DHCP Message Type'''
    option = 'DHCP Message Type'
    tag = 53
    length = 1
    value_type = Enum(1, 8, 'B', {
        1: 'DHCPDISCOVER',
        2: 'DHCPOFFER',
        3: 'DHCPREQUEST',
        4: 'DHCPDECLINE',
        5: 'DHCPACK',
        6: 'DHCPNAK',
        7: 'DHCPRELEASE',
        8: 'DHCPINFORM',
    })

@add_metaclass(BuiltIn)
class ParameterRequestList(Option):
    '''RFC 2132 Section 9.8. Parameter Request List'''
    option = 'Parameter Request List'
    tag = 55
    value_type = True
    @classmethod
    def encode_value(cls, val):
        octets = b''
        for elem in val:
            octets += int2byte(elem)
        return octets
    @classmethod
    def decode_value(cls, octets):
        if len(octets) < 1:
            raise ValueError(octets)
        value = []
        while octets:
            value.append(byte2int(octets))
            octets = octets[1:]
        return tuple(value)
