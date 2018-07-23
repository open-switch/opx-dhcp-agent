#!/usr/bin/env python3

'''RFC 2131 DHCP message structures.'''

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

from six import add_metaclass

from .types import (
    StructuredValue,
    UInt8, UInt16, UInt32, IPv4,
    HexString, NulTerminatedString,
)
from .rfc2132 import Cookie, Options
from .options import Supported

@add_metaclass(StructuredValue)
class Message(object):
    '''A class representing a RFC 2131 DHCP message.

       Each instance is a :class:`dict` instance restricted to the pairs specified in :attr:`spec`:
       attempting to set a pair at a key not in :attr:`spec` is rejected with :class:`KeyError`;
       attempting to set a pair with a value which is not supported by that pair's value type is
       rejected with :class:`ValueError` or :class:`TypeError`.

       An instance of this class may be created as per :class:`dict`, or by calling classmethod
       :meth:`unpack` with a binary string, encoded as per RFC 2131. To serialise an instance to a
       binary string, call :meth:`pack`.

       If a new value is set at 'hlen' or 'chaddr' then call :meth:`truncate_chaddr` to ensure that
       the encoded value of 'chaddr' does not exceed 'hlen' octets.
    '''
    name = 'RFC 2131 DHCP message'
    ### :attr:`spec` is a sequence of (key, value type) pairs
    spec = (
        ('op', UInt8(1, 2)),
        ('htype', UInt8()),
        ('hlen', UInt8(1, 16)),
        ('hops', UInt8()),
        ('xid', UInt32()),
        ('secs', UInt16()),
        ('flags', UInt16()),
        ('ciaddr', IPv4()),
        ('yiaddr', IPv4()),
        ('siaddr', IPv4()),
        ('giaddr', IPv4()),
        ('chaddr', HexString(16)),
        ('sname', NulTerminatedString(64)),
        ('file', NulTerminatedString(128)),
        ('cookie', Cookie()),
        ('options', Options()),
    )
    def __init__(self):
        self.truncate_chaddr()
    def truncate_chaddr(self):
        '''If this instance's 'chaddr' is too long to be encoded in 'hlen' octets then truncate the
           value of 'chaddr' so that it can be encoded in 'hlen' octets. If this instance does not
           have a value for 'chaddr' or 'hlen' then do nothing.
        '''
        ### pylint: disable=unsubscriptable-object
        try:
            self['chaddr'] = self.fields['chaddr'].truncate(self['chaddr'], self['hlen']) ### pylint: disable=no-member
        except KeyError:
            pass
    def decode_options(self, supported=None):
        '''Return a plain :class:`dict` copy of `self`, with 'options' decoded using `supported`. If
           `supported` is None, then decode options as TLV.
        '''
        if supported is None:
            ### use an empty set of supported options to decode as TLV
            supported = Supported()
        copy = dict(self)
        copy['options'] = supported.decode(self['options']) ### pylint: disable=unsubscriptable-object
        return copy
    def encode_options(self, options, supported=None, append=False):
        '''Set this instance's 'options' from `options` encoded using `supported`. If `supported` is
           None, then encode options from TLV. If `append` is True, then append encoded `options` to
           the existing 'options' rather than replacing them.
        '''
        if supported is None:
            ### use an empty set of supported options to encode from TLV
            supported = Supported()
        encoded = tuple(supported.encode(options))
        if append:
            self['options'] += encoded ### pylint: disable=unsubscriptable-object
        else:
            self['options'] = encoded ### pylint: disable=unsubscriptable-object
