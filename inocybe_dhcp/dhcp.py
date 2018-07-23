#!/usr/bin/env python3

'''Parse a DHCP message and print it as a JSON-encoded value.'''

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

from __future__ import print_function

import json

from argparse import ArgumentParser

from .rfc2131 import Message as DhcpMessage
from .options import BuiltIn as DhcpOptions

### pylint: disable=unused-import
### explicitly import DHCP option modules to register all built-in options
import inocybe_dhcp.rfc2132
import inocybe_dhcp.rfc3046

def main():
    '''Parse a DHCP message from a binary file and print it as a JSON-encoded value.'''
    aparser = ArgumentParser(description=main.__doc__)
    aparser.add_argument('--decode-options', type=int, default=1, choices=(0, 1), help=', '.join((
        'fully decode options (1)',
        'or decode as TLV (0)'
    )))
    aparser.add_argument('file', help=', '.join((
        'the file containing the encoded DHCP message',
        'or "-" to read from stdin',
    )))
    args = vars(aparser.parse_args())
    filename = '/dev/stdin' if args['file'] == '-' else args['file']
    with open(filename, 'rb') as fid:
        ### options in unpacked message contain binary string values which cannot be JSON-encoded
        msg = DhcpMessage.unpack(fid.read()) ### pylint: disable=no-member
        ### decoding options returns a value which can be JSON-encoded
        msg = msg.decode_options(DhcpOptions if args['decode_options'] else None)
        print(json.dumps(msg))

if __name__ == '__main__':
    main()
