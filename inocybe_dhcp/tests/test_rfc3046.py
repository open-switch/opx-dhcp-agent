#!/usr/bin/env python3

'''Test cases for inocybe_dhcp.rfc3046.'''

from inocybe_dhcp.rfc3046 import RelayAgentInformation

from .test_options import OptionTest

class TestRelayAgentInformation(OptionTest):
    '''Tests for :class:`RelayAgentInformation` option implementation.'''
    option = RelayAgentInformation
    accepts_encode = (
        ({'option': 'Relay Agent Information', 'value': {'circuit-id': 'X'}},
         {'tag': 82, 'length': 3, 'value': b'\x01\x01\x58'},
        ),
        ({'option': 'Relay Agent Information', 'value': {'remote-id': 'Y'}},
         {'tag': 82, 'length': 3, 'value': b'\x02\x01\x59'},
        ),
        ### "A sub-option length may be zero."
        ({'option': 'Relay Agent Information', 'value': {'circuit-id': ''}},
         {'tag': 82, 'length': 2, 'value': b'\x01\x00'},
        ),
        ({'option': 'Relay Agent Information', 'value': {'remote-id': ''}},
         {'tag': 82, 'length': 2, 'value': b'\x02\x00'},
        ),
        ### "The sub-options need not appear in sub-option code order." but are encoded that way
        ({'option': 'Relay Agent Information', 'value': {'circuit-id': 'X', 'remote-id': 'Y'}},
         {'tag': 82, 'length': 6, 'value': b'\x01\x01\x58\x02\x01\x59'},
        ),
    )
    rejects_encode = (
        ### bad sub-option name
        {'option': 'Relay Agent Information', 'value': {'foo': 'bar'}},
        ### bad sub-option value
        {'option': 'Relay Agent Information', 'value': {'circuit-id': (1, 2, 3)}},
    )
    accepts_decode = (
        ({'tag': 82, 'length': 3, 'value': b'\x01\x01\x58'},
         {'option': 'Relay Agent Information', 'value': {'circuit-id': 'X'}},
        ),
        ({'tag': 82, 'length': 3, 'value': b'\x02\x01\x59'},
         {'option': 'Relay Agent Information', 'value': {'remote-id': 'Y'}},
        ),
        ### "A sub-option length may be zero."
        ({'tag': 82, 'length': 2, 'value': b'\x01\x00'},
         {'option': 'Relay Agent Information', 'value': {'circuit-id': ''}},
        ),
        ({'tag': 82, 'length': 2, 'value': b'\x02\x00'},
         {'option': 'Relay Agent Information', 'value': {'remote-id': ''}},
        ),
        ### "The sub-options need not appear in sub-option code order."
        ({'tag': 82, 'length': 6, 'value': b'\x01\x01\x58\x02\x01\x59'},
         {'option': 'Relay Agent Information', 'value': {'circuit-id': 'X', 'remote-id': 'Y'}},
        ),
        ({'tag': 82, 'length': 6, 'value': b'\x02\x01\x59\x01\x01\x58'},
         {'option': 'Relay Agent Information', 'value': {'circuit-id': 'X', 'remote-id': 'Y'}},
        ),
        ### RFC is silent on duplication: accept last value
        ({'tag': 82, 'length': 6, 'value': b'\x01\x01\x5A\x01\x01\x58'},
         {'option': 'Relay Agent Information', 'value': {'circuit-id': 'X'}},
        ),
        ({'tag': 82, 'length': 6, 'value': b'\x01\x01\x58\x01\x01\x5A'},
         {'option': 'Relay Agent Information', 'value': {'circuit-id': 'Z'}},
        ),
    )
    rejects_decode = (
        ### missing sub-option tag
        {'tag': 82, 'length': 0, 'value': b''},
        ### missing sub-option length
        {'tag': 82, 'length': 1, 'value': b'\x01'},
        ### bad sub-option tag
        {'tag': 82, 'length': 2, 'value': b'\x03\x00'},
        ### missing sub-option value
        {'tag': 82, 'length': 2, 'value': b'\x01\x01'},
        ### good first sub-option, bad second sub-option
        {'tag': 82, 'length': 4, 'value': b'\x01\x00\x02\x0A'},
    )
