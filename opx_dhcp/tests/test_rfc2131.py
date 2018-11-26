#!/usr/bin/env python3

'''Test cases for opx_dhcp.rfc2131.'''

import os.path
from nose.tools import assert_equal

from opx_dhcp.rfc2131 import Message as DhcpMessage
from opx_dhcp.options import BuiltIn as DhcpOptions

from opx_dhcp.rfc2132 import (
    MessageType,
    RequestedIPAddress,
    HostName,
    ParameterRequestList,
)
from opx_dhcp.rfc3046 import (
    RelayAgentInformation,
)

TESTDIR = os.path.dirname(__file__)

EXPECTED = {
    'op': 1,
    'htype': 1,
    'hlen': 6,
    'hops': 0,
    'xid': 1987698441,
    'secs': 0,
    'flags': 0,
    'ciaddr': '0.0.0.0',
    'yiaddr': '0.0.0.0',
    'siaddr': '0.0.0.0',
    'giaddr': '192.168.98.1',
    'chaddr': '1e:4b:ad:91:68:3a',
    'sname': '',
    'file': '',
    'cookie': True,
    'options': ({
        'tag': 53,
        'length': 1,
        'value': b'\x03',
    }, {
        'tag': 50,
        'length': 4,
        'value': b'\xc0\xa8\x62\x88',
    }, {
        'tag': 12,
        'length': 12,
        'value': b'\x44\x65\x62\x69\x61\x6e\x54\x65\x73\x74\x65\x72',
    }, {
        'tag': 55,
        'length': 13,
        'value': b'\x01\x1c\x02\x03\x0f\x06\x77\x0c\x2c\x2f\x1a\x79\x2a',
    }, {
        'tag': 82,
        'length': 12,
        'value': b'\x01\x0a\x76\x65\x74\x68\x53\x30\x49\x39\x39\x56',
    }, {
        'tag': 255,
    })
}
with open(os.path.join(TESTDIR, 'client-request.bin'), 'rb') as FID:
    OCTETS = FID.read()

def test_message():
    '''Test opx_dhcp.rfc2131.Message class'''
    ### pylint: disable=no-member
    unpacked = DhcpMessage.unpack(OCTETS)
    assert_equal(EXPECTED, unpacked)
    ### test truncate_chaddr() is a no-op for a good message
    unpacked.truncate_chaddr()
    assert_equal(EXPECTED, unpacked)
    ### test pack to octets
    packed = unpacked.pack()
    assert_equal(OCTETS[:len(packed)], packed)
    ### trailing octets must only be right fill zeroes
    assert_equal(OCTETS[len(packed):], b'\x00' * (len(OCTETS) - len(packed)))
    ### final sanity check
    assert_equal(EXPECTED, unpacked)

def test_message_decode_options():
    '''Test opx_dhcp.rfc2131.Message decode_options()'''
    ### pylint: disable=no-member
    ### test with options intact, decoding as TLV
    expected = dict(EXPECTED)
    expected['options'] = [{
        "tag": 53, "length": 1, "value": "03"
    }, {
        "tag": 50, "length": 4, "value": "c0:a8:62:88"
    }, {
        "tag": 12, "length": 12, "value": "44:65:62:69:61:6e:54:65:73:74:65:72"
    }, {
        "tag": 55, "length": 13, "value": "01:1c:02:03:0f:06:77:0c:2c:2f:1a:79:2a"
    }, {
        "tag": 82, "length": 12, "value": "01:0a:76:65:74:68:53:30:49:39:39:56"
    }, {
        "tag": 255
    }]
    assert_equal(expected, DhcpMessage.unpack(OCTETS).decode_options())
    ### test with options chopped, decoding as TLV
    expected['options'] = [{'tag': 255}]
    assert_equal(expected, DhcpMessage.unpack(OCTETS[:240]).decode_options())

def test_message_encode_options():
    '''Test opx_dhcp.rfc2131.Message encode_options()'''
    ### pylint: disable=no-member
    ### unpack with options stripped
    msg = DhcpMessage.unpack(OCTETS[:240])
    ### set empty
    options = ()
    msg.encode_options(options, DhcpOptions)
    ### set some options
    options = (
        MessageType('DHCPREQUEST'),
        RequestedIPAddress('192.168.98.136'),
    )
    msg.encode_options(options, DhcpOptions)
    ### append empty
    options = ()
    msg.encode_options(options, DhcpOptions, append=True)
    ### append rest
    options = (
        HostName('DebianTester'),
        ParameterRequestList([1, 28, 2, 3, 15, 6, 119, 12, 44, 47, 26, 121, 42]),
        RelayAgentInformation({'circuit-id': 'vethS0I99V'}),
    )
    msg.encode_options(options, DhcpOptions, append=True)
    ### pack
    packed = msg.pack()
    assert_equal(OCTETS[:len(packed)], packed)
    assert_equal(EXPECTED, DhcpMessage.unpack(packed))
    ### set options as TLV
    options = ({'tag': 255},)
    msg.encode_options(options)
    ### pack
    packed = msg.pack()
    assert_equal(240 + 1, len(packed))
    assert_equal(OCTETS[:240] + b'\xFF', packed)
    expected = dict(EXPECTED)
    expected['options'] = options
    assert_equal(expected, DhcpMessage.unpack(packed))

def test_truncate_chaddr_benign():
    '''Test opx_dhcp.rfc2131.Message truncate_chaddr() is benign'''
    msg = DhcpMessage()
    assert_equal({}, msg)
    msg.truncate_chaddr()
    assert_equal({}, msg)

def test_truncate_chaddr_success():
    '''Test opx_dhcp.rfc2131.Message truncate_chaddr() truncates chaddr'''
    ### pylint: disable=too-many-function-args,unsubscriptable-object
    msg = DhcpMessage({
        'hlen': 16,
        'chaddr': '00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF',
    })
    assert_equal({
        'hlen': 16,
        'chaddr': '00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF',
    }, msg)
    msg['hlen'] = 6
    msg.truncate_chaddr()
    assert_equal({
        'hlen': 6,
        'chaddr': '00:11:22:33:44:55',
    }, msg)
