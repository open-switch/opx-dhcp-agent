#!/usr/bin/env python3

'''Test cases for inocybe_dhcp.rfc2132.'''

from inocybe_dhcp.rfc2132 import (
    Cookie, Options,
    Pad, End,
    SubnetMask, TimeOffset, HostName,
    RequestedIPAddress, MessageType, ParameterRequestList,
)

from .test_types import ValueTypeTest
from .test_options import OptionTest

class TestCookie(ValueTypeTest):
    '''Test :class:`Cookie`.'''
    value_type = Cookie()
    attrs = (
        ('sfmt', None),
    )
    accepts_value = tuple([
        (_, True) for _ in (
            True,
            -1, 1,
            'foo',
            -2.3, 4.8,
            ('AB',),
            ['AB',],
            {'AB': 'CD'},
        )
    ] + [
        (_, False) for _ in (
            None,
            False,
            0,
            '',
            0.0,
            (),
            [],
            {},
        )
    ])
    accepts_pack = tuple([
        (_[0], b'\x63\x82\x53\x63' if _[1] else b'') for _ in accepts_value
    ])
    accepts_unpack = (
        (b'', (False, b'')),
        (b'\x63', (False, b'\x63')),
        (b'\x63\x82', (False, b'\x63\x82')),
        (b'\x63\x82\x53', (False, b'\x63\x82\x53')),
        (b'\x63\x82\x53\x62', (False, b'\x63\x82\x53\x62')),
        (b'\x63\x82\x53\x63', (True, b'')),
        (b'\x63\x82\x53\x63\x01', (True, b'\x01')),
    )

class TestOptions(ValueTypeTest):
    '''Test :class:`Options`.'''
    value_type = Options()
    attrs = (
        ('sfmt', None),
    )
    accepts_value = (
        ### empty iterable cases
        ('',
         ({'tag': 255},),
        ),
        ((),
         ({'tag': 255},),
        ),
        ([],
         ({'tag': 255},),
        ),
        ({},
         ({'tag': 255},),
        ),
        ### end tag
        ([{'tag': 255}],
         ({'tag': 255},),
        ),
        ([{'tag': 255}, {'tag': 255}],
         ({'tag': 255},),
        ),
        ### pad tag
        ([{'tag': 0}],
         ({'tag': 0}, {'tag': 255}),
        ),
        ([{'tag': 0}, {'tag': 255}],
         ({'tag': 0}, {'tag': 255}),
        ),
        ([{'tag': 255}, {'tag': 0}],
         ({'tag': 0}, {'tag': 255}),
        ),
        ### multiple pad tags
        ([{'tag': 0}, {'tag': 0}],
         ({'tag': 0}, {'tag': 0}, {'tag': 255}),
        ),
        ([{'tag': 0}, {'tag': 0}, {'tag': 255}],
         ({'tag': 0}, {'tag': 0}, {'tag': 255}),
        ),
        ([{'tag': 0}, {'tag': 255}, {'tag': 0}],
         ({'tag': 0}, {'tag': 0}, {'tag': 255}),
        ),
        ([{'tag': 255}, {'tag': 0}, {'tag': 0}],
         ({'tag': 0}, {'tag': 0}, {'tag': 255}),
        ),
        ### TLV
        ([{'tag': 7, 'length': 4, 'value': b'\x00\x01\x02\x03'}],
         ({'tag': 7, 'length': 4, 'value': b'\x00\x01\x02\x03'}, {'tag': 255}),
        ),
        ([{'tag': 7, 'length': 4, 'value': b'\x00\x01\x02\x03'}, {'tag': 255}],
         ({'tag': 7, 'length': 4, 'value': b'\x00\x01\x02\x03'}, {'tag': 255}),
        ),
        ([{'tag': 255}, {'tag': 7, 'length': 4, 'value': b'\x00\x01\x02\x03'}],
         ({'tag': 7, 'length': 4, 'value': b'\x00\x01\x02\x03'}, {'tag': 255}),
        ),
        ### extra key/value pairs
        ([{'tag': 255, 'length': 4, 'value': b'\x00\x01\x02\x03', 'foo': 'bar'}],
         ({'tag': 255},),
        ),
        ([{'tag': 0, 'length': 4, 'value': b'\x00\x01\x02\x03', 'foo': 'bar'}],
         ({'tag': 0}, {'tag': 255}),
        ),
        ([{'tag': 7, 'length': 4, 'value': b'\x00\x01\x02\x03', 'foo': 'bar'}],
         ({'tag': 7, 'length': 4, 'value': b'\x00\x01\x02\x03'}, {'tag': 255}),
        ),
        ### hexadecimal string values
        ([{'tag': '0x07', 'length': '0x01', 'value': b'\x03'}, {'tag': '0x0'}, {'tag': '0xFF'}],
         ({'tag': 7, 'length': 1, 'value': b'\x03'}, {'tag': 0}, {'tag': 255}),
        ),
    )
    rejects_value = (
        None,
        False, True,
        -1, 0, 1,
        'foo',
        -2.3, 0.0, 4.8,
        ('AB',),
        ['AB',],
        {'AB': 'CD'},
        ### malformed T
        [{'tag': -1}],
        [{'tag': 1}],
        [{'tag': 7}],
        [{'tag': 254}],
        [{'tag': 256}],
        ### malformed TLV
        [{'tag': -1, 'length': 4, 'value': b'\x00\x01\x02\x03'}],
        [{'tag': 256, 'length': 4, 'value': b'\x00\x01\x02\x03'}],
        [{'tag': 2, 'length': -1, 'value': b'\x00\x01\x02\x03'}],
        [{'tag': 2, 'length': 256, 'value': b'\x00\x01\x02\x03'}],
        [{'tag': 2, 'length': 99, 'value': b'\x00\x01\x02\x03'}],
        [{'tag': 2, 'length': 99}],
        [{'tag': 2, 'value': b'\x00\x01\x02\x03'}],
    )
    accepts_pack = (
        ('',
         b'',
        ),
        ((),
         b'',
        ),
        ([],
         b'',
        ),
        ({},
         b'',
        ),
        (({'tag': 0},),
         b'\x00',
        ),
        (({'tag': 255},),
         b'\xFF',
        ),
        (({'tag': 0}, {'tag': 255}),
         b'\x00\xFF',
        ),
        (({'tag': 7, 'length': 4, 'value': b'\x00\x01\x02\x03'},),
         b'\x07\x04\x00\x01\x02\x03',
        ),
        (({'tag': 7, 'length': 4, 'value': b'\x00\x01\x02\x03'}, {'tag': 255}),
         b'\x07\x04\x00\x01\x02\x03\xFF',
        ),
    )
    rejects_pack = (
        None,
        False, True,
        -1, 0, 1,
        'foo',
        -2.3, 0.0, 4.8,
        ('AB',),
        ['AB',],
        {'AB': 'CD'},
        ### malformed T
        [{'tag': -1}],
        [{'tag': 1}],
        [{'tag': 7}],
        [{'tag': 254}],
        [{'tag': 256}],
        ### malformed TLV
        [{'tag': 3}],
        [{'length': 1}],
        [{'value': b'\x01'}],
        [{'tag': 6, 'length': 4}],
        [{'tag': 6, 'value': b'\x0A\x0B\x0C\x0D'}],
        [{'length': 4, 'value': b'\x0A\x0B\x0C\x0D'}],
    )
    accepts_unpack = (
        (b'',
         ([], b''),
        ),
        (b'\xFF',
         ([{'tag': 255}], b''),
        ),
        (b'\xFF\x03\x02\x01\x00',
         ([{'tag': 255}], b'\x03\x02\x01\x00'),
        ),
        (b'\x00',
         ([{'tag': 0}], b''),
        ),
        (b'\x08\x03\xAA\xBB\xCC',
         ([{'tag': 8, 'length': 3, 'value': b'\xAA\xBB\xCC'}], b''),
        ),
        (b'\x08\x03\xAA\xBB\xCC\xFF',
         ([{'tag': 8, 'length': 3, 'value': b'\xAA\xBB\xCC'}, {'tag': 255}], b''),
        ),
        (b'\x08\x03\xAA\xBB\xCC\xFF\x07\x06\x04',
         ([{'tag': 8, 'length': 3, 'value': b'\xAA\xBB\xCC'}, {'tag': 255}], b'\x07\x06\x04'),
        ),
        (b'\x08\x03\xAA\xBB\xCC\x00\x00\xFF\x07\x06\x04',
         ([{'tag': 8, 'length': 3, 'value': b'\xAA\xBB\xCC'}, {'tag': 0}, {'tag': 0}, {'tag': 255}],
          b'\x07\x06\x04'
         ),
        ),
    )
    rejects_unpack = (
        b'\x08\x03\xAA\xBB',
        b'\x08\x03\xAA',
        b'\x08\x03',
        b'\x08',
        b'\x08\x03\xAA\xBB\xCC\x0A\x02\x01',
        b'\x08\x03\xAA\xBB\xCC\x0A\x02',
        b'\x08\x03\xAA\xBB\xCC\x0A',
        b'\x08\x03\xAA\xBB\xCC\x00\x0A\x02\x01',
    )

class TestPad(OptionTest):
    '''Tests for :class:`Pad` option implementation.'''
    option = Pad
    accepts_encode = (
        ({'option': 'Pad'}, {'tag': 0}),
    )
    accepts_decode = [(_[1], _[0]) for _ in accepts_encode]

class TestEnd(OptionTest):
    '''Tests for :class:`End` option implementation.'''
    option = End
    accepts_encode = (
        ({'option': 'End'}, {'tag': 255}),
    )
    accepts_decode = [(_[1], _[0]) for _ in accepts_encode]

class TestSubnetMask(OptionTest):
    '''Tests for :class:`SubnetMask` option implementation.'''
    option = SubnetMask
    accepts_encode = (
        ({'option': 'Subnet Mask', 'value': '255.255.252.0'},
         {'tag': 1, 'length': 4, 'value': b'\xFF\xFF\xFC\x00'},
        ),
    )
    accepts_decode = [(_[1], _[0]) for _ in accepts_encode]

class TestTimeOffset(OptionTest):
    '''Tests for :class:`TimeOffset` option implementation.'''
    option = TimeOffset
    accepts_encode = (
        ({'option': 'Time Offset', 'value': 2147483647},
         {'tag': 2, 'length': 4, 'value': b'\x7F\xFF\xFF\xFF'},
        ),
        ({'option': 'Time Offset', 'value': 1},
         {'tag': 2, 'length': 4, 'value': b'\x00\x00\x00\x01'},
        ),
        ({'option': 'Time Offset', 'value': 0},
         {'tag': 2, 'length': 4, 'value': b'\x00\x00\x00\x00'},
        ),
        ({'option': 'Time Offset', 'value': -1},
         {'tag': 2, 'length': 4, 'value': b'\xFF\xFF\xFF\xFF'},
        ),
        ({'option': 'Time Offset', 'value': -2147483648},
         {'tag': 2, 'length': 4, 'value': b'\x80\x00\x00\x00'},
        ),
    )
    accepts_decode = [(_[1], _[0]) for _ in accepts_encode]

class TestHostName(OptionTest):
    '''Tests for :class:`HostName` option implementation.'''
    option = HostName
    accepts_encode = (
        ({'option': 'Host Name', 'value': ''},
         {'tag': 12, 'length': 0, 'value': b''},
        ),
        ({'option': 'Host Name', 'value': u'\xFF'},
         {'tag': 12, 'length': 1, 'value': b'\xFF'},
        ),
        ({'option': 'Host Name', 'value': 'foobar'},
         {'tag': 12, 'length': 6, 'value': b'foobar'},
        ),
    )
    accepts_decode = [(_[1], _[0]) for _ in accepts_encode]

class TestRequestedIPAddress(OptionTest):
    '''Tests for :class:`RequestedIPAddress` option implementation.'''
    option = RequestedIPAddress
    accepts_encode = (
        ({'option': 'Requested IP Address', 'value': '10.6.2.1'},
         {'tag': 50, 'length': 4, 'value': b'\x0A\x06\x02\x01'},
        ),
    )
    accepts_decode = [(_[1], _[0]) for _ in accepts_encode]

class TestMessageType(OptionTest):
    '''Tests for :class:`MessageType` option implementation.'''
    option = MessageType
    accepts_encode = (
        ({'option': 'DHCP Message Type', 'value': 'DHCPDISCOVER'},
         {'tag': 53, 'length': 1, 'value': b'\x01'},
        ),
        ({'option': 'DHCP Message Type', 'value': 'DHCPOFFER'},
         {'tag': 53, 'length': 1, 'value': b'\x02'},
        ),
        ({'option': 'DHCP Message Type', 'value': 'DHCPREQUEST'},
         {'tag': 53, 'length': 1, 'value': b'\x03'},
        ),
        ({'option': 'DHCP Message Type', 'value': 'DHCPDECLINE'},
         {'tag': 53, 'length': 1, 'value': b'\x04'},
        ),
        ({'option': 'DHCP Message Type', 'value': 'DHCPACK'},
         {'tag': 53, 'length': 1, 'value': b'\x05'},
        ),
        ({'option': 'DHCP Message Type', 'value': 'DHCPNAK'},
         {'tag': 53, 'length': 1, 'value': b'\x06'},
        ),
        ({'option': 'DHCP Message Type', 'value': 'DHCPRELEASE'},
         {'tag': 53, 'length': 1, 'value': b'\x07'},
        ),
        ({'option': 'DHCP Message Type', 'value': 'DHCPINFORM'},
         {'tag': 53, 'length': 1, 'value': b'\x08'},
        ),
    )
    accepts_decode = [(_[1], _[0]) for _ in accepts_encode]

class TestParameterRequestList(OptionTest):
    '''Tests for :class:`ParameterRequestList` option implementation.'''
    option = ParameterRequestList
    accepts_encode = (
        ({'option': 'Parameter Request List', 'value': (0,)},
         {'tag': 55, 'length': 1, 'value': b'\x00'},
        ),
        ({'option': 'Parameter Request List', 'value': (0, 7)},
         {'tag': 55, 'length': 2, 'value': b'\x00\x07'},
        ),
        ({'option': 'Parameter Request List', 'value': (0, 255, 7)},
         {'tag': 55, 'length': 3, 'value': b'\x00\xFF\x07'},
        ),
    )
    accepts_decode = [(_[1], _[0]) for _ in accepts_encode]
    rejects_decode = (
        {'tag': 55, 'length': 0, 'value': b''},
    )
