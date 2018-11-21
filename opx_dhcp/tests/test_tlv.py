#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''Test cases for opx_dhcp.tlv.'''

from nose.tools import assert_equal
from nose.tools import raises

from six import add_metaclass

from opx_dhcp.tlv import (
    Int,
    UInt8, UInt16, UInt32,
    IPv4,
    NulTerminatedString,
    HexString,
    Value,
)

class _TestValueType(object):
    '''Common test procedures for a value type.'''
    ### a custom type name to present in test case descriptions (default=class name of value type)
    type_name = None
    ### the value type instance under test
    value_type = None
    ### a sequence of (attribute name, expected value) which `value_type` must have
    attrs = ()
    ### a sequence of (input, output) values for `value_type` call
    accepts_value = ()
    ### a sequence of input values raising ValueError or TypeError for `value_type` call
    rejects_value = ()
    ### a sequence of (input, output) values for `value_type` encode call
    ### if empty, test that `value_type` does not have an encode method
    accepts_encode = ()
    ### a sequence of input values raising ValueError or TypeError for `value_type` encode call
    rejects_encode = ()
    ### a sequence of (input, output) values for `value_type` decode call
    ### if empty, test that `value_type` does not have a decode method
    accepts_decode = ()
    ### a sequence of input values raising ValueError or TypeError for `value_type` decode call
    rejects_decode = ()
    def __init__(self):
        if self.type_name is None:
            self.type_name = self.value_type.__class__.__name__
    def description(self, fmt, val):
        '''Format and return `fmt` with :attr:`type_name`, class name of `val` and `val`.'''
        try:
            return fmt.format(self.type_name, val.__class__.__name__, val)
        except UnicodeEncodeError:
            return fmt.format(self.type_name, val.__class__.__name__, val.encode('utf-8'))
    def test_attrs(self):
        '''Test value type has expected attribute values.'''
        for (attr, val) in self.attrs:
            func = lambda t=self.value_type, a=attr, v=val: assert_equal(getattr(t, a), v)
            func.description = 'Test {} has {} attr value {}'.format(self.type_name, attr, val)
            yield func
    def test_accepts_value(self):
        '''Test value type accepts values for direct call.'''
        for (in_, out) in self.accepts_value:
            func = lambda t=self.value_type, i=in_, o=out: assert_equal(t(i), o)
            func.description = self.description('Test {} accepts value {} {}', in_)
            yield func
    def test_rejects_value(self):
        '''Test value type rejects values for direct call.'''
        for in_ in self.rejects_value:
            func = raises(ValueError, TypeError)(lambda t=self.value_type, i=in_: t(i))
            func.description = self.description('Test {} rejects value {} {}', in_)
            yield func
    def test_accepts_encode(self):
        '''Test value type accepts values for encode call.'''
        for (in_, out) in self.accepts_encode:
            func = lambda t=self.value_type, i=in_, o=out: assert_equal(t.encode(i), o)
            func.description = self.description('Test {} accepts encode {} {}', in_)
            yield func
        if not self.accepts_encode:
            func = raises(AttributeError)(lambda t=self.value_type: t.encode)
            func.description = 'Test {} does not support encode'.format(self.type_name)
            yield func
    def test_rejects_encode(self):
        '''Test value type rejects values for encode call.'''
        for in_ in self.rejects_encode:
            func = raises(ValueError, TypeError)(lambda t=self.value_type, i=in_: t.encode(i))
            func.description = self.description('Test {} rejects encode {} {}', in_)
            yield func
    def test_accepts_decode(self):
        '''Test value type accepts values for decode call.'''
        for (in_, out) in self.accepts_decode:
            func = lambda t=self.value_type, i=in_, o=out: assert_equal(t.decode(i), o)
            func.description = self.description('Test {} accepts decode {} {}', in_)
            yield func
        if not self.accepts_decode:
            func = raises(AttributeError)(lambda t=self.value_type: t.decode)
            func.description = 'Test {} does not support decode'.format(self.type_name)
            yield func
    def test_rejects_decode(self):
        '''Test value type rejects values for decode call.'''
        for in_ in self.rejects_decode:
            func = raises(ValueError, TypeError)(lambda t=self.value_type, i=in_: t.decode(i))
            func.description = self.description('Test {} rejects decode {} {}', in_)
            yield func

### test accepts/rejects integers and stringy integers for all integer classes
### test accepts/rejects other native types only for base integer class

class TestInt(_TestValueType):
    '''Test :class:`Int`.'''
    value_type = Int(-10, 7, 'b')
    attrs = (
        ('min_', -10),
        ('max_', 7),
        ('sfmt', 'b'),
    )
    accepts_value = (
        (-10, -10), (-1, -1), (0, 0), (1, 1), (7, 7),
        ('-10', -10), ('-1', -1), ('0', 0), ('1', 1), ('7', 7),
        ('0x0', 0), ('0x1', 1), ('0x07', 7),
    ) + (
        (False, 0), (True, 1),
        (-10.7, -10), (7.9, 7),
    )
    rejects_value = (
        -11, 8, '-12', '0xA',
    ) + (
        None,
        -11.2, 8.1,
        'foo',
        (), (1, 2),
        [], [1, 2],
        {}, {1: 2},
    )

class TestUInt8(_TestValueType):
    '''Test :class:`UInt8`.'''
    value_type = UInt8()
    attrs = (
        ('min_', 0),
        ('max_', 0xFF),
        ('sfmt', 'B'),
    )
    accepts_value = (
        (0, 0), (1, 1), (254, 254), (255, 255),
        ('0', 0), ('1', 1), ('254', 254), ('255', 255),
        ('0x0', 0), ('0x01', 1), ('0xFE', 254), ('0x00FF', 255),
    )
    rejects_value = (
        -1, 256, '-2', '0x100',
    )

@raises(ValueError)
def test_uint8_min():
    '''Test UInt8 cannot be restricted with negative min_ value'''
    UInt8(min_=-1)

@raises(ValueError)
def test_uint8_max():
    '''Test UInt8 cannot be restricted with out of range max_ value'''
    UInt8(max_=0x100)

class TestUInt8Restricted(_TestValueType):
    '''Test :class:`UInt8` with restricted range.'''
    value_type = UInt8(min_=6, max_=8)
    type_name = 'UInt8(6..8)'
    attrs = (
        ('min_', 6),
        ('max_', 8),
        ('sfmt', 'B'),
    )
    accepts_value = (
        (6, 6), (7, 7), (8, 8),
    )
    rejects_value = (
        0, 5, 9, 255,
    )

class TestUInt16(_TestValueType):
    '''Test :class:`UInt16`.'''
    value_type = UInt16()
    attrs = (
        ('min_', 0),
        ('max_', 0xFFFF),
        ('sfmt', 'H'),
    )
    accepts_value = (
        (0, 0), (1, 1), (65534, 65534), (65535, 65535),
        ('0', 0), ('1', 1), ('65534', 65534), ('65535', 65535),
        ('0x0', 0), ('0x01', 1), ('0xFFFE', 65534), ('0xFFFF', 65535),
    )
    rejects_value = (
        -1, 65536, '-2', '0x010000',
    )

@raises(ValueError)
def test_uint16_min():
    '''Test UInt16 cannot be restricted with negative min_ value'''
    UInt16(min_=-1)

@raises(ValueError)
def test_uint16_max():
    '''Test UInt16 cannot be restricted with out of range max_ value'''
    UInt16(max_=0x10000)

class TestUInt16Restricted(_TestValueType):
    '''Test :class:`UInt16` with restricted range.'''
    value_type = UInt16(min_=996, max_=998)
    type_name = 'UInt16(996..998)'
    attrs = (
        ('min_', 996),
        ('max_', 998),
        ('sfmt', 'H'),
    )
    accepts_value = (
        (996, 996), (997, 997), (998, 998),
    )
    rejects_value = (
        0, 995, 999, 65535,
    )

class TestUInt32(_TestValueType):
    '''Test :class:`UInt32`.'''
    value_type = UInt32()
    attrs = (
        ('min_', 0),
        ('max_', 0xFFFFFFFF),
        ('sfmt', 'I'),
    )
    accepts_value = (
        (0, 0), (1, 1), (4294967294, 4294967294), (4294967295, 4294967295),
        ('0', 0), ('1', 1), ('4294967294', 4294967294), ('4294967295', 4294967295),
        ('0x0', 0), ('0x01', 1), ('0xFFFFFFFE', 4294967294), ('0xFFFFFFFF', 4294967295),
    )
    rejects_value = (
        -1, 4294967296, '-2', '0x100000000',
    )

@raises(ValueError)
def test_uint32_min():
    '''Test UInt32 cannot be restricted with negative min_ value'''
    UInt32(min_=-1)

@raises(ValueError)
def test_uint32_max():
    '''Test UInt32 cannot be restricted with out of range max_ value'''
    UInt32(max_=0x100000000)

class TestUInt32Restricted(_TestValueType):
    '''Test :class:`UInt32` with restricted range.'''
    value_type = UInt32(min_=0xFFFFFFF0, max_=0xFFFFFFF4)
    type_name = 'UInt32(0xFFFFFFF0..0xFFFFFFF4)'
    attrs = (
        ('min_', 4294967280),
        ('max_', 4294967284),
        ('sfmt', 'I'),
    )
    accepts_value = (
        (4294967280, 4294967280),
        (4294967281, 4294967281),
        (4294967282, 4294967282),
        (4294967283, 4294967283),
        (4294967284, 4294967284),
    )
    rejects_value = (
        0, 4294967279, 4294967285, 4294967295,
    )

class TestIPv4(_TestValueType):
    '''Test :class:`IPv4`.'''
    value_type = IPv4()
    attrs = (
        ('sfmt', '4s'),
    )
    accepts_value = (
        ('0.0.0.0', '0.0.0.0'),
        ('1.2.3.4', '1.2.3.4'),
        ('255.255.255.255', '255.255.255.255'),
    )
    rejects_value = (
        'foo', '1.2.3', '256.0.0.0',
    ) + (
        None,
        False, True,
        -1, 0, 1,
        -2.3, 0.1, 4.8,
        (), ('1.2.3.4',),
        [], ['0.0.0.0',],
        {}, {'255.255.255.255': '0.0.0.0'},
    )
    accepts_encode = (
        ('0.0.0.0', b'\x00\x00\x00\x00'),
        ('1.2.3.4', b'\x01\x02\x03\x04'),
        ('255.255.255.255', b'\xFF\xFF\xFF\xFF'),
    )
    rejects_encode = rejects_value
    accepts_decode = tuple([(_[1], _[0]) for _ in accepts_encode])
    rejects_decode = rejects_value + (
        b'\x00',
        b'\x00\x00',
        b'\x00\x00\x00',
        b'\x00\x00\x00\x00\x00',
    )

class TestNulTerminatedString(_TestValueType):
    '''Test :class:`NulTerminatedString` for default encoding.'''
    value_type = NulTerminatedString(10)
    attrs = (
        ('max_', 10),
        ('encoding', 'iso-8859-1'),
        ('sfmt', '10s'),
    )
    accepts_value = (
        ('', ''),
        ('foo', 'foo'),
        ('bar' * 3, 'bar' * 3),
        (u'ìë', u'ìë'),
    )
    rejects_value = (
        'bar' * 3 + 'b',
        u'ìë' * 5,
        u'실례@', ### short enough, but cannot encode
    ) + (
        None,
        False, True,
        -1, 0, 1,
        -2.3, 0.1, 4.8,
        (), ('baz',),
        [], ['baz',],
        {}, {'baz': 'quux'},
    )
    accepts_encode = (
        ('', b''),
        ('foo', b'foo'),
        ('bar' * 3, b'bar' * 3),
        (u'ìë', b'\xec\xeb'),
        (u'ìë' * 4, b'\xec\xeb' * 4),
    )
    rejects_encode = rejects_value
    accepts_decode = tuple([(_[1], _[0]) for _ in accepts_encode]) + (
        (b'\x00', ''),
        (b'\xec\xeb', u'ìë'),
        ### oversize binary string but only because of zero padding
        (b'\xec\x8b\xa4\xeb\xa1\x80' + b'\x00' * 30, u'실례'.encode('utf-8').decode('latin-1')),
    )
    rejects_decode = rejects_value + (
        b'bar' * 3 + b'b',
        b'\xec\xeb' * 5,
        u'실'.encode('utf-8') * 4,
    )

class TestNulTerminatedUTF8(_TestValueType):
    '''Test :class:`NulTerminatedString` for utf-8 encoding.'''
    value_type = NulTerminatedString(33, encoding='utf-8')
    type_name = 'NulTerminatedString(encoding="utf-8")'
    attrs = (
        ('max_', 33),
        ('encoding', 'utf-8'),
        ('sfmt', '33s'),
    )
    accepts_value = (
        ('', ''),
        ('foo', 'foo'),
        ('bar' * 10 + 'ba', 'bar' * 10 + 'ba'),
        (u'실례@실례.테스트', u'실례@실례.테스트'),
    )
    rejects_value = (
        'bar' * 11,
        u'실' * 11,
    ) + (
        None,
        False, True,
        -1, 0, 1,
        -2.3, 0.1, 4.8,
        (), ('baz',),
        [], ['baz',],
        {}, {'baz': 'quux'},
    )
    accepts_encode = (
        ('', b''),
        ('foo', b'foo'),
        ('bar' * 10 + 'ba', b'bar' * 10 + b'ba'),
        (u'실례@실례.테스트',
         b'\xec\x8b\xa4\xeb\xa1\x80@\xec\x8b\xa4\xeb\xa1\x80.\xed\x85\x8c\xec\x8a\xa4\xed\x8a\xb8',
        ),
    )
    rejects_encode = rejects_value
    accepts_decode = tuple([(_[1], _[0]) for _ in accepts_encode]) + (
        (b'\x00', ''),
        ### oversize binary string but only because of zero padding
        (b'\xec\x8b\xa4\xeb\xa1\x80' + b'\x00' * 30, u'실례'),
    )
    rejects_decode = rejects_value + (
        b'bar' * 11,
        u'실'.encode('utf-8') * 11,
    )

class TestHexString(_TestValueType):
    '''Test :class:`HexString`.'''
    value_type = HexString(6)
    attrs = (
        ('max_', 6),
        ('sfmt', '6s'),
    )
    accepts_value = (
        ('', ''),
        ('0a', '0a'),
        ('0A', '0A'),
        ('0a:1b', '0a:1b'),
        ('0a:1B', '0a:1B'),
        ('0A:1B', '0A:1B'),
        ('0a:1b:c2:d3:4e:5f', '0a:1b:c2:d3:4e:5f'),
        ('0a:1B:c2:D3:4e:5F', '0a:1B:c2:D3:4e:5F'),
        ('0A:1B:C2:D3:4E:5F', '0A:1B:C2:D3:4E:5F'),
        ('00:00:00:00:00:00', '00:00:00:00:00:00'),
        ('ff:ff:ff:ff:ff:ff', 'ff:ff:ff:ff:ff:ff'),
        ('ff:ff:ff:FF:FF:FF', 'ff:ff:ff:FF:FF:FF'),
        ('FF:FF:FF:FF:FF:FF', 'FF:FF:FF:FF:FF:FF'),
    )
    rejects_value = (
        'foo', 'foo:bar',
        'X', 'Y:0A', '00:Z', '01:X:AB',
        'ABC', 'AB C', 'A B C',
    ) + (
        None,
        False, True,
        -1, 0, 1,
        -2.3, 0.1, 4.8,
        (), ('AB',),
        [], ['AB',],
        {}, {'AB': 'CD'},
    )
    accepts_encode = (
        ('', b''),
        ('0a', b'\x0A'),
        ('0a:1b', b'\x0A\x1B'),
        ('0a:1b:c2:d3:4e:5f', b'\x0A\x1B\xC2\xD3\x4E\x5F'),
        ('00:00:00:00:00:00', b'\x00\x00\x00\x00\x00\x00'),
        ('ff:ff:ff:ff:ff:ff', b'\xFF\xFF\xFF\xFF\xFF\xFF'),
    )
    rejects_encode = rejects_value
    accepts_decode = tuple([(_[1], _[0]) for _ in accepts_encode])
    rejects_decode = (
        None,
        False, True,
        -1, 0, 1,
        -2.3, 0.1, 4.8,
        (), ('AB',),
        [], ['AB',],
        {}, {'AB': 'CD'},
    ) + (
        b'\x00\x00\x00\x00\x00\x00\x00',
        b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF',
    )
    def test_truncate(self):
        '''Test HexString truncate method'''
        assert_equal(self.value_type.truncate('', 3), '')
        assert_equal(self.value_type.truncate('00', 3), '00')
        assert_equal(self.value_type.truncate('00:11:22', 3), '00:11:22')
        assert_equal(self.value_type.truncate('00:11:22:33', 3), '00:11:22')
        assert_equal(self.value_type.truncate('00:11:22:33:44:55', 3), '00:11:22')

### pylint: disable=too-few-public-methods,unsubscriptable-object,no-member

@add_metaclass(Value)
class Simple(object):
    '''A simple message class/structured value for testing: only specifies field :attr:`spec`.'''
    name = 'simple message for testing'
    spec = (
        ('foo', UInt32()),
        ('bar', NulTerminatedString(16)),
        ('baz', IPv4()),
    )

def test_simple_success():
    '''Test Value-based class as a dict'''
    ### create like a dict
    simple = Simple(foo=0x48, bar='quuz', baz='192.168.1.1')
    ### is a dict
    assert_equal(True, isinstance(simple, dict))
    ### has dict value
    assert_equal({'foo': 72, 'bar': 'quuz', 'baz': '192.168.1.1'}, simple)
    ### has keys
    assert_equal(simple['foo'], 72)
    assert_equal(simple['bar'], 'quuz')
    assert_equal(simple['baz'], '192.168.1.1')
    ### del key
    del simple['bar']
    assert_equal({'foo': 72, 'baz': '192.168.1.1'}, simple)
    assert_equal(simple['foo'], 72)
    raises(KeyError)(lambda s=simple: s['bar'])()
    assert_equal(simple['baz'], '192.168.1.1')
    ### has update method
    simple.update(bar='thud', baz='10.0.0.8')
    assert_equal({'foo': 72, 'bar': 'thud', 'baz': '10.0.0.8'}, simple)
    assert_equal(simple['foo'], 72)
    assert_equal(simple['bar'], 'thud')
    assert_equal(simple['baz'], '10.0.0.8')
    ### only updates if all good
    raises(ValueError)(lambda s=simple: s.update(foo=9, bar='corge', baz='not an IP address'))()
    assert_equal({'foo': 72, 'bar': 'thud', 'baz': '10.0.0.8'}, simple)
    assert_equal(simple['foo'], 72)
    assert_equal(simple['bar'], 'thud')
    assert_equal(simple['baz'], '10.0.0.8')

@raises(KeyError)
def test_simple_set_bad_key():
    '''Test Value-based class set rejects bad key'''
    simple = Simple()
    simple['quux'] = True

@raises(TypeError)
def test_simple_set_bad_type():
    '''Test Value-based class set rejects bad value type'''
    simple = Simple()
    simple['foo'] = {'a': 'b'}

@raises(ValueError)
def test_simple_set_bad_value():
    '''Test Value-based class set rejects bad value'''
    simple = Simple()
    simple['foo'] = 'not an integer'

@raises(KeyError)
def test_simple_update_bad_key():
    '''Test Value-based class update rejects bad key'''
    simple = Simple()
    simple.update(quux=True)

@raises(TypeError)
def test_simple_update_bad_type():
    '''Test Value-based class update rejects bad value type'''
    simple = Simple()
    simple.update((('foo', {'a': 'b'}),))

@raises(ValueError)
def test_simple_update_bad_value():
    '''Test Value-based class update rejects bad value'''
    simple = Simple()
    simple.update({'foo': 'not an integer'})

def test_simple_encode():
    '''Test Value-based class encode method'''
    simple = Simple({'foo': 0xFEDCBA98, 'bar': 'quuz', 'baz': '192.168.1.1'})
    assert_equal(
        simple.encode(),
        ### UInt32 in network-byte order
        b'\xfe\xdc\xba\x98' +
        ### NulTerminatedString zero right padded to fixed field size
        b'quuz' + b'\0' * 12 +
        ### IPv4 in network-byte order
        b'\xc0\xa8\x01\x01'
    )

def test_simple_decode():
    '''Test Value-based class decode method'''
    encoded = (
        ### UInt32 in network-byte order
        b'\x00\x00\x00\x63' +
        ### NulTerminatedString zero right padded to fixed field size and literally "corrupted"
        b'corge' + b'\0' + b'corrupted' + b'\0' +
        ### IPv4 in network-byte order
        b'\x0a\x06\x00\x07' +
        ### trailing stuff which should be ignored/discarded
        b'gumph'
    )
    simple = Simple.decode(encoded)
    assert_equal({'foo': 99, 'bar': 'corge', 'baz': '10.6.0.7'}, simple)

class Ethernet(object):
    '''A class for testing custom bases are supported.'''
    def __init__(self, key):
        self.key = key
    def clear_multicast_bit(self):
        '''Clear the multicast bit in the hex string at :attr:`key`.'''
        ### multicast bit is least significant bit of first octet
        elems = self[self.key].split(':')
        elems[0] = '{:02x}'.format(int(elems[0], base=16) & 0xFE)
        self[self.key] = ':'.join(elems)

@add_metaclass(Value)
class Custom(Ethernet):
    '''A custom message class/structured value for testing.'''
    name = 'custom message for testing'
    spec = (
        ('len', UInt8(min_=6, max_=16)),
        ('mac', HexString(max_=16)),
    )
    def __init__(self):
        Ethernet.__init__(self, 'mac')
    def make_unicast(self):
        '''If this message's mac could be an ethernet address, make it a unicast address.'''
        if self['len'] == 6:
            self.clear_multicast_bit()

def test_custom_success():
    '''Test Value-based class supports customisation'''
    custom = Custom((('len', 6), ('mac', '11:22:33:44:55:66'))) ### pylint: disable=too-many-function-args
    assert_equal({'len': 6, 'mac': '11:22:33:44:55:66'}, custom)
    ### supports custom __init__ and custom attributes
    assert_equal('mac', custom.key)
    ### supports custom methods
    custom.make_unicast()
    assert_equal({'len': 6, 'mac': '10:22:33:44:55:66'}, custom)
