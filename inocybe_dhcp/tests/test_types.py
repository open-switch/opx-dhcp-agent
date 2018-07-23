#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''Test cases for inocybe_dhcp.types.'''

from nose.tools import assert_equal
from nose.tools import raises

from six import add_metaclass

from inocybe_dhcp.types import (
    ValueType,
    Int, Enum,
    UInt8, UInt16, UInt32, SInt32,
    IPv4,
    NulTerminatedString,
    HexString,
    StructuredValue,
)

def test_value_type():
    '''Test inocybe_dhcp.types.ValueType default behaviours'''
    value_type = ValueType()
    assert_equal(None, value_type.sfmt)
    assert_equal('foo', value_type.encode('foo'))
    assert_equal(-7.3, value_type.decode(-7.3))

@raises(NotImplementedError)
def test_value_type_call_abstract():
    '''Test inocybe_dhcp.types.ValueType __call__() is abstract'''
    ValueType()(None)

@raises(NotImplementedError)
def test_value_type_pack_abstract():
    '''Test inocybe_dhcp.types.ValueType pack() is abstract'''
    ValueType().pack(None)

@raises(NotImplementedError)
def test_value_type_unpack_abstract():
    '''Test inocybe_dhcp.types.ValueType unpack() is abstract'''
    ValueType().unpack(None)

class ValueTypeTest(object):
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
    ### a sequence of (input, output) values for `value_type` pack call
    accepts_pack = ()
    ### a sequence of input values raising ValueError or TypeError for `value_type` pack call
    rejects_pack = ()
    ### a sequence of (input, output) values for `value_type` unpack call
    accepts_unpack = ()
    ### a sequence of input values raising ValueError or TypeError for `value_type` unpack call
    rejects_unpack = ()
    ### a sequence of (input, output) values for `value_type` encode call
    accepts_encode = ()
    ### a sequence of input values raising ValueError or TypeError for `value_type` encode call
    rejects_encode = ()
    ### a sequence of (input, output) values for `value_type` decode call
    accepts_decode = ()
    ### a sequence of input values raising ValueError or TypeError for `value_type` decode call
    rejects_decode = ()
    def __init__(self):
        if self.type_name:
            self.type_name = self.value_type.__module__ + '.' + self.type_name
        else:
            self.type_name = self.value_type.__module__ + '.' + self.value_type.__class__.__name__
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
    def test_accepts_pack(self):
        '''Test value type accepts values for pack call.'''
        for (in_, out) in self.accepts_pack:
            func = lambda t=self.value_type, i=in_, o=out: assert_equal(t.pack(i), o)
            func.description = self.description('Test {} accepts pack {} {}', in_)
            yield func
    def test_rejects_pack(self):
        '''Test value type rejects values for pack call.'''
        for in_ in self.rejects_pack:
            func = raises(ValueError, TypeError)(lambda t=self.value_type, i=in_: t.pack(i))
            func.description = self.description('Test {} rejects pack {} {}', in_)
            yield func
    def test_accepts_unpack(self):
        '''Test value type accepts values for unpack call.'''
        for (in_, out) in self.accepts_unpack:
            func = lambda t=self.value_type, i=in_, o=out: assert_equal(t.unpack(i), o)
            func.description = self.description('Test {} accepts unpack {} {}', in_)
            yield func
    def test_rejects_unpack(self):
        '''Test value type rejects values for unpack call.'''
        for in_ in self.rejects_unpack:
            func = raises(ValueError, TypeError)(lambda t=self.value_type, i=in_: t.unpack(i))
            func.description = self.description('Test {} rejects unpack {} {}', in_)
            yield func
    def test_accepts_encode(self):
        '''Test value type accepts values for encode call.'''
        for (in_, out) in self.accepts_encode:
            func = lambda t=self.value_type, i=in_, o=out: assert_equal(t.encode(i), o)
            func.description = self.description('Test {} accepts encode {} {}', in_)
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
    def test_rejects_decode(self):
        '''Test value type rejects values for decode call.'''
        for in_ in self.rejects_decode:
            func = raises(ValueError, TypeError)(lambda t=self.value_type, i=in_: t.decode(i))
            func.description = self.description('Test {} rejects decode {} {}', in_)
            yield func

### test accepts/rejects integers and stringy integers for all integer classes
### test accepts/rejects other native types only for base integer class

class TestInt(ValueTypeTest):
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

class TestEnum(ValueTypeTest):
    '''Test :class:`Enum`.'''
    value_type = Enum(-1, 3, 'b', ((-1, 'foo'), (0, 'bar'), (1, 'baz'), (3, 'quux')))
    attrs = (
        ('min_', -1),
        ('max_', 3),
        ('sfmt', 'b'),
        ('label_to_value', {'foo': -1, 'bar': 0, 'baz': 1, 'quux': 3}),
        ('value_to_label', {-1: 'foo', 0: 'bar', 1: 'baz', 3: 'quux'}),
    )
    accepts_value = (
        (-1, 'foo'), (0, 'bar'), (1, 'baz'), (3, 'quux'),
        ('-1', 'foo'), ('0', 'bar'), ('1', 'baz'), ('3', 'quux'),
        ('-0x1', 'foo'), ('0x0', 'bar'), ('0x1', 'baz'), ('0x3', 'quux'),
    ) + (
        ('foo', 'foo'), ('bar', 'bar'), ('baz', 'baz'), ('quux', 'quux'),
    ) + (
        (False, 'bar'), (True, 'baz'),
    )
    rejects_value = (
        -2, 2, 4, 'thud',
    ) + (
        None,
        -11.2, 8.1,
        (), (1, 2),
        [], [1, 2],
        {}, {1: 2},
    )
    accepts_encode = (
        ('foo', -1), ('bar', 0), ('baz', 1), ('quux', 3),
    )
    rejects_encode = (
        'thud', -2, -1, 0, 1, 2, 3, 4,
    )
    accepts_decode = (
        (-1, 'foo'), (0, 'bar'), (1, 'baz'), (3, 'quux'),
    )
    rejects_decode = (
        'foo', 'bar', 'baz', 'quux', 'thud', -2, 2, 4,
    )

class TestUInt8(ValueTypeTest):
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
    '''Test inocybe_dhcp.types.UInt8 cannot be restricted with negative min_ value'''
    UInt8(min_=-1)

@raises(ValueError)
def test_uint8_max():
    '''Test inocybe_dhcp.types.UInt8 cannot be restricted with out of range max_ value'''
    UInt8(max_=0x100)

class TestUInt8Restricted(ValueTypeTest):
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

class TestUInt16(ValueTypeTest):
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
    '''Test inocybe_dhcp.types.UInt16 cannot be restricted with negative min_ value'''
    UInt16(min_=-1)

@raises(ValueError)
def test_uint16_max():
    '''Test inocybe_dhcp.types.UInt16 cannot be restricted with out of range max_ value'''
    UInt16(max_=0x10000)

class TestUInt16Restricted(ValueTypeTest):
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

class TestUInt32(ValueTypeTest):
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
    '''Test inocybe_dhcp.types.UInt32 cannot be restricted with negative min_ value'''
    UInt32(min_=-1)

@raises(ValueError)
def test_uint32_max():
    '''Test inocybe_dhcp.types.UInt32 cannot be restricted with out of range max_ value'''
    UInt32(max_=0x100000000)

class TestUInt32Restricted(ValueTypeTest):
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

class TestSInt32(ValueTypeTest):
    '''Test :class:`SInt32`.'''
    value_type = SInt32()
    attrs = (
        ('min_', -0x80000000),
        ('max_', 0x7FFFFFFF),
        ('sfmt', 'i'),
    )
    accepts_value = (
        (-2147483648, -2147483648), (-1, -1), (0, 0), (1, 1), (2147483647, 2147483647),
        ('-2147483648', -2147483648), ('-1', -1), ('0', 0), ('1', 1), ('2147483647', 2147483647),
        ('-0x80000000', -2147483648), ('-0x01', -1), ('0x0', 0), ('0x1', 1),
        ('0x7FFFFFFF', 2147483647),
    )
    rejects_value = (
        -2147483649, 2147483648,
        '-0x80000001', '0x80000000',
    )

@raises(ValueError)
def test_sint32_min():
    '''Test inocybe_dhcp.types.SInt32 cannot be restricted with out of range min_ value'''
    SInt32(min_=-0x80000001)

@raises(ValueError)
def test_sint32_max():
    '''Test inocybe_dhcp.types.SInt32 cannot be restricted with out of range max_ value'''
    SInt32(max_=0x80000000)

class TestSInt32Restricted(ValueTypeTest):
    '''Test :class:`SInt32` with restricted range.'''
    value_type = SInt32(min_=-3, max_=4)
    type_name = 'SInt32(-3..4)'
    attrs = (
        ('min_', -3),
        ('max_', 4),
        ('sfmt', 'i'),
    )
    accepts_value = (
        (-3, -3),
        (-2, -2),
        (-1, -1),
        (0, 0),
        (1, 1),
        (2, 2),
        (3, 3),
        (4, 4),
    )
    rejects_value = (
        -4, 5,
    )

class TestIPv4(ValueTypeTest):
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

class TestNulTerminatedString(ValueTypeTest):
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

class TestNulTerminatedUTF8(ValueTypeTest):
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

class TestHexString(ValueTypeTest):
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
        '''Test inocybe_dhcp.types.HexString truncate method'''
        assert_equal(self.value_type.truncate('', 3), '')
        assert_equal(self.value_type.truncate('00', 3), '00')
        assert_equal(self.value_type.truncate('00:11:22', 3), '00:11:22')
        assert_equal(self.value_type.truncate('00:11:22:33', 3), '00:11:22')
        assert_equal(self.value_type.truncate('00:11:22:33:44:55', 3), '00:11:22')

### pylint: disable=too-few-public-methods,unsubscriptable-object,no-member

@add_metaclass(StructuredValue)
class Simple(object):
    '''A simple message class/structured value for testing: only specifies field :attr:`spec`.'''
    name = 'simple message for testing'
    spec = (
        ('foo', UInt32()),
        ('bar', NulTerminatedString(16)),
        ('baz', IPv4()),
    )

def test_simple_success():
    '''Test inocybe_dhcp.types.StructuredValue-based class as a dict'''
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
    '''Test inocybe_dhcp.types.StructuredValue-based class set rejects bad key'''
    simple = Simple()
    simple['quux'] = True

@raises(TypeError)
def test_simple_set_bad_type():
    '''Test inocybe_dhcp.types.StructuredValue-based class set rejects bad value type'''
    simple = Simple()
    simple['foo'] = {'a': 'b'}

@raises(ValueError)
def test_simple_set_bad_value():
    '''Test inocybe_dhcp.types.StructuredValue-based class set rejects bad value'''
    simple = Simple()
    simple['foo'] = 'not an integer'

@raises(KeyError)
def test_simple_update_bad_key():
    '''Test inocybe_dhcp.types.StructuredValue-based class update rejects bad key'''
    simple = Simple()
    simple.update(quux=True)

@raises(TypeError)
def test_simple_update_bad_type():
    '''Test inocybe_dhcp.types.StructuredValue-based class update rejects bad value type'''
    simple = Simple()
    simple.update((('foo', {'a': 'b'}),))

@raises(ValueError)
def test_simple_update_bad_value():
    '''Test inocybe_dhcp.types.StructuredValue-based class update rejects bad value'''
    simple = Simple()
    simple.update({'foo': 'not an integer'})

def test_simple_pack():
    '''Test inocybe_dhcp.types.StructuredValue-based class pack method'''
    simple = Simple({'foo': 0xFEDCBA98, 'bar': 'quuz', 'baz': '192.168.1.1'})
    assert_equal(
        simple.pack(),
        ### UInt32 in network-byte order
        b'\xfe\xdc\xba\x98' +
        ### NulTerminatedString zero right padded to fixed field size
        b'quuz' + b'\0' * 12 +
        ### IPv4 in network-byte order
        b'\xc0\xa8\x01\x01'
    )

def test_simple_unpack():
    '''Test inocybe_dhcp.types.StructuredValue-based class unpack method'''
    packed = (
        ### UInt32 in network-byte order
        b'\x00\x00\x00\x63' +
        ### NulTerminatedString zero right padded to fixed field size and literally "corrupted"
        b'corge' + b'\0' + b'corrupted' + b'\0' +
        ### IPv4 in network-byte order
        b'\x0a\x06\x00\x07' +
        ### trailing stuff which should be ignored/discarded
        b'gumph'
    )
    simple = Simple.unpack(packed)
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

@add_metaclass(StructuredValue)
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
    '''Test inocybe_dhcp.types.StructuredValue-based class supports customisation'''
    custom = Custom((('len', 6), ('mac', '11:22:33:44:55:66'))) ### pylint: disable=too-many-function-args
    assert_equal({'len': 6, 'mac': '11:22:33:44:55:66'}, custom)
    ### supports custom __init__ and custom attributes
    assert_equal('mac', custom.key)
    ### supports custom methods
    custom.make_unicast()
    assert_equal({'len': 6, 'mac': '10:22:33:44:55:66'}, custom)
