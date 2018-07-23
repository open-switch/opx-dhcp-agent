#!/usr/bin/env python3

'''Test cases for inocybe_dhcp.options.'''

from nose.tools import assert_equal
from nose.tools import raises

from inocybe_dhcp.options import (Option, Supported, BuiltIn)
from inocybe_dhcp.types import IPv4

### tests for :class:`Option`

class OptionTest(object):
    '''Common test procedures for option implementations.'''
    ### the option class under test
    option = None
    ### a sequence of (input, output) values for `encode` call
    accepts_encode = ()
    ### a sequence of input values raising KeyError, ValueError or TypeError for `encode` call
    rejects_encode = ()
    ### a sequence of (input, output) values for `decode` call
    accepts_decode = ()
    ### a sequence of input values raising KeyError, ValueError or TypeError for `decode` call
    rejects_decode = ()
    def __init__(self):
        self.option_name = self.option.__module__ + '.' + self.option.__name__
    def description(self, fmt, val):
        '''Format and return `fmt` with :attr:`option_name`, class name of `val` and `val`.'''
        try:
            return fmt.format(self.option_name, val.__class__.__name__, val)
        except UnicodeEncodeError:
            return fmt.format(self.option_name, val.__class__.__name__, val.encode('utf-8'))
    def test_accepts_encode(self):
        '''Test option accepts values for encode call.'''
        for (in_, out) in self.accepts_encode:
            func = lambda p=self.option, i=in_, o=out: assert_equal(p.encode(i), o)
            func.description = self.description('Test {} accepts encode {} {}', in_)
            yield func
    def test_rejects_encode(self):
        '''Test option rejects values for encode call.'''
        for in_ in self.rejects_encode:
            func = raises(KeyError, ValueError, TypeError)(lambda p=self.option, i=in_: p.encode(i))
            func.description = self.description('Test {} rejects encode {} {}', in_)
            yield func
    def test_accepts_decode(self):
        '''Test option accepts values for decode call.'''
        for (in_, out) in self.accepts_decode:
            func = lambda p=self.option, i=in_, o=out: assert_equal(p.decode(i), o)
            func.description = self.description('Test {} accepts decode {} {}', in_)
            yield func
    def test_rejects_decode(self):
        '''Test option rejects values for decode call.'''
        for in_ in self.rejects_decode:
            func = raises(KeyError, ValueError, TypeError)(lambda p=self.option, i=in_: p.decode(i))
            func.description = self.description('Test {} rejects decode {} {}', in_)
            yield func

class TagOnly(Option):
    '''A tag-only option implementation.'''
    option = 'tag-only'
    tag = 254

class TestTagOnly(OptionTest):
    '''Tests for tag-only option implementation.'''
    option = TagOnly
    accepts_encode = (
        ({'option': 'tag-only'}, {'tag': 254}),
    )
    rejects_encode = (
        None,
        False, True,
        -1, 0, 1,
        -2.3, 0.1, 4.8,
        '', 'foo',
        (), ('baz',),
        [], ['baz',],
        {}, {'baz': 'quux'},
    ) + (
        {'tag': 253},
        {'length': 1},
        {'value': b'\x42'},
        {'option': 'bad'},
    )
    accepts_decode = (
        ({'tag': 254}, {'option': 'tag-only'}),
        ({'tag': 254, 'length': 1, 'value': b'\x42'}, {'option': 'tag-only'}),
    )
    rejects_decode = (
        None,
        False, True,
        -1, 0, 1,
        -2.3, 0.1, 4.8,
        '', 'foo',
        (), ('baz',),
        [], ['baz',],
        {}, {'baz': 'quux'},
    ) + (
        {'tag': 253},
        {'length': 1},
        {'value': '\x42'},
        {'option': 'tag-only'},
    )

class FixedTlv(Option):
    '''A fixed length tlv option implementation.'''
    option = 'fixed-length-tlv'
    tag = 253
    length = 4
    value_type = IPv4()

class TestFixedTlv(OptionTest):
    '''Tests for fixed-length tlv option implementation.'''
    option = FixedTlv
    accepts_encode = (
        ({'option': 'fixed-length-tlv', 'value': '192.168.1.1'},
         {'tag': 253, 'length': 4, 'value': b'\xC0\xA8\x01\x01'},
        ),
    )
    rejects_encode = (
        None,
        False, True,
        -1, 0, 1,
        -2.3, 0.1, 4.8,
        '', 'foo',
        (), ('baz',),
        [], ['baz',],
        {}, {'baz': 'quux'},
    ) + (
        {'tag': 253},
        {'length': 4},
        {'value': b'\x42'},
        {'option': 'fixed-length-tlv'},
        {'option': 'fixed-length-tlv', 'value': '192.168.1.'},
        {'option': 'fixed-length-tlv', 'value': 2},
    )
    accepts_decode = (
        ({'tag': 253, 'length': 4, 'value': b'\xC0\xA8\x01\x01'},
         {'option': 'fixed-length-tlv', 'value': '192.168.1.1'},
        ),
    )
    rejects_decode = (
        None,
        False, True,
        -1, 0, 1,
        -2.3, 0.1, 4.8,
        '', 'foo',
        (), ('baz',),
        [], ['baz',],
        {}, {'baz': 'quux'},
    ) + (
        {'tag': 253},
        {'length': 4},
        {'value': b'\xC0\xA8\x01\x01'},
        {'length': 4, 'value': b'\xC0\xA8\x01\x01'},
        {'tag': 253, 'length': 4},
        {'tag': 253, 'value': b'\xC0\xA8\x01\x01'},
        {'tag': 252, 'length': 4, 'value': b'\xC0\xA8\x01\x01'},
        {'tag': 253, 'length': 3, 'value': b'\xC0\xA8\x01\x01'},
        {'tag': 253, 'length': 4, 'value': b'\xC0\xA8\x01\x01\xFF'},
        {'tag': 253, 'length': 4, 'value': ('foo', 'bar', 'baz', 'quux')},
    )

class VariableTlv(Option):
    '''A variable-length tlv option implementation.'''
    option = 'variable-length-tlv'
    tag = 252
    value_type = IPv4()

class TestVariableTlv(OptionTest):
    '''Tests for variable-length tlv option implementation: incremental cases over fixed-length.'''
    option = VariableTlv
    rejects_decode = (
        {'tag': 252, 'length': 5, 'value': b'\x0A\x07\x02\x01\xFF'},
    )

### tests for :class:`Supported`

class _MockOption(object): ### pylint: disable=too-few-public-methods
    '''A mock option implementation.'''
    def __init__(self, name, tag):
        self.option = name
        self.tag = tag

class _MockTagOnly(_MockOption): ### pylint: disable=too-few-public-methods
    '''A mock tag-only option implementation.'''
    def encode(self, option): ### pylint: disable=unused-argument
        '''Return fixed encoded option.'''
        return {'tag': self.tag}
    def decode(self, option): ### pylint: disable=unused-argument
        '''Return fixed decoded option.'''
        return {'option': self.option}

class _MockTlv(_MockOption): ### pylint: disable=too-few-public-methods
    '''A mock tlv option implementation.'''
    def __init__(self, name, tag, bad, val):
        _MockOption.__init__(self, name, tag)
        self.bad = bad
        self.val = val
    def encode(self, option):
        '''If `option` has 'value' equal to :attr:`bad` then raise :class:`ValueError`.
           Otherwise, return an encoded option with 'value' :attr:`val`.
        '''
        if option['value'] == self.bad:
            raise ValueError(option)
        return {'tag': self.tag, 'length': len(self.val), 'value': self.val}
    def decode(self, option):
        '''If `option` has 'value' equal to :attr:`bad` then raise :class:`ValueError`.
           Otherwise, return a decoded option with 'value' :attr:`val`.
        '''
        if option['value'] == self.bad:
            raise ValueError(option)
        return {'option': self.option, 'value': self.val}

@raises(ValueError)
def test_supported_duplicate_option():
    '''Test inocybe_dhcp.options.Supported rejects duplicate option name'''
    option = _MockOption('duplicate name', None)
    supported = Supported()
    supported.add(option)
    supported.add(option)

@raises(ValueError)
def test_supported_duplicate_tag():
    '''Test inocybe_dhcp.options.Supported rejects duplicate option tag'''
    supported = Supported()
    supported.add(_MockOption('first', 1))
    supported.add(_MockOption('second', 1))

def test_supported_encode_empty():
    '''Test inocybe_dhcp.options.Supported encodes empty options sequence'''
    supported = Supported()
    assert_equal([], supported.encode([]))

def test_supported_encode_tag():
    '''Test inocybe_dhcp.options.Supported encodes tag options'''
    supported = Supported()
    supported.add(_MockTagOnly('two', 2))
    ### encode of registered option
    assert_equal([{'tag': 2}], supported.encode([{'option': 'two'}]))
    ### encode of unregistered option
    assert_equal([{'tag': 255}], supported.encode([{'tag': 255}]))

def test_supported_encode_tlv():
    '''Test inocybe_dhcp.options.Supported encodes tlv options'''
    supported = Supported()
    supported.add(_MockTlv('three', 3, 'foobar', b'\x05\x06\x07\x08'))
    ### encode of registered option with "good" value
    assert_equal([{
        'tag': 3, 'length': 4, 'value': b'\x05\x06\x07\x08',
    }], supported.encode([{
        'option': 'three', 'value': 'baz',
    }]))
    ### encode of registered option with "bad" value
    assert_equal([{
        'option': 'three', 'value': 'foobar',
    }], supported.encode([{
        'option': 'three', 'value': 'foobar',
    }]))
    ### encode of unregistered option with arbitrary value
    assert_equal([{
        'tag': 4, 'length': 4, 'value': b'\x05\x06\x07\x08',
    }], supported.encode([{
        'tag': 4, 'length': 4, 'value': '05:06:07:08',
    }]))

def test_supported_decode_empty():
    '''Test inocybe_dhcp.options.Supported decodes empty options sequence'''
    supported = Supported()
    assert_equal([], supported.decode([]))

def test_supported_decode_tag():
    '''Test inocybe_dhcp.options.Supported decodes tag options'''
    supported = Supported()
    supported.add(_MockTagOnly('two', 2))
    ### decode of registered option tag
    assert_equal([{'option': 'two'}], supported.decode([{'tag': 2}]))
    ### decode of unregistered option tag
    assert_equal([{'tag': 255}], supported.decode([{'tag': 255}]))

def test_supported_decode_tlv():
    '''Test inocybe_dhcp.options.Supported decodes tlv options'''
    supported = Supported()
    supported.add(_MockTlv('three', 3, b'\x00\x01\x02\x03', 'foo'))
    ### decode of registered option tag with "good" value
    assert_equal([{
        'option': 'three', 'value': 'foo',
    }], supported.decode([{
        'tag': 3, 'length': 4, 'value': b'\x01\x02\x03\x04',
    }]))
    ### decode of registered option tag with "bad" value
    assert_equal([{
        'tag': 3, 'length': 4, 'value': '00:01:02:03',
    }], supported.decode([{
        'tag': 3, 'length': 4, 'value': b'\x00\x01\x02\x03',
    }]))
    ### decode of unregistered option tag with arbitrary value
    assert_equal([{
        'tag': 4, 'length': 4, 'value': '06:07:08:09',
    }], supported.decode([{
        'tag': 4, 'length': 4, 'value': b'\x06\x07\x08\x09',
    }]))

### tests for :class:`BuiltIn`

def test_builtin_encode():
    '''Test inocybe_dhcp.options.BuiltIn encodes options'''
    assert_equal([{'tag': 0}], BuiltIn.encode([{'option': 'Pad'}]))
    assert_equal([{'tag': 255}], BuiltIn.encode([{'option': 'End'}]))

def test_builtin_decode():
    '''Test inocybe_dhcp.options.BuiltIn decodes options'''
    assert_equal([{'option': 'Pad'}], BuiltIn.decode([{'tag': 0}]))
    assert_equal([{'option': 'End'}], BuiltIn.decode([{'tag': 255}]))
