from unittest import TestCase
from datetime import datetime

from format_cef import cef


class TestCef(TestCase):
    def test_escaping(self):
        escape = cef.escaper('|=')
        self.assertEqual(
            escape(r'|some|really\nasty\\things\|to=try\='),
            r'\|some\|really\\nasty\\things\|to\=try\=')

    def test_unbounded_str_sanitisation(self):
        sanitise = cef.str_sanitiser('banana')
        self.assertEqual(sanitise('banana', 'label'), 'banana')
        self.assertRaises(ValueError, sanitise, 'apple', 'label')
        sanitise = cef.str_sanitiser()
        self.assertEqual(sanitise('', 'label'), '')
        sanitise = cef.str_sanitiser(min_len=1)
        self.assertRaises(ValueError, sanitise, '', 'label')
        self.assertEqual(sanitise('a', 'label'), 'a')

    def test_bounded_str_sanitisation(self):
        sanitise = cef.str_sanitiser(
            '[banana]*', min_len=3, max_len=6, escape_chars='b')
        self.assertRaises(ValueError, sanitise, 'an', 'label')
        self.assertEqual(sanitise('ba', 'label'), r'\ba')
        self.assertEqual(sanitise('banan', 'label'), r'\banan')
        # Escaping makes string too long:
        self.assertRaisesRegexp(
            ValueError, 'range', sanitise, 'banana', 'label')
        self.assertRaises(ValueError, sanitise, 'apple', 'label')
        self.assertRaises(TypeError, sanitise, 3, 'label')

    def test_int_stanitisation(self):
        sanitise = cef.int_sanitiser(min=0, max=32)
        self.assertEqual(sanitise(0, 'label'), '0')
        self.assertEqual(sanitise(32, 'label'), '32')
        self.assertRaises(ValueError, sanitise, -1, 'label')
        self.assertRaises(ValueError, sanitise, 33, 'label')
        self.assertRaises(TypeError, sanitise, 'moo', 'label')

    def test_float_sanitisation(self):
        sanitise = cef.float_sanitiser()
        self.assertEqual(sanitise(1.3, 'label'), '1.3')
        self.assertRaises(TypeError, sanitise, 'moo', 'label')

    def test_datetime_sanitisation(self):
        sanitise = cef.datetime_sanitiser()
        d = datetime(2017, 4, 10, 1, 2, 3)
        expected = 'Apr 10 2017 01:02:03'
        self.assertEqual(sanitise(d, 'label'), expected)
        self.assertRaises(TypeError, sanitise, expected, 'label')

    def test_ensure_in_range(self):
        self.assertRaises(ValueError, cef.ensure_in_range, 'test', 3, 5, 2)
        cef.ensure_in_range('test', 3, 5, 3)
        cef.ensure_in_range('test', 3, 5, 4)
        cef.ensure_in_range('test', 3, 5, 5)
        self.assertRaises(ValueError, cef.ensure_in_range, 'test', 3, 5, 6)
        cef.ensure_in_range('test', None, 5, 4)
        cef.ensure_in_range('test', None, 5, 5)
        self.assertRaises(ValueError, cef.ensure_in_range, 'test', None, 5, 6)
        cef.ensure_in_range('test', 3, None, 4)
        cef.ensure_in_range('test', 3, None, 3)
        self.assertRaises(ValueError, cef.ensure_in_range, 'test', 3, None, 2)
        cef.ensure_in_range('test', None, None, 42)

    def test_format_cef(self):
        args = (
            'acme corp', 'TNT', '1.0', '404 | not found',
            'Explosives not found', 10)
        self.assertEqual(
            cef.format_cef(*args, extensions={'deviceAction': 'explode = !'}),
            r'CEF:0|acme corp|TNT|1.0|404 \| not found|Explosives not found|'
            r'10|act=explode \= !')

    def test_extensions_with_prototypical_data(self):
        # This pretty much just checks that all the sanitisers execute!
        example_data = {
            'baseEventCount': 8,
            'bytesIn': 15860,
            'bytesOut': 9999,
            'destinationAddress': '1.2.3.4',
            'destinationMacAddress': '00:18:1a:c8:cc:aa',
            'destinationPort': 22,
            'destinationProcessId': 3210,
            'destinationTranslatedAddress': '192.168.0.120',
            'destinationTranslatedPort': 12000,
            'deviceAddress': '2.3.4.5',
            'deviceCustomDate1': datetime(2019, 9, 25, 10, 59, 50),
            'deviceCustomDate2': datetime(2018, 7, 10, 11, 23, 59),
            'deviceCustomFloatingPoint1': 1.0,
            'deviceCustomFloatingPoint2': 2.0,
            'deviceCustomFloatingPoint3': 3.0,
            'deviceCustomFloatingPoint4': 4.0,
            'deviceCustomIPv6Address1': '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
            'deviceCustomIPv6Address3': 'aa:2:3:4:5:6:7:8',
            'deviceCustomIPv6Address4': '1:2:3:4:5:6:7:8',
            'deviceCustomNumber1': 1,
            'deviceCustomNumber2': 2,
            'deviceCustomNumber3': 3,
            'deviceDirection': 1,
            'deviceMacAddress': '10:b1:1a:77:AB:BC',
            'deviceProcessId': 5530,
            'deviceReceiptTime': datetime(2017, 11, 10, 11, 23, 59),
            'deviceTranslatedAddress': '30.99.66.77',
            'endTime': datetime(2017, 8, 9, 9, 14, 33),
            'fileCreateTime': datetime(2008, 1, 1, 1, 1, 1),
            'fileModificationTime': datetime(2019, 12, 23, 11, 23, 59),
            'fileSize': 128357,
            'flexDate1': datetime(2019, 9, 5, 16, 23, 10),
            'oldFileCreateTime': datetime(2019, 9, 25, 23, 8, 55),
            'oldFileModificationTime': datetime(2010, 10, 10, 10, 10, 10),
            'oldFileSize': 130962,
            'sourceAddress': '3.4.5.6',
            'sourceMacAddress': '33:99:29:00:cc:aa',
            'sourcePort': 22,
            'sourceProcessId': 123,
            'sourceTranslatedAddress': '6.7.8.9',
            'sourceTranslatedPort': 1234,
            'start': datetime(2017, 8, 9, 9, 0, 0),
            'startTime': datetime(2019, 11, 11, 11, 11, 11),
            'type': 0,
        }
        for extension_name, (key_name, f) in cef.valid_extensions.items():
            f(example_data.get(extension_name, 'foo'), extension_name)
