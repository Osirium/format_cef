import re
from datetime import datetime
from collections import namedtuple


def format_cef(
        vendor, product, product_version, event_id, event_name, severity,
        extensions):
    """Produces a CEF compliant message from the arguments.

    :parameter str vendor: Vendor part of the product type identifier
    :parameter str product: Product part of the product type identifier
    :parameter str product_version: Version part of the product type identifier
    :parameter str event_id: A unique identifier for the type of event being
        reported
    :parameter str event_name: A human-friendly description of the event
    :parameter int severity: Between 0 and 10 inclusive.
    :parameter dict extensions: key-value pairs for event metadata.
    """
    extension_strs = {
        valid_extensions[name].key_name:
            _equals_escaper(valid_extensions[name].sanitiser(value, name))
        for name, value in extensions.items()}
    extensions_str = ' '.join(sorted(
        '{}={}'.format(k, v) for k, v in extension_strs.items()))
    pfs = _prefix_field_str_sanitiser
    return '|'.join((
        'CEF:0', pfs(vendor, 'VENDOR'), pfs(product, 'PRODUCT'),
        pfs(product_version, 'VERSION'), pfs(event_id, 'EVENT_ID'),
        pfs(event_name, 'EVENT_NAME'),
        _severity_sanitiser(severity, 'SEVERITY'), extensions_str))


def escaper(special_chars):
    strip_escaped_re = re.compile(
        r'\\([{}\\])'.format(special_chars))
    do_escape_re = re.compile(r'([{}\\])'.format(special_chars))

    def escape(s):
        stripped = strip_escaped_re.sub(r'\1', s)
        return do_escape_re.sub(r'\\\1', stripped)
    return escape


def ensure_in_range(debug_name, min, max, num):
    if max is None:
        if min is not None and num < min:
            raise ValueError('{}: {} less than {}'.format(
                debug_name, num, min))
    elif min is None:
        if max is not None and num > max:
            raise ValueError('{}: {} greater than {}'.format(
                debug_name, num, max))
    elif not min <= num <= max:
        raise ValueError('{}: {} out of range {}-{}'.format(
            debug_name, num, min, max))


def int_sanitiser(max=None, min=None):
    def sanitise(n, debug_name):
        if not isinstance(n, int):
            raise TypeError('{}: Expected int, got {}'.format(
                debug_name, type(n)))
        ensure_in_range(debug_name, min, max, n)
        return str(n)
    return sanitise


_severity_sanitiser = int_sanitiser(min=0, max=10)


def float_sanitiser():
    def sanitise(n, debug_name):
        if not isinstance(n, float):
            raise TypeError('{}: Expected float, got {}'.format(
                debug_name, type(n)))
        else:
            return str(n)
    return sanitise


def str_sanitiser(regex_str='.*', escape_chars='', min_len=0, max_len=None):
    regex = re.compile('^{}$'.format(regex_str))
    escape = escaper(escape_chars)

    def sanitise(s, debug_name):
        if not isinstance(s, basestring):
            raise TypeError('{}: Expected str, got {}'.format(
                debug_name, type(s)))
        elif not regex.match(s):
            raise ValueError(
                '{}: {!r} did not match regex {!r}'.format(
                    debug_name, s, regex_str))
        else:
            if isinstance(s, unicode):
                s = s.encode('utf-8')
            s = escape(s)
            if max_len is None:
                if len(s) < min_len:
                    raise ValueError(
                        '{}: String shorter than {} characters'.format(
                            debug_name, min_len))
            else:
                if not min_len <= len(s) <= max_len:
                    raise ValueError(
                        '{}: String length out of range {}-{}'.format(
                            debug_name, min_len, max_len))
            return s
    return sanitise


_prefix_field_str_sanitiser = str_sanitiser('[^\r\n]*', escape_chars='|')
_equals_escaper = escaper('=')


def datetime_sanitiser():
    def sanitise(t, debug_name):
        if not isinstance(t, datetime):
            raise TypeError('{}: Expected datetime, got {}'.format(
                debug_name, type(t)))
        else:
            return t.strftime('%b %d %Y %H:%M:%S')
    return sanitise


Extension = namedtuple('Extension', ('key_name', 'sanitiser'))
ipv4_addr = str_sanitiser(r'\.'.join(['\d{1,3}'] * 4))
ipv6_addr = str_sanitiser(r'\:'.join(['[0-9a-fA-F]{1,4}'] * 8))  # only complete ipv6 address accepted
mac_addr = str_sanitiser(r'\:'.join(['[0-9a-fA-F]{2}'] * 6))
str_31 = str_sanitiser(max_len=31)
str_63 = str_sanitiser(max_len=63)
str_128 = str_sanitiser(max_len=128)
str_255 = str_sanitiser(max_len=255)
str_1023 = str_sanitiser(max_len=1023)

valid_extensions = {
    'applicationProtocol': Extension('app', str_31),
    'baseEventCount': Extension('cnt', int_sanitiser()),
    'bytesIn': Extension('in', int_sanitiser()),
    'bytesOut': Extension('out', int_sanitiser()),
    'destinationAddress': Extension('dst', ipv4_addr),
    'destinationDnsDomain': Extension('destinationDnsDomain', str_255),
    'destinationHostName': Extension('dhost', str_1023),
    'destinationMacAddress': Extension('dmac', mac_addr),
    'destinationNtDomain': Extension('dntdom', str_255),
    'destinationPort': Extension('dpt', int_sanitiser(min=0, max=65535)),
    'destinationProcessId': Extension('dpid', int_sanitiser()),
    'destinationProcessName': Extension('dproc', str_1023),
    'destinationServiceName': Extension('destinationServiceName', str_1023),
    'destinationTranslatedAddress': Extension('destinationTranslatedAddress', ipv4_addr),
    'destinationTranslatedPort': Extension('destinationTranslatedPort', int_sanitiser(min=0, max=65535)),
    'destinationUserId': Extension('duid', str_1023),
    'destinationUserName': Extension('duser', str_1023),
    'destinationUserPrivileges': Extension('dpriv', str_1023),
    'deviceAction': Extension('act', str_63),
    'deviceAddress': Extension('dvc', ipv4_addr),
    'deviceCustomDate1': Extension('deviceCustomDate1', datetime_sanitiser()),
    'deviceCustomDate1Label': Extension('deviceCustomDate1Label', str_1023),
    'deviceCustomDate2': Extension('deviceCustomDate2', datetime_sanitiser()),
    'deviceCustomDate2Label': Extension('deviceCustomDate2Label', str_1023),
    'deviceCustomFloatingPoint1': Extension('cfp1', float_sanitiser()),
    'deviceCustomFloatingPoint1Label': Extension('cfp1Label', str_sanitiser()),
    'deviceCustomFloatingPoint2': Extension('cfp2', float_sanitiser()),
    'deviceCustomFloatingPoint2Label': Extension('cfp2Label', str_sanitiser()),
    'deviceCustomFloatingPoint3': Extension('cfp3', float_sanitiser()),
    'deviceCustomFloatingPoint3Label': Extension('cfp3Label', str_sanitiser()),
    'deviceCustomFloatingPoint4': Extension('cfp4', float_sanitiser()),
    'deviceCustomFloatingPoint4Label': Extension('cfp4Label', str_sanitiser()),
    'deviceCustomIPv6Address1': Extension('c6a1', ipv6_addr),
    'deviceCustomIPv6Address1Label': Extension('c6a1Label', str_1023),
    'deviceCustomIPv6Address3': Extension('c6a3', ipv6_addr),
    'deviceCustomIPv6Address3Label': Extension('c6a3Label', str_1023),
    'deviceCustomIPv6Address4': Extension('c6a4', ipv6_addr),
    'deviceCustomIPv6Address4Label': Extension('c6a4Label', str_1023),
    'deviceCustomNumber1': Extension('cn1', int_sanitiser()),
    'deviceCustomNumber1Label': Extension('cn1Label', str_1023),
    'deviceCustomNumber2': Extension('cn2', int_sanitiser()),
    'deviceCustomNumber2Label': Extension('cn2Label', str_1023),
    'deviceCustomNumber3': Extension('cn3', int_sanitiser()),
    'deviceCustomNumber3Label': Extension('cn3Label', str_1023),
    'deviceCustomString1': Extension('cs1', str_1023),
    'deviceCustomString1Label': Extension('cs1Label', str_1023),
    'deviceCustomString2': Extension('cs2', str_1023),
    'deviceCustomString2Label': Extension('cs2Label', str_1023),
    'deviceCustomString3': Extension('cs3', str_1023),
    'deviceCustomString3Label': Extension('cs3Label', str_1023),
    'deviceCustomString4': Extension('cs4', str_1023),
    'deviceCustomString4Label': Extension('cs4Label', str_1023),
    'deviceCustomString5': Extension('cs5', str_1023),
    'deviceCustomString5Label': Extension('cs5Label', str_1023),
    'deviceCustomString6': Extension('cs6', str_1023),
    'deviceCustomString6Label': Extension('cs6Label', str_1023),
    'deviceDirection': Extension('deviceDirection', int_sanitiser()),
    'deviceDnsDomain': Extension('deviceDnsDomain', str_255),
    'deviceEventCategory': Extension('cat', str_1023),
    'deviceExternalId': Extension('deviceExternalId', str_255),
    'deviceFacility': Extension('deviceFacility', str_1023),
    'deviceHostName': Extension('dvchost', str_sanitiser(max_len=100)),
    'deviceInboundInterface': Extension('deviceInboundInterface', str_128),
    'deviceMacAddress': Extension('dvcmac', mac_addr),
    'deviceNtDomain': Extension('deviceNtDomain', str_255),
    'deviceOutboundInterface': Extension('DeviceOutboundInterface', str_128),
    'devicePayloadId': Extension('DevicePayloadId', str_128),
    'deviceProcessId': Extension('dvcpid', int_sanitiser()),
    'deviceProcessName': Extension('deviceProcessName', str_1023),
    'deviceReceiptTime': Extension('rt', datetime_sanitiser()),
    'deviceTimeZone': Extension('dtz', str_255),
    'deviceTranslatedAddress': Extension('deviceTranslatedAddress', ipv4_addr),
    'endTime': Extension('end', datetime_sanitiser()),
    'eventOutcome': Extension('outcome', str_63),
    'externalID': Extension('externalID', str_sanitiser(max_len=40)),
    'fileCreateTime': Extension('fileCreateTime', datetime_sanitiser()),
    'fileHash': Extension('fileHash', str_255),
    'fileId': Extension('fileId', str_1023),
    'fileModificationTime': Extension('fileModificationTime', datetime_sanitiser()),
    'fileName': Extension('fname', str_1023),
    'filePath': Extension('act', str_63),
    'filePermission': Extension('filePermission', str_1023),
    'fileSize': Extension('fsize', int_sanitiser()),
    'fileType': Extension('fileType', str_1023),
    'flexDate1': Extension('flexDate1', datetime_sanitiser()),
    'flexDate1Label': Extension('flexDate1Label', str_128),
    'flexString1': Extension('flexString1', str_1023),
    'flexString1Label': Extension('flexString1Label', str_128),
    'flexString2': Extension('flexString2', str_1023),
    'flexString2Label': Extension('flexString2Label', str_128),
    'message': Extension('msg', str_1023),
    'oldFileCreateTime': Extension('oldFileCreateTime', datetime_sanitiser()),
    'oldFileHash': Extension('oldFileHash', str_255),
    'oldFIleId': Extension('oldFIleId', str_1023),
    'oldFileModificationTime': Extension('oldFileModificationTime', datetime_sanitiser()),
    'oldFileName': Extension('oldFileName', str_1023),
    'oldFilePath': Extension('oldFilePath', str_1023),
    'oldFilePermission': Extension('oldFilePermission', str_1023),
    'oldFileSize': Extension('oldFileSize', int_sanitiser()),
    'oldFileType': Extension('oldFileType', str_1023),
    'reason': Extension('reason', str_1023),
    'requestClientApplication': Extension('requestClientApplication', str_1023),
    'requestContext': Extension('requestContext', str_sanitiser(max_len=2048)),
    'requestCookies': Extension('requestCookies', str_1023),
    'requestMethod': Extension('requestMethod', str_1023),
    'requestURL': Extension('request', str_1023),
    'sourceAddress': Extension('src', ipv4_addr),
    'sourceDnsDomain': Extension('sourceDnsDomain', str_255),
    'sourceHostName': Extension('shost', str_1023),
    'sourceMacAddress': Extension('smac', mac_addr),
    'sourceNtDomain': Extension('sntdom', str_255),
    'sourcePort': Extension('spt', int_sanitiser(min=0, max=65535)),
    'sourceProcessId': Extension('spid', int_sanitiser()),
    'sourceProcessName': Extension('sproc', str_1023),
    'sourceServiceName': Extension('sourceServiceName', str_1023),
    'sourceTranslatedAddress': Extension('sourceTranslatedAddress', ipv4_addr),
    'sourceTranslatedPort': Extension('sourceTranslatedPort', int_sanitiser(min=0, max=65535)),
    'sourceUserId': Extension('suid', str_1023),
    'sourceUserName': Extension('suser', str_1023),
    'sourceUserPrivileges': Extension('spriv', str_1023),
    'start': Extension('start', datetime_sanitiser()),
    'startTime': Extension('start', datetime_sanitiser()),
    'transportProtocol': Extension('proto', str_31),
    'type': Extension('type', int_sanitiser())
}
