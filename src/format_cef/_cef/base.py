from __future__ import absolute_import

import collections
import csv
import datetime as dt
import re

from . import compat

try:
    from importlib import resources as importlib_resources
except ImportError:
    import importlib_resources


def format_cef(
    vendor, product, product_version, event_id, event_name, severity, extensions
):
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
        valid_extensions[name].key_name: _equals_escaper(
            valid_extensions[name].sanitiser(value, name)
        )
        for name, value in extensions.items()
    }
    extensions_str = " ".join(
        sorted("{}={}".format(k, v) for k, v in extension_strs.items())
    )
    pfs = _prefix_field_str_sanitiser
    return "|".join(
        (
            "CEF:0",
            pfs(vendor, "VENDOR"),
            pfs(product, "PRODUCT"),
            pfs(product_version, "VERSION"),
            pfs(event_id, "EVENT_ID"),
            pfs(event_name, "EVENT_NAME"),
            _severity_sanitiser(severity, "SEVERITY"),
            extensions_str,
        )
    )


def escaper(special_chars):
    strip_escaped_re = re.compile(r"\\([{}\\])".format(special_chars))
    do_escape_re = re.compile(r"([{}\\])".format(special_chars))

    def escape(s):
        stripped = strip_escaped_re.sub(r"\1", s)
        return do_escape_re.sub(r"\\\1", stripped)

    return escape


def ensure_in_range(debug_name, min, max, num):
    if max is None:
        if min is not None and num < min:
            raise ValueError("{}: {} less than {}".format(debug_name, num, min))
    elif min is None:
        if max is not None and num > max:
            raise ValueError("{}: {} greater than {}".format(debug_name, num, max))
    elif not min <= num <= max:
        raise ValueError("{}: {} out of range {}-{}".format(debug_name, num, min, max))


def int_sanitiser(max=None, min=None):
    def sanitise(n, debug_name):
        if not isinstance(n, int):
            raise TypeError("{}: Expected int, got {}".format(debug_name, type(n)))
        ensure_in_range(debug_name, min, max, n)
        return str(n)

    return sanitise


_severity_sanitiser = int_sanitiser(min=0, max=10)


def float_sanitiser():
    def sanitise(n, debug_name):
        if not isinstance(n, float):
            raise TypeError("{}: Expected float, got {}".format(debug_name, type(n)))
        else:
            return str(n)

    return sanitise


def str_sanitiser(regex_str=".*", escape_chars="", min_len=0, max_len=None):
    regex = re.compile("^{}$".format(regex_str))
    escape = escaper(escape_chars)

    def sanitise(s, debug_name):
        if not isinstance(s, basestring):
            raise TypeError("{}: Expected str, got {}".format(debug_name, type(s)))
        elif not regex.match(s):
            raise ValueError(
                "{}: {!r} did not match regex {!r}".format(debug_name, s, regex_str)
            )
        else:
            if isinstance(s, unicode):
                s = s.encode("utf-8")
            s = escape(s)
            if max_len is None:
                if len(s) < min_len:
                    raise ValueError(
                        "{}: String shorter than {} characters".format(
                            debug_name, min_len
                        )
                    )
            else:
                if not min_len <= len(s) <= max_len:
                    raise ValueError(
                        "{}: String length out of range {}-{}".format(
                            debug_name, min_len, max_len
                        )
                    )
            return s

    return sanitise


_prefix_field_str_sanitiser = str_sanitiser("[^\r\n]*", escape_chars="|")
_equals_escaper = escaper("=")


def datetime_sanitiser():
    def sanitise(t, debug_name):
        if not isinstance(t, dt.datetime):
            raise TypeError("{}: Expected datetime, got {}".format(debug_name, type(t)))
        else:
            return t.strftime("%b %d %Y %H:%M:%S")

    return sanitise


Extension = collections.namedtuple("Extension", ("key_name", "sanitiser"))


def _valid_extensions():
    ipv4_addr = str_sanitiser(r"\.".join([r"\d{1,3}"] * 4))
    ipv6_addr = str_sanitiser(
        r"\:".join(["[0-9a-fA-F]{1,4}"] * 8)
    )  # only complete ipv6 address accepted
    mac_addr = str_sanitiser(r"\:".join(["[0-9a-fA-F]{2}"] * 6))
    str_lens = [31, 40, 63, 100, 128, 255, 1023, 2048]
    sanitisers = {
        "IPv4 Address": {"": ipv4_addr},
        "IPv6 address": {"": ipv6_addr},
        "MAC Address": {"": mac_addr},
        "Time Stamp": {"": datetime_sanitiser()},
        "Floating Point": {"": float_sanitiser()},
        "Integer": {"": int_sanitiser(), "65535": int_sanitiser(min=0, max=65535)},
        "String": dict(
            [("", str_sanitiser())]
            + [(str(str_len), str_sanitiser(max_len=str_len)) for str_len in str_lens]
        ),
    }

    with importlib_resources.open_text(
        compat.pkgname(globals()), "valid_extensions.csv", encoding="ascii"
    ) as csv_f:
        return {
            record["Full Name"]: Extension(
                key_name=record["CEF Key Name"],
                sanitiser=sanitisers[record["Data Type"]][record["Length"]],
            )
            for record in csv.DictReader(csv_f, strict=True)
        }


valid_extensions = _valid_extensions()
