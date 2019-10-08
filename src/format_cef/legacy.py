import warnings

from ._cef import base as _base


class LegacyCefWarning(Warning):
    pass


ignore_warning_format_cef = _base.LegacyCefFormatter().format_cef


def format_cef(*args, **kwargs):
    def _modern_cef():
        try:
            return (None, None, _base.format_cef(*args, **kwargs))
        except _base.FormatCefError as e:
            return (type(e), e.args, None)

    def _legacy_cef():
        try:
            return (None, None, ignore_warning_format_cef(*args, **kwargs), None)
        except _base.FormatCefError as e:
            return (type(e), e.args, None, e)

    cef_result = _legacy_cef()
    if cef_result[:3] != _modern_cef():
        warnings.warn(
            "{!r} would behave differently on format_cef.format_cef".format(
                (args, kwargs)
            ),
            LegacyCefWarning,
        )
    _e_type, _e_args, value, error = cef_result
    if error is None:
        return value
    raise error
