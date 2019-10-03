from __future__ import absolute_import


def pkgname(globals):
    """
    Return the package name of a module.
    https://github.com/benjaminp/six/pull/301/files

    On Python 2 under __future__.absolute_import __package__ is None until an
    explcit relative import is attempted.
    compat.pgkname(globals()) is equivalent to __package__ on Python 3.
    """
    pkgname_ = globals.get("__package__")
    if pkgname_ is not None:
        return pkgname_
    modname = globals.get("__name__")
    return modname if "__path__" in globals else modname.rpartition(".")[0]
