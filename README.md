format_cef
==========

[![Build Status](https://travis-ci.org/ch3pjw/format_cef.svg?branch=master)](
https://travis-ci.org/ch3pjw/format_cef)

`format_cef` is a little helper library for producing [ArcSight Common Event
Format (CEF)][CEF] compliant messages from structured arguments. You can use it
like this:

```python
>>> from format_cef import format_cef
>>> format_cef(
    'acme corp', 'TNT', 1.0, '404 | not found', 'Explosives not found', 10
    oextensions={'deviceAction': 'bang = !'})
'CEF:0|acme corp|TNT|1.0|404 \| not found|Explosives not found|10|act=bang \= !'
```

Notice how the format `format_cef` takes care of escaping deimiters correctly.
It will also ensure that each CEF extension complies to the restrictions
outlined in the [CEF documentation][CEF].

This module deliberately remains agnostic as to the log message transport
protocol (as does CEF itself). It is also designed to remain stateless so as to
easy to test and use as a building block in larger systems.

Currently, the library only implements a subset of the permissable CEF
extensions that were personally useful. I'm very happy to take PRs to extend
coverage to the fully valid CEF extension set.

[CEF]: https://community.saas.hpe.com/t5/ArcSight-Connectors/ArcSight-Common-Event-Format-CEF-Guide/ta-p/1589306


Licence
-------

`format_cef` is free software: you can redistribute it and/or modify it under the
terms of the GNU Lesser General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

`format_cef` is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License along
with `format_cef`.  If not, see <http://www.gnu.org/licenses/>.
