format_cef
==========

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

[CEF]: https://www.protect724.hpe.com/servlet/JiveServlet/downloadBody/1072-102-9-20354/CommonEventFormatv23.pdf
