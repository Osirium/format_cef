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

Notice how the format `format_cef` takes care of escaping delimiters correctly.
It will also ensure that each CEF extension complies to the restrictions
outlined in the [CEF documentation][CEF].

This module deliberately remains agnostic as to the log message transport
protocol (as does CEF itself). It is also designed to remain stateless so as to
easy to test and use as a building block in larger systems.

[CEF]: https://web.archive.org/web/20191001144632/https://community.microfocus.com/dcvta86296/attachments/dcvta86296/connector-documentation/1197/2/CommonEventFormatV25.pdf
