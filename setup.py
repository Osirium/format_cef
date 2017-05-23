from setuptools import setup

setup(
    name='format_cef',
    packages=['format_cef'],
    decsription=(
        'A small helper for formatting ArcSight Common Event Format (CEF) '
        'compliant messages'),
    keywords=['cef', 'logging'],
    url='http://github.com/ch3pjw/format_cef',
    author='Paul Weaver',
    author_email='paul@ruthorn.co.uk',
    version='0.0.1',
    license='LGPL v3.0',
    install_requires=[],
    tests_require=['pytest'],
    test_suite='pytest')
