from setuptools import setup

setup(
    name='format_cef',
    version='0.0',
    decsription=(
        'A small helper for formatting ArcSight Common Event Format (CEF) '
        'compliant messages'),
    url='http://github.com/ch3pjw/format_cef',
    author='Paul Weaver',
    author_email='paul@ruthorn.co.uk',
    packages=['format_cef'],
    install_required=[],
    tests_require=['pytest'],
    test_suite='pytest')
