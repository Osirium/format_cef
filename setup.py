from os import path
import io

from setuptools import setup

this_directory = path.abspath(path.dirname(__file__))
with io.open(path.join(this_directory, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="format_cef",
    packages=["format_cef"],
    description=(
        "A small helper for formatting ArcSight Common Event Format (CEF) "
        "compliant messages"
    ),
    keywords=["cef", "logging"],
    url="https://github.com/Osirium/format_cef",
    version="0.0.3-post1",
    install_requires=[],
    long_description=long_description,
    long_description_content_type="text/markdown",
)
