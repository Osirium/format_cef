from setuptools import setup, find_packages

with open("README.md") as f:
    long_description = f.read()

setup(
    name="format_cef",
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
    packages=find_packages('src'),
    package_dir={'':'src'},
)
