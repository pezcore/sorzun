from setuptools import setup, find_packages
setup(
    name="sorzun",
    version="0.0.1",
    packages=find_packages(),
    include_package_data=True,
    scripts=["bin/szn", "bin/cashaddrconv", "bin/base58"],
)
