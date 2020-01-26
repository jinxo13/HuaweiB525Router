import os
import re
from setuptools import find_packages, setup


READMEFILE = "README.md"
VERSIONFILE = os.path.join("huawei_lte", "_version.py")
VSRE = r"^__version__ = ['\"]([^'\"]*)['\"]"


def get_version():
    verstrline = open(VERSIONFILE, "rt").read()
    mo = re.search(VSRE, verstrline, re.M)
    if mo:
        return mo.group(1)
    else:
        raise RuntimeError(
            "Unable to find version string in %s." % VERSIONFILE)


setup(
    name='huawei_lte',
    version=get_version(),
    description='Huawei LTE API',
    long_description=open(READMEFILE).read(),
    url='https://github.com/jinxo13/HuaweiB525Router',
    author='Hamish McNeish',
    license='BSD',
    packages=find_packages(),
    install_requires=[
        'huawei_lte>=1.0.0',
        'pycrypto>=2.6.1',
        'IPy>=1.0.0'
    ],
    include_package_data=True,
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Natural Language :: English',
        ],
)
