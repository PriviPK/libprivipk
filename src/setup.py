import os
from setuptools import setup


# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name="PriviPK",
    version="0.0.1",
    author="Johnny C. Encrypt",
    author_email="johnny.can.encrypt@gmail.com",
    description=("An end-to-end public-key encryption library designed for" +
                 " email security."),
    license="GPLv2",
    keywords="crypto encryption public-key certificateless",
    url="http://packages.python.org/privipk",
    packages=['privipk'],
    long_description=read('README'),
    classifiers=[
        "Development Status :: 1 - Planning",
        "Topic :: Utilities",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "Operating System :: POSIX :: Linux"
        "Programming Language :: Python :: 2.7",
        "Topic :: Communications :: Email",
        "Topic :: Internet",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries"
    ],
)
