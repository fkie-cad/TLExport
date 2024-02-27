import os
from setuptools import setup, find_packages
from os.path import abspath, dirname, join

from tlexport.__init__ import __version__
from tlexport.__init__ import __author__

# Fetches the content from README.md
# This will be used for the "long_description" field.
README_MD = open(join(dirname(abspath(__file__)), "README.md")).read()

# here - where we are.
here = os.path.abspath(os.path.dirname(__file__))

# read the package requirements for install_requires
with open(os.path.join(here, 'requirements.txt'), 'r') as f:
    requirements = f.readlines()




setup(
    # pip install tlexport
    name="TLExport",
    version=__version__,

    # The description that will be shown on PyPI.
    description="TLExport (TLE) is a tool for decrypting TLS-Traffic and exporting the traffic into unencrypted TCP/UDP traffic",

    # The content that will be shown on your project page.
    # In this case, we're displaying whatever is there in our README.md file
    long_description=README_MD,

    # Now, we'll tell PyPI what language our README file is in.
    long_description_content_type="text/markdown",


    url="https://github.com/fkie-cad/TLExport/",

    author_name=__author__,
    author_email="daniel.baier@fkie.fraunhofer.de",
    license='GPL v3',

     # include other files
     #package_data={
     #   '': [ os.path.join(here, 'TBD') # the frida agent to do the actual hooking
     #    ],  
     # },



    include_package_data=True,
    python_requires='>=3.10',
    packages=find_packages(),
    install_requires=requirements,


    classifiers=[
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Natural Language :: English",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: JavaScript",
        "Topic :: Security"
    ],

    # Keywords are tags that identify your project and help searching for it
    # This field is OPTIONAL
    keywords=["tls", "decryption", "network forensik", "pcap", "pcapng"],

    entry_points={
            'console_scripts': [
            'tlexport=tlexport.main:run',
        ],
    },
)
