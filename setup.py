# Always prefer setuptools over distutils
from setuptools import setup, find_packages
# To use a consistent encoding
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='birch_girder',
    version='1.0.0',
    description='An Email Interface for GitHub Issues',
    long_description=long_description,
    url='https://github.com/gene1wood/birch-girder',
    author='Gene Wood',
    author_email='gene_wood@cementhorizon.com',
    license='GPL-3.0',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: System Administrators',
        'Topic :: Software Development :: Bug Tracking',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
    ],
    keywords='aws lambda github issue ses',
    packages=find_packages(exclude=['contrib', 'docs', 'tests']),
    install_requires=[
        'boto3',
        'botocore>1.8.8',
        'agithub',
        'PyYAML',
        'python-dateutil',
        'email_reply_parser',
        'pyzmail',
        'beautifulsoup4'],
    extras_require={
        "deploy":  ["pynacl", "boto3", "PyYAML", "agithub"]
    },
    entry_points={
        "console_scripts": [
            "deploy-birch-girder = birch_girder.deploy:main"
        ]
    }
)
