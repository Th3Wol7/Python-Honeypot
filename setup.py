"""
@author: TYrien Gilpin
@description: This file contains the setup configurations of the
              honey pot upon execution of the code
"""
from setuptools import setup


def readme_file_contents():
    with open('README.rst') as readMeFile:
        data = readMeFile.read()
    return data


setup(
    name='cshoneypot',
    version='1.0.0',
    description='CIT4020 HoneyPot Lab Project',
    long_description=readme_file_contents(),  # making long description of the project be the entire readme file
    author='Tyrien Gilpin',
    author_email='N/A',
    liscense='MIT',
    packages=['honeypot'],
    zipSafe=False,
    installRequire=[]
)