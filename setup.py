#!/usr/bin/env python
import os

from setuptools import setup


def readhere(path):
    here = os.path.abspath(os.path.dirname(__file__))
    with open(os.path.join(here, path), 'r') as fd:
        return fd.read()


def readreqs(path):
    return [req for req in
            [line.strip() for line in readhere(path).split('\n')]
            if req and not req.startswith(('#', '-r'))]


version = readhere('VERSION').strip()
install_requires = readreqs('requirements.txt')
tests_require = install_requires + readreqs('test-requirements.txt')


if __name__ == '__main__':
    setup(
        name='pmipt',
        version=version,
        description='Partially Managed IPTables',
        long_description='Manage a subset of IPTables rules',
        url='https://github.com/SurveyMonkey/pmipt.git',
        author='SurveyMonkey Inc.',
        author_email='api-admin@surveymonkey.com',
        py_modules=['pmipt'],
        install_requires=install_requires,
        tests_require=tests_require,
        entry_points={
            'console_scripts': [
                'pmipt-changes = pmipt:main',
            ],
        },
        scripts=['pmipt-apply'],
    )
