# coding: utf-8
from distutils.core import setup

import mellophone

with open('README.md', encoding='utf8') as file:
    long_description = file.read()

setup(
    name='mellophone-valve',
    version=mellophone.__version__,
    py_modules=['mellophone'],
    url='https://github.com/CourseOrchestra/mellophone-valve',
    license='MIT',
    author='Maria Prudyvus',
    author_email='maria.prudyvus@curs.ru',
    description='Python mellophone requests wrapper ',
    long_description=long_description,
    install_requires=[
        'requests',
        'xmltodict'
    ],
)
