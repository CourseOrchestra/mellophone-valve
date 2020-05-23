# coding: utf-8
from distutils.core import setup


with open('README.md', encoding='utf8') as file:
    long_description = file.read()

setup(
    name='mellophone-valve',
    version='1.0',
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
