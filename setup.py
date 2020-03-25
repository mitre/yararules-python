from setuptools import setup

setup(
    name='yararules',
    version='0.1.1',
    py_modules=['yararules'],
    scripts=['bin/yara-multi-rules.py'],
    install_requires=[
        'yara-python',
    ],
)
