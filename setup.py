from setuptools import setup

setup(
    name='yararules',
    version='0.3.0',
    py_modules=['yararules'],
    scripts=['bin/yara-multi-rules.py'],
    install_requires=[
        'yara-python>=4.3.0',
        'python-magic',
    ],
)
