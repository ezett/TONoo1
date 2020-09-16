from setuptools import (
    setup,
    find_packages,
)


def readme():
    with open('README.rst', "r", encoding="UTF-8") as f:
        return f.read()


setup(
    name='TONoo1',
    version='0.0.1',
    description='1-out-of-N Oblivious Transfer implementation',
    long_description=readme(),
    keywords='1-out-of-N Oblivious Transfer',
    author='ezett',
    url='https://github.com/ezett/TONoo1',
    packages=find_packages(),
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Topic :: Security :: Cryptography',
    ],
    install_requires=[
        'pynacl',
    ],
)
