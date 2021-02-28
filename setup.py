import os
from setuptools import setup

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "buffered_encryption",
    version = "0.1.1",
    author = "Elliott Blocha",
    description = "Encrypt large files without loading the entire file into memory.",
    license = "MIT",
    keywords = "cryptography, big, large, encryption",
    packages=['buffered_encryption'],
    long_description=read('README.md'),
    long_description_content_type="text/markdown",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Topic :: Utilities",
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3 :: Only',
    ],
    install_requires=["cryptography"],
     python_requires='>=3.6, <4',
)