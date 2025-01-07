from setuptools import setup, find_packages

setup(
    name='EnigPy',
    version='0.1.6',    
    description='',
    long_description=open('README.md').read(),
    url='https://github.com/atticus-zhang/EnigPy/tree/main/EnigPy',
    author='Atticus Zhang',
    author_email='ay9zhang@uwaterloo.ca',
    license='MIT',
    packages=find_packages(),  # Automatically discover packages
    package_data={
        'EnigPy': ['source/*'],  # This will include all files in the 'source' directory
    },
    keywords=['Python', 'Cryptography'],
    install_requires=[],
    classifiers=[
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: MIT License",
        "Development Status :: 5 - Production/Stable",
        "Operating System :: OS Independent",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "Natural Language :: English",
        "Programming Language :: Python :: 3",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ]
)
