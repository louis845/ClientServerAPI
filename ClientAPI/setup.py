from setuptools import setup, find_packages

setup(
    name='ClientAPI',
    version='0.2.1',
    description='A Python interface creating a simple API client with login mechanisms.',
    author='Louis, Chau Yu Hei',
    author_email='louis321yh@gmail.com',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    install_requires=[
    ],
    entry_points={
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'Operating System :: Unix',
    ],
)