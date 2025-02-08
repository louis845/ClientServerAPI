from setuptools import setup, find_packages

setup(
    name='ServerAPI',
    version='0.1.3',
    description='A Python interface creating a simple API server with login mechanisms.',
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