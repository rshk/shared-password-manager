from setuptools import setup, find_packages

version = '0.1a'
install_requires = [
    'pygpgme',  # For pubkey encryption via GPG
    'pycrypto',  # For symmetric crypto via AES
    'cliff',  # For the CLI
]

dependency_links = [
    'https://github.com/rshk/pygpgme/tarball/master#egg=pygpgme-0.3.1',
]

entry_points = {
    'console_scripts': [
        'password_manager = password_manager.cli:main'
    ],
    'password_manager.cli': [
        'setup = password_manager.cli.commands:Setup',

        'user_add = password_manager.cli.commands:UserAdd',
        'user_remove = password_manager.cli.commands:UserRemove',
        'user_list = password_manager.cli.commands:UserList',

        'key_regen = password_manager.cli.commands:KeyRegen',
        'key_recrypt = password_manager.cli.commands:KeyRecrypt',

        'secret_put = password_manager.cli.commands:SecretPut',
        'secret_get = password_manager.cli.commands:SecretGet',
        'secret_delete = password_manager.cli.commands:SecretDelete',
    ],
}

setup(
    name='PasswordManager',
    version=version,
    packages=find_packages(),
    url='',
    license='Apache Software License',
    author='Samuele Santi',
    author_email='samuele@samuelesanti.com',
    description='Directory based, multi-user, password manager',
    long_description='',
    install_requires=install_requires,
    dependency_links=dependency_links,
    # test_suite='tests',
    classifiers=[
        "License :: OSI Approved :: Apache Software License",

        "Development Status :: 1 - Planning",
        # "Development Status :: 2 - Pre-Alpha",
        # "Development Status :: 3 - Alpha",
        # "Development Status :: 4 - Beta",
        # "Development Status :: 5 - Production/Stable",
        # "Development Status :: 6 - Mature",
        # "Development Status :: 7 - Inactive",

        ## Support for python 3 is planned, but not tested yet
        "Programming Language :: Python :: 2",
        # "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        # "Programming Language :: Python :: 3.1",
        # "Programming Language :: Python :: 3.2",
        # "Programming Language :: Python :: 3.3",
        # "Programming Language :: Python :: 3.4",

        ## Should work on all implementations, but further
        ## testing is still needed..
        "Programming Language :: Python :: Implementation :: CPython",
        # "Programming Language :: Python :: Implementation :: PyPy",
    ],
    package_data={'': ['README.md', 'LICENSE']},
    zip_safe=False,
    entry_points=entry_points)
