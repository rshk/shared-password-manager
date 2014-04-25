#!/usr/bin/env python

"""
Password manager script.

Stores passwords in a directory structure like this:

```
|-- users
|   '-- <userid>                For each user..
|       |-- userinfo.json       Information about the user
|       |-- gpg-key.pub         User's public GPG key
|       '-- secret.key          Symmetric key encrypted with user's gpg key
'-- passwords
    |-- account-1               JSON files containing secret data
    |-- account-2
    '-- account-3
```

In the user configuration, we want to associate a user identity with a
GPG key, by id. Keys are shipped with the repository, but this is not
mandatory, as they might already be in user's GPG keyring, or they
can be received from a keyserver.

We'd also need to allow for some extra configuration, such as current
user's default identity, etc..

"""

import json
import os

from Crypto.Cipher import AES
from Crypto import Random

import gnupg


# ----------------------------------------------------------------------
# Library
# ----------------------------------------------------------------------


class PasswordManager(object):
    def __init__(self, basedir, identity=None):
        self.basedir = basedir
        self.identity = identity

    def initialize(self, identity, gpgkey):
        if not os.path.exists(self.basedir):
            os.makedirs(self.basedir)
        if len(os.listdir(self.basedir)) > 0:
            raise RuntimeError("Directory not empty -- refusing to proceed")

        os.makedirs(os.path.join(self.basedir, 'users'))
        os.makedirs(os.path.join(self.basedir, 'passwords'))

        # Now generate a key to be used for encryption and store
        # encrypted for this user.
        aes_key = Random.new().read(32)

        # Create user information file
        userdir = os.path.join(self.basedir, 'users', identity)
        infofile = os.path.join(userdir, 'userinfo.json')
        with open(infofile, 'w') as f:
            json.dump({
                'name': identity,
                'gpg_key': gpgkey,
            }, f)

        # Now encrypt the key and store in the user directory
        aes_key_file = os.path.join(userdir, 'secret.key')
        gpg = gnupg.GPG()
        enc_key = str(gpg.encrypt(aes_key, gpgkey))
        with open(aes_key_file, 'w') as f:
            f.write(enc_key)

        # Finally, store user's public key
        gpg_pubkey_file = os.path.join(userdir, 'gpg-key.pub')
        with open(gpg_pubkey_file, 'w') as f:
            f.write(gpg.export_keys(gpgkey))

    def create_user(self, identity, gpgkey):
        """
        Create a new user identity, with its own version
        of the encrypted password.
        """
        # Create user information file
        userdir = os.path.join(self.basedir, 'users', identity)
        infofile = os.path.join(userdir, 'userinfo.json')
        with open(infofile, 'w') as f:
            json.dump({
                'name': identity,
                'gpg_key': gpgkey,
            }, f)

        # Now encrypt the key and store in the user directory
        aes_key = self.get_aes_key()
        aes_key_file = os.path.join(userdir, 'secret.key')
        gpg = gnupg.GPG()
        enc_key = str(gpg.encrypt(aes_key, gpgkey))
        with open(aes_key_file, 'w') as f:
            f.write(enc_key)

        # Finally, store user's public key
        gpg_pubkey_file = os.path.join(userdir, 'gpg-key.pub')
        with open(gpg_pubkey_file, 'w') as f:
            f.write(gpg.export_keys(gpgkey))

    def get_identity(self, name):
        """
        Get information about a user's identity, i.e. load
        the user's json file.

        User's json file contains at least the following information:

        - ``gpg_key`` -- fingerprint of users's gpg key
        """
        userdir = os.path.join(self.basedir, 'users', name)
        infofile = os.path.join(userdir, 'userinfo.json')
        with open(infofile, 'r') as f:
            return json.load(f)

    def get_aes_key(self):
        """
        To get the AES key, to be used to encrypt/decrypt json
        files, we need to figure out which is the key encrypted with
        a secret key we have, then decrypt it.
        """
        pass

    def encrypt_data(self, data):
        key = self.get_aes_key()
        pass

    def decrypt_data(self, data):
        key = self.get_aes_key()
        pass


# ----------------------------------------------------------------------
# Commands
# ----------------------------------------------------------------------
