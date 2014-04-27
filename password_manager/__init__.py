"""
Password manager.

Manages encrypted passwords in a directory, using GPG + AES
to encrypt them for multiple users.
"""

import json
import os
from io import BytesIO

# import gnupg
import gpgme
from Crypto.Cipher import AES
from Crypto import Random

# Keep in sync with setup.py
__version__ = '0.1a'


class PasswordManagerException(Exception):
    pass


class PasswordManager(object):
    def __init__(self, basedir, gpghome=None):
        self.basedir = basedir
        self.gpghome = gpghome

    @property
    def keydir(self):
        return os.path.join(self.basedir, '.keys')

    @property
    def gpg(self):
        # todo: cache on a per-gpghome basis?
        return self._get_gpg()

    def setup(self, identities):
        """
        Prepare the configured directory for use by the password
        manager.

        :param identities:
            fingerprints of the keys of the initial users for which
            we want to encrypt the AES key.
        """

        identities = [self.get_key_fingerprint(x) for x in identities]

        if os.path.exists(self.basedir) and len(os.listdir(self.basedir)) > 0:
            raise ValueError("Destination directory not empty")

        os.makedirs(self.keydir)

        aes_key = self.generate_aes_key()

        for identity in identities:
            self.write_aes_key(aes_key, identity)
            self.store_gpg_pubkey(identity)

        # Just to try things, let's create a new encrypted file..
        hello = {'username': 'Hello', 'password': 'Word'}
        self.write_secret('example', hello)
        assert self.read_secret('example') == hello

    # ----------------------------------------------------------------------
    #   Identity management

    def add_identity(self, identity):
        """
        Create a new user.

        - copy its public key in the ``.keys`` directory
        - encrypt the AES key using the selected public key
        """

        # Note: if we are adding another user for which we have
        #       a private key, we risk trying to decrypt it with
        #       the wrong key!

        identity = self.get_key_fingerprint(identity)
        aes_key = self.get_aes_key()
        self.write_aes_key(aes_key, identity)
        self.store_gpg_pubkey(identity)

    def list_identities(self):
        """List GPG fingerprints for the configured users"""

        for name in os.listdir(self.keydir):
            if name.startswith('.'):
                continue
            if name.endswith('.pub'):
                yield name[:-4]

    def remove_identity(self, identity):
        identity = self.get_key_fingerprint(identity)
        os.unlink(self.get_aes_key_filename(identity))
        os.unlink(self.get_gpg_pubkey_filename(identity))
        self.regenerate_aes_key()

    # ----------------------------------------------------------------------
    #   Symmetric encryption operations

    def get_aes_key(self, identity=None):
        """Get the AES key, decrypted using GPG"""

        if identity is None:
            # Figure out one key we own..
            # todo: we might also want to try *all* our keys..?
            our_keys = set(self.list_gpg_privkeys())
            user_keys = set(self.list_identities())
            common_keys = our_keys.intersection(user_keys)
            if len(common_keys) < 1:
                raise PasswordManagerException(
                    "Unable to find a key for decryption!")
            identity = common_keys.pop()

        return self.read_aes_key(identity)

    def generate_aes_key(self, keysize=32):
        """Generate a new random AES key"""

        return Random.new().read(keysize)

    def read_aes_key(self, identity):
        """Read the AES key, using the selected identity"""

        _io = BytesIO()
        gpg = self._get_gpg()
        with open(self.get_aes_key_filename(identity), 'rb') as fp:
            gpg.decrypt(fp, _io)
        return _io.getvalue()

    def write_aes_key(self, aes_key, identity):
        """Store the AES key, encrypted for a given identity"""

        gpg = self._get_gpg()
        key = gpg.get_key(identity)

        # todo: tell the user to trust more people!
        flags = gpgme.ENCRYPT_ALWAYS_TRUST

        with open(self.get_aes_key_filename(identity), 'wb') as fp:
            gpg.encrypt([key], flags, BytesIO(aes_key), fp)

    def regenerate_aes_key(self):
        """
        Generate a new AES key.

        - update encrypted key for all the configured pubkeys
        - decrypt all entries with the old key, recrypt with the new one

        .. warning::

            The old key is kept in memory during the process,
            if something goes wrong in the meanwhile, there is a high
            risk password entries would be corrupted.

            But we assume the directory is under version control,
            so you can just revert the changes and restart..
        """

        old_aes_key = self.get_aes_key()
        new_aes_key = self.generate_aes_key()

        for identity in self.list_identities():
            self.write_aes_key(new_aes_key, identity)

        for secret in self.list_secrets():
            secret_data = self.read_secret(secret, key=old_aes_key)
            self.write_secret(secret, secret_data, key=new_aes_key)

        # todo: now iterate all the password files and recrypt them

    def aes_encrypt(self, data, key=None):
        if isinstance(data, unicode):
            data = data.encode('utf-8')
        if key is None:
            key = self.get_aes_key()
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CFB, iv)
        return iv + cipher.encrypt(data)

    def aes_decrypt(self, data, key=None):
        if key is None:
            key = self.get_aes_key()
        enc_iv = data[:AES.block_size]
        enc_msg = data[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CFB, enc_iv)
        return cipher.decrypt(enc_msg)

    # ----------------------------------------------------------------------
    #   Asymmetric (GPG) encryption handling..

    def _get_gpg(self):
        """
        Get a gpgme Context instance, with correct gnupghome set
        """

        ctx = gpgme.Context()
        if self.gpghome is not None:
            ctx.set_engine_info(gpgme.PROTOCOL_OpenPGP, None, self.gpghome)
        return ctx

    def get_key_fingerprint(self, name):
        """
        Get the fingerprint for a given key.

        :param name: either key fingerprint, id, or identity name
        """

        gpg = self._get_gpg()
        key = gpg.get_key(name)
        # Return fingerprint of the first (main) sub-key
        return key.subkeys[0].fpr

    def list_gpg_privkeys(self):
        """List fingerprints of our private GPG keys"""

        for key in self._get_gpg().keylist('', True):
            yield key.subkeys[0].fpr

    def list_gpg_pubkeys(self):
        """List fingerprints of public keys in our keyring"""

        for key in self._get_gpg().keylist():
            yield key.subkeys[0].fpr

    def store_gpg_pubkey(self, identity):
        """Export a GPG public key"""

        identity = self.get_key_fingerprint(identity)
        gpg = self._get_gpg()
        with open(self.get_gpg_pubkey_filename(identity), 'wb') as fp:
            gpg.export(identity, fp)

    def import_all_pubkeys(self):
        # todo: do this in a better way!
        gpg = self._get_gpg()
        for identity in self.list_identities():
            pubkeyfile = self.get_gpg_pubkey_filename(identity)
            with open(pubkeyfile, 'rb') as fp:
                gpg.import_(fp)

    # ----------------------------------------------------------------------
    #   High-level operations

    def read_secret(self, name, key=None):
        name = self.get_secret_filename(name)
        with open(name, 'rb') as f:
            raw_secret = self.aes_decrypt(f.read(), key=key)
        return raw_secret

    def write_secret(self, name, secret, key=None):
        name = self.get_secret_filename(name)
        with open(name, 'wb') as f:
            f.write(self.aes_encrypt(secret, key=key))

    def delete_secret(self, name):
        name = self.get_secret_filename(name)
        os.unlink(name)

    def list_secrets(self):
        """Find all the files containing secrets"""

        # todo: yield paths relative to the root?
        for dirpath, dirnames, filenames in os.walk(self.basedir):
            dirnames[:] = [x for x in dirnames if not x.startswith('.')]
            for filename in filenames:
                if self._is_secret_file(filename):
                    yield os.path.join(dirpath, filename)

    # ----------------------------------------------------------------------
    #   Utility functions

    def _is_secret_file(self, name):
        if name.startswith('.'):
            return False
        if name.endswith('~'):
            return False
        return True

    def get_secret_filename(self, name):
        return os.path.join(self.basedir, name)

    def get_aes_key_filename(self, identity):
        return os.path.join(self.keydir, '{0}.key'.format(identity))

    def get_gpg_pubkey_filename(self, identity):
        return os.path.join(self.keydir, '{0}.pub'.format(identity))
