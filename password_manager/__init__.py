"""
Password manager.

Manages encrypted passwords in a directory, using GPG + AES
to encrypt them for multiple users.
"""

import json
import os

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

    def setup(self, identities):
        """
        Prepare the configured directory for use by the password
        manager.

        :param identities:
            fingerprints of the keys of the initial users for which
            we want to encrypt the AES key.
        """

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

        self.store_gpg_pubkey(identity)
        aes_key = self.get_aes_key()
        self.write_aes_key(aes_key, identity)

    def delete_identity(self, identity):
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

        with open(self.get_aes_key_filename(identity), 'rb') as f:
            data = f.read()

        # Decrypt and return
        gpg = self.get_gpg()
        return gpg.decrypt(data).data

    def write_aes_key(self, aes_key, identity):
        """Store the AES key, encrypted for a given identity"""

        gpg = self.get_gpg()

        # todo: using ``always_trust`` here is sub-optimal!
        #       find some better way (tell the user how to change
        #       trust, ..)
        encrypted = gpg.encrypt(aes_key, identity, always_trust=True)

        with open(self.get_aes_key_filename(identity), 'wb') as f:
            f.write(encrypted.data)

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

    def list_identities(self):
        """List GPG fingerprints for the configured users"""

        for name in os.listdir(os.path.join(self.basedir, '.keys')):
            if name.startswith('.'):
                continue
            if name.endswith('.pub'):
                yield name[:-4]

    # ----------------------------------------------------------------------
    #   Asymmetric (GPG) encryption handling..

    def _get_gpg(self):
        """
        Get a gpgme Context instance, with correct gnupghome set
        """

        ctx = gpgme.Context()
        if self.gnupghome is not None:
            ctx.set_engine_info(gpgme.PROTOCOL_OpenPGP, None, self.gnupghome)
        return ctx

    def _get_key_fingerprint(self, name):
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

        identity = self._get_key_fingerprint(identity)

        gpg = self.get_gpg()
        exported = gpg.export_keys(identity)
        with open(self.get_gpg_pubkey_filename(identity), 'wb') as f:
            f.write(exported)

    def import_all_pubkeys(self):
        # todo: do this in a better way
        gpg = self._get_gpg()
        for identity in self.list_identities():
            pubkeyfile = self.get_gpg_pubkey_filename(identity)
            with open(pubkeyfile, 'rb') as f:
                gpg.import_(f.read())

    # ----------------------------------------------------------------------
    #   High-level operations

    def read_secret(self, name, key=None):
        name = self._fix_secret_name(name)
        with open(name, 'rb') as f:
            raw_secret = self.aes_decrypt(f.read(), key=key)
        return json.loads(raw_secret)

    def write_secret(self, name, secret, key=None):
        name = self._fix_secret_name(name)
        secret_data = json.dumps(secret)
        with open(name, 'wb') as f:
            f.write(self.aes_encrypt(secret_data, key=key))

    def list_secrets(self):
        """Find all the files containing secrets"""

        # todo: yield paths relative to the root?
        for dirpath, dirnames, filenames in os.walk(self.basedir):
            dirnames[:] = [x for x in dirnames if not x.startswith('.')]
            for filename in filenames:
                if ((not filename.startswith('.'))
                        and filename.endswith('.json')):
                    yield os.path.join(dirpath, filename)

    # ----------------------------------------------------------------------
    #   Utility functions

    def _fix_secret_name(self, name):
        if not name.endswith('.json'):
            name += '.json'
        name = os.path.join(self.basedir, name)
        # todo: check that filename is in the correct path?
        return name

    def get_aes_key_filename(self, identity):
        return os.path.join(self.keydir, '{0}.key'.format(identity))

    def get_gpg_pubkey_filename(self, identity):
        return os.path.join(self.keydir, '{0}.pub'.format(identity))
