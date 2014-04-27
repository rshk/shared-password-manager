"""
Tests for password manager
"""

import os
import json
from io import BytesIO

# import pytest

import gpgme

from Crypto.Cipher import AES
from Crypto import Random

from utils import get_gpg


_get_gpg = get_gpg


def test_encrypt_key_between_users(tmpdir, keyfiles):
    """
    Test that the basic functionality of sharing an encrypted
    symmetric key between two users works as intended..
    """

    # Initialize a couple GPG contexts

    gpg1 = _get_gpg(str(tmpdir.join('gpg-1')))
    gpg2 = _get_gpg(str(tmpdir.join('gpg-2')))

    # Make sure keyrings are empty

    for gpg in (gpg1, gpg2):
        assert len(list(gpg.keylist())) == 0
        assert len(list(gpg.keylist('', True))) == 0

    # Import public keys in both contexts

    for gpg in (gpg1, gpg2):
        for name in ('key1.pub', 'key2.pub'):
            with keyfiles.open(name, 'rb') as fp:
                gpg.import_(fp)

    # Import secret keys, one per user..

    with keyfiles.open('key1.sec', 'rb') as fp:
        gpg1.import_(fp)

    with keyfiles.open('key2.sec', 'rb') as fp:
        gpg2.import_(fp)

    # Make sure we have the correct number of keys

    for gpg in (gpg1, gpg2):
        assert len(list(gpg.keylist())) == 2
        assert len(list(gpg.keylist('', True))) == 1

    # Get fingerprints of secret key

    key1_fp = list(gpg1.keylist('', True))[0].subkeys[0].fpr
    key2_fp = list(gpg2.keylist('', True))[0].subkeys[0].fpr

    assert key1_fp != key2_fp

    # ------------------------------------------------------------
    #   Let's now proceed with AES encryption..
    # ------------------------------------------------------------

    # Generate a 32bit AES key, for encrypting files

    aes_key = Random.new().read(32)

    # Store password encrypted for the two users

    for gpg, keyfp, outfile in [
            (gpg1, key1_fp, 'aes-key-1.key'),
            (gpg2, key2_fp, 'aes-key-2.key'),
            ]:
        with open(str(tmpdir.join(outfile)), 'wb') as fp:
            key = gpg.get_key(keyfp)  # Get encryption key
            flags = gpgme.ENCRYPT_ALWAYS_TRUST
            gpg.encrypt([key], flags, BytesIO(aes_key), fp)

    # Now use the AES password to write an encrypted file..

    passwords_dir = str(tmpdir.join('passwords'))
    os.makedirs(passwords_dir)

    secret = {'secret': 'This is a secret!'}
    secret_data = json.dumps(secret)

    iv = Random.new().read(AES.block_size)
    cipher = AES.new(aes_key, AES.MODE_CFB, iv)
    packed = iv + cipher.encrypt(secret_data.encode('utf-8'))

    with open(os.path.join(passwords_dir, 'example.txt'), 'wb') as fp:
        fp.write(packed)

    #   Let's pretend we forgot everything now! :)

    del iv, cipher, packed, aes_key

    # ------------------------------------------------------------
    #   Now the users want to get their data back
    # ------------------------------------------------------------

    # Get the AES key by GPG-decrypting it

    with open(str(tmpdir.join('aes-key-1.key')), 'rb') as fp:
        # Decrypt the key from file
        _io = BytesIO()
        gpg1.decrypt(fp, _io)

        aes_key = _io.getvalue()

    # Get AES encrypted data

    with open(os.path.join(passwords_dir, 'example.txt'), 'rb') as fp:
        enc_data = fp.read()

    iv, msg = enc_data[:AES.block_size], enc_data[AES.block_size:]

    cypher = AES.new(aes_key, AES.MODE_CFB, iv)

    # Decrypt / decode message and check

    decoded = cypher.decrypt(msg)
    assert decoded == secret_data

    loaded = json.loads(decoded)
    assert loaded == secret


def test_gpg_multiple_homes(tmpdir):
    """Make sure we can use multiple GPG contexts"""

    os.environ['GNUPGHOME'] = '/no/such/dir'
    keysdir = os.path.join(os.path.dirname(__file__), 'keys')

    for userid in (1, 2):
        # Create a directory for user's pgp stuff..
        gpg_home = str(tmpdir.join('gpg-{0}'.format(userid)))
        os.makedirs(gpg_home)

        ctx = gpgme.Context()

        # We have no keys yet
        assert len(list(ctx.keylist())) == 0

        # Configure GNUPGHOME for this context
        ctx.set_engine_info(gpgme.PROTOCOL_OpenPGP, None, gpg_home)

        # Import public keys and check
        for name in ('key1.pub', 'key2.pub'):
            with open(os.path.join(keysdir, name), 'rb') as fp:
                ctx.import_(fp)

        assert len(list(ctx.keylist())) == 2
        assert len(list(ctx.keylist('', True))) == 0

        # Import private key and check
        keyfile = os.path.join(keysdir, 'key{0}.sec'.format(userid))
        with open(keyfile, 'r') as fp:
            ctx.import_(fp)

        assert len(list(ctx.keylist())) == 2
        assert len(list(ctx.keylist('', True))) == 1


def test_aes_encryption():
    secret = {'secret': 'This is a secret!'}
    secret_data = json.dumps(secret)

    aes_key = 'This is a key123'  # 128bit key

    # Generate initialization vector for AES
    iv = Random.new().read(AES.block_size)
    assert len(iv) == AES.block_size

    # Initialize AES cipher
    cipher = AES.new(aes_key, AES.MODE_CFB, iv)

    # Prepare a packed string containing IV + crypto text
    packed = iv + cipher.encrypt(secret_data.encode('utf-8'))

    del iv, cipher

    # ---------- time to get the message back! ----------

    iv = packed[:AES.block_size]
    msg = packed[AES.block_size:]

    cypher = AES.new(aes_key, AES.MODE_CFB, iv)

    decrypted = cypher.decrypt(msg)
    assert decrypted == secret_data

    loaded = json.loads(decrypted)
    assert loaded == secret
