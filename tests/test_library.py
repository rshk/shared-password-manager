"""
Tests for password manager
"""

# gpg = GPG(gnupghome="keys")
# input = gpg.gen_key_input()
# result = gpg.gen_key(input)
# print1 = result.fingerprint

import os
import json

import pytest
import gnupg

from Crypto.Cipher import AES
from Crypto import Random


# @pytest.fixture
# def gpg(tmpdir):
#     return gnupg.GPG(gnupghome=str(tmpdir))


#gpg.gen_key_input(key_type="RSA", key_length=1024)


def test_encrypt_key_between_users(tmpdir):
    """
    Test that the basic functionality of sharing an encrypted
    symmetric key between two users works as intended..
    """

    gpg1 = gnupg.GPG(gnupghome=str(tmpdir.join('gpg-1')))
    gpg2 = gnupg.GPG(gnupghome=str(tmpdir.join('gpg-2')))

    keysdir = os.path.join(os.path.dirname(__file__), 'keys')

    # Read + import RSA keys from files, as generating them on the fly
    # would be quite expensive..

    with open(os.path.join(keysdir, 'key1.pub'), 'r') as f:
        gpg_key1_pub = f.read()

    with open(os.path.join(keysdir, 'key1.sec'), 'r') as f:
        gpg_key1_sec = f.read()

    with open(os.path.join(keysdir, 'key2.pub'), 'r') as f:
        gpg_key2_pub = f.read()

    with open(os.path.join(keysdir, 'key2.sec'), 'r') as f:
        gpg_key2_sec = f.read()

    # Both users have both public keys, but each has only
    # its own secret key..

    gpg1.import_keys(gpg_key1_sec)
    gpg1.import_keys(gpg_key1_pub)
    gpg1.import_keys(gpg_key2_pub)
    key1_fp = gpg1.list_keys(True)[0]['fingerprint']

    gpg2.import_keys(gpg_key2_sec)
    gpg2.import_keys(gpg_key1_pub)
    gpg2.import_keys(gpg_key2_pub)
    key2_fp = gpg2.list_keys(True)[0]['fingerprint']

    assert key1_fp != key2_fp

    # Generate a 32bit AES key, for encrypting files

    aes_key = Random.new().read(32)

    # Store password encrypted for the two users

    with open(str(tmpdir.join('aes-key-1.key')), 'wb') as f:
        enc = gpg1.encrypt(aes_key, key1_fp, always_trust=True)
        f.write(str(enc))

    with open(str(tmpdir.join('aes-key-2.key')), 'wb') as f:
        enc = gpg2.encrypt(aes_key, key2_fp, always_trust=True)
        f.write(str(enc))

    # Now use the AES password to write a couple files

    passwords_dir = str(tmpdir.join('passwords'))
    os.makedirs(passwords_dir)

    data = json.dumps({'secret': 'This is a secret!'})
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(aes_key, AES.MODE_CFB, iv)
    packed = iv + cipher.encrypt(data.encode('utf-8'))

    with open(os.path.join(passwords_dir, 'example.txt'), 'wb') as f:
        f.write(packed)

    # Ok. It's time for the users to access their own data..

    # This is user 1, geting its aes key and using it to access the file.

    with open(str(tmpdir.join('aes-key-1.key')), 'rb') as f:
        dec_aes_key = gpg1.decrypt(f.read())
        # Note: using str(dec_aes_key) will try to decode unicode
        # but the key is binary
        my_aes_key = dec_aes_key.data

    with open(os.path.join(passwords_dir, 'example.txt'), 'rb') as f:
        enc_data = f.read()

    my_iv = enc_data[:AES.block_size]
    my_msg = enc_data[AES.block_size:]
    cypher1 = AES.new(my_aes_key, AES.MODE_CFB, my_iv)
    msg = cypher1.decrypt(my_msg)
    loaded = json.loads(msg)
    assert loaded == {'secret': 'This is a secret!'}
