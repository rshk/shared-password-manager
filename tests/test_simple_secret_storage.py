import os

import gnupg

from password_manager import PasswordManager


def test_oneuser(tmpdir):
    # ------------------------------------------------------------
    # Create a dummy gpg keyring

    gpg = gnupg.GPG(gnupghome=str(tmpdir.join('gnupg')))

    assert len(gpg.list_keys()) == 0
    assert len(gpg.list_keys(True)) == 0

    # Import some keys in keyring

    keysdir = os.path.join(os.path.dirname(__file__), 'keys')
    for keyname in ('key1.sec', 'key1.pub', 'key2.pub'):
        with open(os.path.join(keysdir, keyname), 'r') as f:
            gpg.import_keys(f.read())

    assert len(gpg.list_keys()) == 2
    assert len(gpg.list_keys(True)) == 1

    # Read fingerprints of the user's private key and other
    # available public keys.

    privkey = gpg.list_keys(True)[0]['fingerprint']
    pubkeys = [x['fingerprint'] for x in gpg.list_keys()]

    # ------------------------------------------------------------
    # Prepare password manager

    pm = PasswordManager(
        str(tmpdir.join('passwords')),
        gpghome=str(tmpdir.join('gnupg')))

    pm.setup([privkey])

    assert list(pm.list_identities()) == [privkey]

    secret = {'hello': 'World'}
    pm.write_secret('hello', secret)

    assert pm.read_secret('hello') == secret
