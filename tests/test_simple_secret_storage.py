import os

import gnupg
import pytest

from password_manager import PasswordManager, PasswordManagerException


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
    # pubkeys = [x['fingerprint'] for x in gpg.list_keys()]

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


def test_multiple_users(tmpdir):
    gpg_alice = gnupg.GPG(gnupghome=str(tmpdir.join('gnupg-alice')))
    gpg_bob = gnupg.GPG(gnupghome=str(tmpdir.join('gnupg-bob')))
    gpg_eve = gnupg.GPG(gnupghome=str(tmpdir.join('gnupg-eve')))

    passwords_dir = str(tmpdir.join('passwords'))

    for gpg in (gpg_alice, gpg_bob, gpg_eve):
        assert len(gpg.list_keys()) == 0
        assert len(gpg.list_keys(True)) == 0

    # Import public keys in all keyrings..

    keysdir = os.path.join(os.path.dirname(__file__), 'keys')
    for keyname in ('key1.pub', 'key2.pub', 'key3.pub'):
        with open(os.path.join(keysdir, keyname), 'r') as f:
            key_data = f.read()
            for gpg in (gpg_alice, gpg_bob, gpg_eve):
                gpg.import_keys(key_data)

    # For each user's gpg home, import all public keys

    with open(os.path.join(keysdir, 'key1.sec'), 'r') as f:
        gpg_alice.import_keys(f.read())

    with open(os.path.join(keysdir, 'key2.sec'), 'r') as f:
        gpg_bob.import_keys(f.read())

    with open(os.path.join(keysdir, 'key3.sec'), 'r') as f:
        gpg_eve.import_keys(f.read())

    # Verify operations

    for gpg in (gpg_alice, gpg_bob, gpg_eve):
        assert len(gpg.list_keys()) == 3
        assert len(gpg.list_keys(True)) == 1

    # Keep key fingerprints in meaningful names..

    gpg_fp_alice = gpg_alice.list_keys(True)[0]['fingerprint']
    gpg_fp_bob = gpg_bob.list_keys(True)[0]['fingerprint']
    gpg_fp_eve = gpg_eve.list_keys(True)[0]['fingerprint']

    # Make sure users have different keys!

    assert len(set((gpg_fp_alice, gpg_fp_bob, gpg_fp_eve))) == 3

    # ------------------------------------------------------------
    # Now, we can create passwor manager instances
    # and start experimenting..

    pm_alice = PasswordManager(
        passwords_dir, gpghome=str(tmpdir.join('gnupg-alice')))
    pm_bob = PasswordManager(
        passwords_dir, gpghome=str(tmpdir.join('gnupg-bob')))
    pm_eve = PasswordManager(
        passwords_dir, gpghome=str(tmpdir.join('gnupg-eve')))

    # Alice creates a new password manager.

    pm_alice.setup([gpg_fp_alice, gpg_fp_bob])
    pm_alice.write_secret('secret1', {'username': 'alice', 'password': '1234'})
    assert pm_alice.read_secret('secret1') == {
        'username': 'alice', 'password': '1234'}

    # And Bob is able to read the secret too..
    assert pm_bob.read_secret('secret1') == {
        'username': 'alice', 'password': '1234'}

    # But Eve cannot. Yet
    with pytest.raises(PasswordManagerException):
        pm_eve.read_secret('secret1')

    # Alice decides to add eve..
    pm_alice.add_identity(gpg_fp_eve)

    # Now Eve can read too..
    assert pm_eve.read_secret('secret1') == {
        'username': 'alice', 'password': '1234'}

    # But then Alice changes her mind
    pm_alice.delete_identity(gpg_fp_eve)

    assert pm_alice.read_secret('secret1') == {
        'username': 'alice', 'password': '1234'}
    assert pm_bob.read_secret('secret1') == {
        'username': 'alice', 'password': '1234'}

    # Eve cannot read password anymore.
    with pytest.raises(PasswordManagerException):
        pm_eve.read_secret('secret1')

    # Btw, Alice things it would be better to change password too..
    pm_alice.write_secret('secret1', {'username': 'alice', 'password': '4321'})

    assert pm_alice.read_secret('secret1') == {
        'username': 'alice', 'password': '4321'}
    assert pm_bob.read_secret('secret1') == {
        'username': 'alice', 'password': '4321'}
    with pytest.raises(PasswordManagerException):
        pm_eve.read_secret('secret1')
