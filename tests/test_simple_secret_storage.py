import pytest

from password_manager import PasswordManager, PasswordManagerException

# From test utils!
from utils import get_gpg


def test_oneuser(tmpdir, keyfiles):
    # ------------------------------------------------------------
    # Create a dummy gpg keyring

    gpg = get_gpg(str(tmpdir.join('gnupg')))

    assert len(list(gpg.keylist())) == 0
    assert len(list(gpg.keylist('', True))) == 0

    # Import some keys in keyring

    for keyname in ('key1.sec', 'key1.pub', 'key2.pub'):
        with keyfiles.open(keyname, 'rb') as fp:
            gpg.import_(fp)

    assert len(list(gpg.keylist())) == 2  # public
    assert len(list(gpg.keylist('', True))) == 1  # secret

    # Read fingerprints of the user's private key and other
    # available public keys.

    privkey = list(gpg.keylist('', True))[0].subkeys[0].fpr

    # ------------------------------------------------------------
    # Prepare password manager

    pm = PasswordManager(
        str(tmpdir.join('passwords')),
        gpghome=str(tmpdir.join('gnupg')))

    pm.setup([privkey])

    assert list(pm.list_identities()) == [privkey]

    secret = "{'hello': 'World'}"
    pm.write_secret('hello', secret)

    assert pm.read_secret('hello') == secret


def test_multiple_users(tmpdir, keyfiles):
    gpg_alice = get_gpg(str(tmpdir.join('gnupg-alice')))
    gpg_bob = get_gpg(str(tmpdir.join('gnupg-bob')))
    gpg_eve = get_gpg(str(tmpdir.join('gnupg-eve')))

    passwords_dir = str(tmpdir.join('passwords'))

    for gpg in (gpg_alice, gpg_bob, gpg_eve):
        assert len(list(gpg.keylist())) == 0
        assert len(list(gpg.keylist('', True))) == 0

    # Import public keys in all keyrings..

    for gpg in (gpg_alice, gpg_bob, gpg_eve):
        for keyname in ('key1.pub', 'key2.pub', 'key3.pub'):
            with keyfiles.open(keyname, 'rb') as fp:
                gpg.import_(fp)

    # For each user's gpg home, import all public keys

    for gpg, keyfile in [
            (gpg_alice, 'key1.sec'),
            (gpg_bob, 'key2.sec'),
            (gpg_eve, 'key3.sec')]:
        with keyfiles.open(keyfile) as fp:
            gpg.import_(fp)

    # Verify operations

    for gpg in (gpg_alice, gpg_bob, gpg_eve):
        assert len(list(gpg.keylist())) == 3
        assert len(list(gpg.keylist('', True))) == 1

    # Keep key fingerprints in meaningful names..

    def _get_first_privkey_fpr(gpg):
        all_privkeys = list(gpg.keylist('', True))
        assert len(all_privkeys) == 1

        # There should be only one subkey (the master one)
        assert len(all_privkeys[0].subkeys) == 1

        return all_privkeys[0].subkeys[0].fpr

    gpg_fp_alice = _get_first_privkey_fpr(gpg_alice)
    gpg_fp_bob = _get_first_privkey_fpr(gpg_bob)
    gpg_fp_eve = _get_first_privkey_fpr(gpg_eve)

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
    secret = "{'username': 'alice', 'password': '1234'}"
    pm_alice.write_secret('secret1', secret)
    assert pm_alice.read_secret('secret1') == secret

    # And Bob is able to read the secret too..
    assert pm_bob.read_secret('secret1') == secret

    # But Eve cannot. Yet
    with pytest.raises(PasswordManagerException):
        pm_eve.read_secret('secret1')

    # Alice decides to add eve..
    pm_alice.add_identity(gpg_fp_eve)

    # Now Eve can read too..
    assert pm_eve.read_secret('secret1') == secret

    # But then Alice changes her mind
    pm_alice.remove_identity(gpg_fp_eve)

    assert pm_alice.read_secret('secret1') == secret
    assert pm_bob.read_secret('secret1') == secret

    # Eve cannot read password anymore.
    with pytest.raises(PasswordManagerException):
        pm_eve.read_secret('secret1')

    # Btw, Alice things it would be better to change password too..
    secret = "{'username': 'alice', 'password': '4321'}"
    pm_alice.write_secret('secret1', secret)

    assert pm_alice.read_secret('secret1') == secret
    assert pm_bob.read_secret('secret1') == secret
    with pytest.raises(PasswordManagerException):
        pm_eve.read_secret('secret1')
