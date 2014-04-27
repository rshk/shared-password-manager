import os
import gpgme


def get_gpg(home):
    os.environ['GNUPGHOME'] = '/path/to/invalid'  # To be safe..
    if not os.path.exists(home):
        os.makedirs(home)
    ctx = gpgme.Context()
    ctx.set_engine_info(gpgme.PROTOCOL_OpenPGP, None, home)
    return ctx
