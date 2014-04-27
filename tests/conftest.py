import os

import pytest


@pytest.fixture
def keyfiles():
    keysdir = os.path.join(os.path.dirname(__file__), 'keys')

    class KeyFiles(object):
        def __init__(self, keysdir):
            self.keysdir = keysdir

        def open(self, name, mode='rb'):
            return open(os.path.join(self.keysdir, name), mode)

    return KeyFiles(keysdir)
